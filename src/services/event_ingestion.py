"""Authorized internal event ingestion; provider signature adapters are separate."""

import json

from pydantic import Field, model_validator

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.protocol.transfer import Address, Epoch, OpaqueId, Record, UInt128
from src.reconciliation.events import Dimension, SourceEvent, TransferEvent, TransferScope, reconcile
from src.reconciliation.provider_links import ProviderLinkCatalog
from src.reconciliation.queue import QueueItem, QueuePage, QueueRequest
from src.storage.pilot import PilotStore, RecordConflict


class EventAuthorityError(ValueError):
    pass


class EventAuthority(Record):
    tenant_id: OpaqueId
    chain_id: UInt128
    registry_address: Address
    source_id: OpaqueId
    actors: tuple[OpaqueId, ...] = Field(min_length=1, max_length=16)
    dimensions: tuple[Dimension, ...] = Field(min_length=1, max_length=6)
    valid_from: Epoch
    valid_until: Epoch

    @model_validator(mode="after")
    def coherent(self):
        if (
            self.valid_from >= self.valid_until
            or len(set(self.actors)) != len(self.actors)
            or len(set(self.dimensions)) != len(self.dimensions)
        ):
            raise ValueError("Invalid event authority")
        TransferScope(
            tenant_id=self.tenant_id,
            transfer_id="validation",
            chain_id=self.chain_id,
            registry_address=self.registry_address,
        )
        return self


class EventIngestionService:
    def __init__(self, db, cipher, principal: Principal, *, authorities: tuple[EventAuthority, ...], links=()):
        self.principal = Principal.model_validate(principal)
        self.links = ProviderLinkCatalog(links)
        if type(authorities) is not tuple or len(authorities) > 256:
            raise ValueError("Configure a bounded authority inventory")
        self.authorities = tuple(EventAuthority.model_validate(a) for a in authorities)
        self.store = PilotStore(db, cipher, self.principal)

    async def ingest(self, source_event: SourceEvent, *, now: int) -> dict:
        return await self._ingest_with_evidence(source_event, now=now, evidence=())

    async def _ingest_with_evidence(self, source_event: SourceEvent, *, now: int, evidence: tuple[dict, ...]) -> dict:
        event, evidence_ids = self._prepare_ingestion(source_event, now=now, evidence=evidence)
        async with self.store.transaction() as tx:
            return await self._ingest_transaction(tx, event, evidence=evidence, evidence_ids=evidence_ids)

    def _prepare_ingestion(self, source_event: SourceEvent, *, now: int, evidence: tuple[dict, ...]):
        self.principal.require("events:ingest")
        self.principal.require("evidence:decrypt")
        source = SourceEvent.model_validate(source_event)
        event = TransferEvent.model_validate({**source.model_dump(), "ingested_at": now})
        if event.scope.tenant_id != self.principal.tenant_id or not any(
            authority.tenant_id == event.scope.tenant_id
            and authority.chain_id == event.scope.chain_id
            and authority.registry_address == event.scope.registry_address
            and authority.source_id == event.source_id
            and self.principal.actor_id in authority.actors
            and event.dimension in authority.dimensions
            and authority.valid_from <= event.occurred_at <= now < authority.valid_until
            for authority in self.authorities
        ):
            raise EventAuthorityError("Event source is outside the configured authority")
        if type(evidence) is not tuple or len(evidence) > 33:
            raise ValueError("Provider evidence exceeds retention bounds")
        evidence_ids = [record_digest("clearproof/provider-evidence/v1", value) for value in evidence]
        return event, evidence_ids

    async def _ingest_transaction(self, tx, event, *, evidence, evidence_ids):
        identity = record_digest(
            "clearproof/source-event-id/v1",
            {
                "tenant_id": self.principal.tenant_id,
                "source_id": event.source_id,
                "source_event_id": event.source_event_id,
            },
        )
        stream = record_digest(
            "clearproof/event-stream/v1",
            {
                "scope_digest": event.scope.digest,
                "source_id": event.source_id,
                "dimension": event.dimension,
            },
        )
        old = await tx.get("event", identity)
        if old is not None:
            previous = TransferEvent.model_validate_json(json.dumps(old["event"]))
            if previous.content_digest != event.content_digest or bool(old.get("evidence_records", [])) != bool(
                evidence_ids
            ):
                raise RecordConflict("Source event identity belongs to different content")
            return {"event_id": identity, "ingested_at": previous.ingested_at, "duplicate": True}
        ids = await tx.event_ids(event.scope.digest)
        if len(ids) >= 256:
            raise ValueError("Transfer event capacity exceeded")
        for evidence_id, value in zip(evidence_ids, evidence, strict=True):
            existing = await tx.get("provider-evidence", evidence_id)
            if existing is None:
                await tx.put("provider-evidence", evidence_id, value)
            elif existing != value:
                raise RecordConflict("Provider evidence identity differs")
        # Persist reviewer identity inside ciphertext, not the public index.
        await tx.put(
            "event",
            identity,
            {
                "actor_id": self.principal.actor_id,
                "event": event.model_dump(mode="json"),
                "evidence_records": evidence_ids,
            },
        )
        await tx.index_event(identity, event.scope.digest, stream, event.source_sequence)
        return {"event_id": identity, "ingested_at": event.ingested_at, "duplicate": False}

    async def investigate(self, scope: TransferScope, *, now: int):
        self.principal.require("evidence:read")
        self.principal.require("evidence:decrypt")
        scope = TransferScope.model_validate(scope)
        if scope.tenant_id != self.principal.tenant_id:
            raise EventAuthorityError("Investigation is outside the authenticated tenant")
        async with self.store.transaction() as tx:
            events = await self._load_events(tx, scope.digest)
        report = reconcile(scope, events, now=now)
        return report.model_copy(
            update={"provider_links": self.links.for_events(self.principal.tenant_id, scope.digest, events)}
        )

    async def _load_events(self, tx, scope_digest: str) -> tuple[TransferEvent, ...]:
        events = []
        for record_id in await tx.event_ids(scope_digest):
            value = await tx.get("event", record_id)
            if value is None:
                raise ValueError("Indexed event is missing")
            event = TransferEvent.model_validate_json(json.dumps(value["event"]))
            expected = record_digest(
                "clearproof/source-event-id/v1",
                {
                    "tenant_id": self.principal.tenant_id,
                    "source_id": event.source_id,
                    "source_event_id": event.source_event_id,
                },
            )
            if (
                expected != record_id
                or event.scope.digest != scope_digest
                or event.scope.tenant_id != self.principal.tenant_id
            ):
                raise ValueError("Indexed event identity or scope differs")
            events.append(event)
        return tuple(events)

    async def queue(self, request: QueueRequest, *, now: int) -> QueuePage:
        self.principal.require("evidence:read")
        self.principal.require("evidence:decrypt")
        request = QueueRequest.model_validate(request)
        items = []
        async with self.store.transaction() as tx:
            scopes = await tx.event_scopes(after=request.after, limit=request.limit)
            for digest in scopes[: request.limit]:
                events = await self._load_events(tx, digest)
                if not events:
                    raise ValueError("Indexed transfer has no events")
                report = reconcile(events[0].scope, events, now=now)
                findings = tuple(f for f in report.findings if f.age_seconds >= request.minimum_age_seconds)
                if findings:
                    items.append(
                        QueueItem(
                            scope=events[0].scope,
                            scope_digest=digest,
                            states=report.states,
                            findings=findings,
                            oldest_age_seconds=max(f.age_seconds for f in findings),
                            provider_links=self.links.for_events(self.principal.tenant_id, digest, events),
                        )
                    )
        return QueuePage(
            as_of=now,
            scanned_transfers=min(len(scopes), request.limit),
            items=tuple(sorted(items, key=lambda item: (-item.oldest_age_seconds, item.scope_digest))),
            next_cursor=scopes[request.limit - 1] if len(scopes) > request.limit else None,
        )
