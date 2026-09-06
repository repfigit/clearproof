"""Authorized internal event ingestion; provider signature adapters are separate."""

import json

from pydantic import Field, model_validator

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.protocol.transfer import Address, Epoch, OpaqueId, Record, UInt128
from src.reconciliation.events import Dimension, SourceEvent, TransferEvent, TransferScope, reconcile
from src.storage.pilot import PilotStore, RecordConflict


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
    def __init__(self, db, cipher, principal: Principal, *, authorities: tuple[EventAuthority, ...]):
        self.principal = Principal.model_validate(principal)
        if type(authorities) is not tuple or len(authorities) > 256:
            raise ValueError("Configure a bounded authority inventory")
        self.authorities = tuple(EventAuthority.model_validate(a) for a in authorities)
        self.store = PilotStore(db, cipher, self.principal)

    async def ingest(self, source_event: SourceEvent, *, now: int) -> dict:
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
            raise ValueError("Event source is outside the configured authority")
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
        async with self.store.transaction() as tx:
            old = await tx.get("event", identity)
            if old is not None:
                previous = TransferEvent.model_validate_json(json.dumps(old["event"]))
                if previous.content_digest != event.content_digest:
                    raise RecordConflict("Source event identity belongs to different content")
                return {"event_id": identity, "ingested_at": previous.ingested_at, "duplicate": True}
            ids = await tx.event_ids(event.scope.digest)
            if len(ids) >= 256:
                raise ValueError("Transfer event capacity exceeded")
            # Persist reviewer identity inside ciphertext, not the public index.
            await tx.put(
                "event", identity, {"actor_id": self.principal.actor_id, "event": event.model_dump(mode="json")}
            )
            await tx.index_event(identity, event.scope.digest, stream, event.source_sequence)
            return {"event_id": identity, "ingested_at": now, "duplicate": False}

    async def investigate(self, scope: TransferScope, *, now: int):
        self.principal.require("evidence:read")
        self.principal.require("evidence:decrypt")
        scope = TransferScope.model_validate(scope)
        if scope.tenant_id != self.principal.tenant_id:
            raise ValueError("Investigation is outside the authenticated tenant")
        events = []
        async with self.store.transaction() as tx:
            for record_id in await tx.event_ids(scope.digest):
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
                if expected != record_id:
                    raise ValueError("Indexed event identity differs")
                events.append(event)
        return reconcile(scope, tuple(events), now=now)
