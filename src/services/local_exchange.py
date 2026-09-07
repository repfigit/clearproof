"""Durable internal simulator delivery through the existing authorized event boundary."""

from pydantic import Field

from src.protocol.bridges.trp_bridge import TRPBridge
from src.protocol.canonical import record_digest
from src.protocol.transfer import Epoch, Hex32, OpaqueId, Record
from src.reconciliation.events import SourceEvent, TransferScope


class ExchangeDelivery(Record):
    receipt_id: Hex32
    delivery_id: OpaqueId
    source_sequence: int = Field(strict=True, ge=1, le=2**53 - 1)
    observed_at: Epoch


class LocalExchangeService:
    """Server-owned counterparty behavior and source authority; never a remote-response ingestion endpoint."""

    def __init__(self, events, counterparty, *, source_id: str, behavior="accept", deadline=None):
        if behavior not in ("accept", "reject", "request-information", "timeout"):
            raise ValueError("Unsupported local counterparty behavior")
        self.events, self.counterparty = events, counterparty
        self.source_id, self.behavior, self.deadline = source_id, behavior, deadline
        transfer, context = counterparty.transfer, counterparty.context
        self.scope = TransferScope(
            tenant_id=transfer.tenant_id,
            transfer_id=transfer.transfer_id,
            chain_id=context.deployment_chain_id,
            registry_address=context.deployment_address,
        )
        if events.principal.tenant_id != self.scope.tenant_id:
            raise ValueError("Local exchange configuration differs from authenticated tenant")

    async def deliver(self, delivery: ExchangeDelivery, *, now: int) -> dict:
        self.events.principal.require("events:ingest")
        self.events.principal.require("evidence:decrypt")
        delivery = ExchangeDelivery.model_validate(delivery)
        if type(now) is not int or not delivery.observed_at <= now < 2**53:
            raise ValueError("Local exchange delivery precedes its declared observation")
        request = {
            **delivery.model_dump(mode="json"),
            "source_id": self.source_id,
            "behavior": self.behavior,
            "deadline": self.deadline,
            "context_digest": self.counterparty.context.digest,
        }
        key = record_digest(
            "clearproof/local-exchange-delivery/v1", {"source_id": self.source_id, "delivery_id": delivery.delivery_id}
        )

        async def apply(tx):
            receipt = await tx.get("receipt", delivery.receipt_id)
            if receipt is None:
                raise ValueError("Local exchange receipt is unavailable")
            record = await tx.get("proof", receipt["proof_id"])
            if record is None:
                raise ValueError("Local exchange authorization evidence is unavailable")
            message = TRPBridge.build_pilot_request(record, {**receipt, "receipt_id": delivery.receipt_id})
            result = self.counterparty.receive(
                message, now=delivery.observed_at, behavior=self.behavior, deadline=self.deadline
            )
            evidence = dict(
                schema_version="clearproof-local-exchange-evidence-v1",
                receipt_id=delivery.receipt_id,
                context_digest=self.counterparty.context.digest,
                result=result,
            )
            evidence_digest = record_digest("clearproof/provider-evidence/v1", evidence)
            source = SourceEvent(
                scope=self.scope,
                source_id=self.source_id,
                source_event_id=key,
                source_sequence=delivery.source_sequence,
                dimension="counterparty",
                state=result["outcome"],
                occurred_at=delivery.observed_at,
                evidence_digest=evidence_digest,
            )
            event, evidence_ids = self.events._prepare_ingestion(source, now=now, evidence=(evidence,))
            retained = await self.events._ingest_transaction(tx, event, evidence=(evidence,), evidence_ids=evidence_ids)
            return dict(
                schema_version="clearproof-recorded-local-exchange-v1",
                scope="retained-local-exchange",
                receipt_id=delivery.receipt_id,
                source_sequence=delivery.source_sequence,
                event_id=retained["event_id"],
                result=result,
                authorization="not-created",
                execution="not-requested",
            )

        return await self.events.store.run_idempotent("ingest-event", key, request, apply)
