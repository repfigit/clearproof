"""Bounded event replay; authenticating sources belongs to the ingestion service."""

from typing import Literal

from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record, UInt128, uint128

STATES = {
    "compliance": {"approved", "review", "denied"},
    "proof": {"valid", "invalid"},
    "counterparty": {"accepted", "rejected", "information-requested", "timeout"},
    "custody": {"created", "submitted", "failed", "cancelled"},
    "chain": {"pending", "confirmed", "finalized", "reorged"},
    "evidence": {"complete", "incomplete"},
}
Dimension = Literal["compliance", "proof", "counterparty", "custody", "chain", "evidence"]


class TransferScope(Record):
    tenant_id: OpaqueId
    transfer_id: OpaqueId
    chain_id: UInt128
    registry_address: Address

    @model_validator(mode="after")
    def deployment(self):
        if not 0 < int(uint128(self.chain_id)) < 2**64 or int(self.registry_address, 16) == 0:
            raise ValueError("Transfer scope requires a nonzero EVM deployment")
        return self

    @property
    def digest(self):
        return record_digest("clearproof/business-transfer/v1", self.model_dump(mode="json"))


class TransferEvent(Record):
    schema_version: Literal["clearproof-transfer-event-v1"] = "clearproof-transfer-event-v1"
    scope: TransferScope
    source_id: OpaqueId
    source_event_id: OpaqueId
    source_sequence: int = Field(ge=1, le=2**53 - 1)
    dimension: Dimension
    state: OpaqueId
    occurred_at: Epoch
    ingested_at: Epoch
    evidence_digest: Hex32
    block_number: Epoch | None = None
    block_hash: Hex32 | None = None

    @model_validator(mode="after")
    def coherent(self):
        if self.state not in STATES[self.dimension]:
            raise ValueError("Unsupported state for event dimension")
        if self.occurred_at > self.ingested_at:
            raise ValueError("Future source event requires quarantine")
        has_block = self.block_number is not None and self.block_hash is not None
        if (self.block_number is None) != (self.block_hash is None):
            raise ValueError("Block identity requires both number and hash")
        if self.dimension != "chain" and has_block:
            raise ValueError("Only chain observations carry block identities")
        if self.dimension == "chain" and self.state != "pending" and not has_block:
            raise ValueError("Chain observation requires its observed block identity")
        return self

    @property
    def content_digest(self):
        # Delivery timing is recorded separately, not part of provider event identity.
        return record_digest("clearproof/transfer-event/v1", self.model_dump(mode="json", exclude={"ingested_at"}))


class InvestigationFinding(Record):
    reason: OpaqueId
    owner: OpaqueId
    next_action: OpaqueId
    since: Epoch
    age_seconds: Epoch


class Investigation(Record):
    schema_version: Literal["clearproof-investigation-v1"] = "clearproof-investigation-v1"
    scope_digest: Hex32
    as_of: Epoch
    states: dict[str, str]
    findings: tuple[InvestigationFinding, ...]
    timeline: tuple[TransferEvent, ...]
    source_authenticity: Literal["caller-required"] = "caller-required"


def reconcile(scope: TransferScope, events: tuple[TransferEvent, ...], *, now: int) -> Investigation:
    scope = TransferScope.model_validate(scope)
    if type(now) is not int or not 0 <= now <= 2**53 - 1:
        raise ValueError("Invalid projection clock")
    if type(events) is not tuple or len(events) > 256:
        raise ValueError("Projection accepts at most 256 events")
    unique = {}
    sequence = {}
    for raw in events:
        event = TransferEvent.model_validate(raw)
        if event.scope != scope or event.ingested_at > now:
            raise ValueError("Event outside scope or observation clock")
        identity = (event.source_id, event.source_event_id)
        previous = unique.get(identity)
        if previous and previous.content_digest != event.content_digest:
            raise ValueError("Conflicting duplicate source event")
        seq = (event.source_id, event.dimension, event.source_sequence)
        if seq in sequence and sequence[seq] != event.content_digest:
            raise ValueError("Conflicting source sequence")
        sequence[seq] = event.content_digest
        if previous is None or event.ingested_at < previous.ingested_at:
            unique[identity] = event
    timeline = tuple(
        sorted(unique.values(), key=lambda e: (e.occurred_at, e.source_id, e.source_sequence, e.source_event_id))
    )
    latest = {}
    for event in timeline:
        stream = (event.dimension, event.source_id)
        if stream not in latest or latest[stream].source_sequence < event.source_sequence:
            latest[stream] = event
    states, findings = {}, []

    def finding(reason, owner, action, relevant):
        since = min(e.occurred_at for e in relevant)
        findings.append(
            InvestigationFinding(reason=reason, owner=owner, next_action=action, since=since, age_seconds=now - since)
        )

    for dimension in STATES:
        selected = [e for (kind, _), e in latest.items() if kind == dimension]
        # Source disagreements, including differing canonical blocks, stay explicit.
        values = {(e.state, e.block_number, e.block_hash) for e in selected}
        states[dimension] = "unknown" if not values else selected[0].state if len(values) == 1 else "conflict"
        if len(values) > 1:
            finding("source-conflict-" + dimension, "operations", "review-source-evidence", selected)
    if states["compliance"] == "approved" and states["custody"] in {"unknown", "created"}:
        finding(
            "approval-without-submission",
            "operations",
            "investigate-submission",
            [e for e in latest.values() if e.dimension == "compliance"],
        )
    if states["counterparty"] == "timeout":
        finding(
            "counterparty-timeout",
            "compliance",
            "review-counterparty-response",
            [e for e in latest.values() if e.dimension == "counterparty"],
        )
    if states["custody"] == "failed":
        finding(
            "settlement-failed",
            "operations",
            "inspect-custody-failure",
            [e for e in latest.values() if e.dimension == "custody"],
        )
    if states["chain"] == "reorged":
        finding(
            "chain-reorganization",
            "operations",
            "recheck-canonical-block",
            [e for e in latest.values() if e.dimension == "chain"],
        )
    if states["chain"] == "finalized" and any(
        states[k] != v
        for k, v in {
            "compliance": "approved",
            "proof": "valid",
            "counterparty": "accepted",
            "evidence": "complete",
        }.items()
    ):
        finding(
            "settled-with-unresolved-evidence",
            "compliance",
            "review-missing-evidence",
            [e for e in latest.values() if e.dimension == "chain"],
        )
    return Investigation(
        scope_digest=scope.digest,
        as_of=now,
        states=states,
        findings=tuple(sorted(findings, key=lambda f: f.reason)),
        timeline=timeline,
    )
