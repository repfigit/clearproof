"""Retain an independently authenticated timestamp without reauthorizing a transfer."""

import base64
import json

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.protocol.decision_attestation import DecisionTrustStore, SignedDecision
from src.protocol.transfer import VerificationContext
from src.prover.history_timing import MAX_TIMESTAMP_BYTES, TimestampTrust
from src.storage.pilot import PilotStore, RecordConflict


def timestamp_record_id(receipt_id):
    return record_digest("clearproof/decision-timestamp-record/v1", {"receipt_id": receipt_id})


def timestamp_record_bytes(record, *, tenant_id, receipt_id):
    if (
        type(record) is not dict
        or record.get("schema_version") != "clearproof-retained-timestamp-v1"
        or record.get("tenant_id") != tenant_id
        or record.get("receipt_id") != receipt_id
        or type(record.get("response")) is not list
        or not 1 <= len(record["response"]) <= 22
        or any(type(part) is not str or not 1 <= len(part) <= 2048 for part in record["response"])
    ):
        raise ValueError("Invalid retained timestamp record")
    raw = base64.b64decode("".join(record["response"]), validate=True)
    if not 1 <= len(raw) <= MAX_TIMESTAMP_BYTES:
        raise ValueError("Invalid retained timestamp size")
    return raw


class TimestampEvidenceService:
    def __init__(
        self, db, cipher, principal: Principal, *, timing_trust: TimestampTrust, decision_trust: DecisionTrustStore
    ):
        self.principal = Principal.model_validate(principal)
        self.store = PilotStore(db, cipher, self.principal)
        self.timing_trust, self.decision_trust = timing_trust, decision_trust

    async def attach(self, receipt_id: str, response: bytes, *, now: int):
        self.principal.require("proof:generate")
        self.principal.require("evidence:decrypt")
        if type(response) is not bytes or not 1 <= len(response) <= MAX_TIMESTAMP_BYTES:
            raise ValueError("Invalid timestamp response size")
        identity = timestamp_record_id(receipt_id)
        async with self.store.transaction() as tx:
            receipt = await tx.get("receipt", receipt_id)
            if (
                receipt is None
                or receipt.get("tenant_id") != tx.tenant_id
                or record_digest("clearproof/local-authorization/v1", receipt) != receipt_id
            ):
                raise ValueError("Authorization receipt unavailable")
            proof = await tx.get("proof", receipt["proof_id"])
            if proof is None:
                raise ValueError("Authorization proof unavailable")
            signed = SignedDecision.model_validate_json(json.dumps(proof["decision_attestation"]))
            context = VerificationContext.model_validate_json(json.dumps(proof["context"]))
            self.decision_trust.verify(signed, receipt, context, verified_at=now)
            self.timing_trust.verify_decision_window(
                response, signed, expires_at=receipt["expires_at"], verified_at=now
            )
            existing = await tx.get("authorization-evidence", identity)
            if existing is not None:
                if timestamp_record_bytes(existing, tenant_id=tx.tenant_id, receipt_id=receipt_id) != response:
                    raise RecordConflict("A different timestamp is already retained")
                return identity
            encoded = base64.b64encode(response).decode("ascii")
            await tx.put(
                "authorization-evidence",
                identity,
                {
                    "schema_version": "clearproof-retained-timestamp-v1",
                    "tenant_id": tx.tenant_id,
                    "receipt_id": receipt_id,
                    "attached_at": now,
                    "response": [encoded[i : i + 2048] for i in range(0, len(encoded), 2048)],
                },
            )
            return identity
