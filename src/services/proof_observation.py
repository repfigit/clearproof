"""Durable local observation of current proof/policy evaluation, never enforcement."""

import hashlib
import time
from typing import Literal

from pydantic import Field, model_validator

from src.auth.principal import Principal
from src.policy.evaluator import PolicyEvaluation
from src.policy.fact_approval import FactTrustStore
from src.protocol.canonical import record_digest
from src.protocol.transfer import Epoch, Hex32, OpaqueId, Record
from src.prover.pilot_verifier import PilotProof, public_signals
from src.services.proof_inspection import ProofInspectionService
from src.storage.database import Database
from src.storage.pilot import PilotStore
from src.storage.pilot_cipher import RecordCipher


class ObservationRecord(Record):
    schema_version: Literal["clearproof-proof-observation-v1"] = "clearproof-proof-observation-v1"
    mode: Literal["observation"] = "observation"
    authorization_consumed: Literal[False] = False
    execution: Literal["not-requested"] = "not-requested"
    assurance: Literal["development-unapproved"]
    tenant_id: OpaqueId
    actor_id: OpaqueId
    request_digest: Hex32
    credential_id: OpaqueId
    proof_digest: Hex32
    signals_digest: Hex32
    transfer_digest: Hex32
    context_digest: Hex32
    policy_digest: Hex32
    manifest_digest: Hex32
    proof_profile: Literal["pilot-transfer-v2"]
    fact_ids: tuple[Hex32, ...] = Field(max_length=64)
    observed_at: Epoch
    cryptographic_valid: bool
    policy: PolicyEvaluation | None

    @model_validator(mode="after")
    def consistent(self):
        if self.fact_ids != tuple(sorted(set(self.fact_ids))):
            raise ValueError("Observation fact references must be distinct and sorted")
        if self.cryptographic_valid != (self.policy is not None):
            raise ValueError("Observation policy requires successful pairing")
        if self.policy is not None and (
            self.policy.policy_digest != self.policy_digest
            or self.policy.transfer_digest != self.transfer_digest
            or self.policy.evaluated_at != self.observed_at
        ):
            raise ValueError("Observation policy scope or clock mismatch")
        return self

    @property
    def digest(self) -> str:
        return record_digest("clearproof/proof-observation/v1", self.model_dump(mode="json"))

    def report(self) -> dict:
        return {"observation_id": self.digest, **self.model_dump(mode="json")}


class TimedObservationRecord(ObservationRecord):
    schema_version: Literal["clearproof-proof-observation-v2"] = "clearproof-proof-observation-v2"
    latency_scope: Literal["current-evaluation-only"] = "current-evaluation-only"
    evaluation_duration_ns: int = Field(ge=0, le=60_000_000_000)

    @property
    def digest(self) -> str:
        return record_digest("clearproof/proof-observation/v2", self.model_dump(mode="json"))


def parse_observation(value: dict) -> ObservationRecord:
    import json

    model = {
        "clearproof-proof-observation-v1": ObservationRecord,
        "clearproof-proof-observation-v2": TimedObservationRecord,
    }.get(value.get("schema_version"))
    if model is None:
        raise ValueError("Unsupported observation version")
    return model.model_validate_json(json.dumps(value))


class ProofObservationService(ProofInspectionService):
    async def observe(
        self,
        credential_id: str,
        proof: bytes,
        signals: list[str],
        fact_ids: tuple[str, ...],
        *,
        fact_trust: FactTrustStore,
        idempotency_key: str,
        now: int,
    ) -> dict:
        """Retain evaluation and its idempotency result in one tenant transaction.

        Exact retries return the original observation, even after expiry or a
        subsequent trust change. Use a new key for a new evaluation. This never
        writes an authorization proof, receipt or nullifier consumption.
        """
        for role in ("observations:write", "proof:inspect", "policy:read", "evidence:decrypt"):
            self._principal.require(role)
        if type(now) is not int or not 0 <= now < 2**53:
            raise ValueError("Invalid observation clock")
        PilotProof.parse(proof)
        signals = public_signals(signals)
        if type(fact_ids) is not tuple or len(fact_ids) > 64 or len(set(fact_ids)) != len(fact_ids):
            raise ValueError("Expected at most 64 distinct fact references")
        references = tuple(sorted(fact_ids))
        request = {
            "credential_id": credential_id,
            "proof_digest": hashlib.sha256(proof).hexdigest(),
            "signals_digest": record_digest("clearproof/observation-signals/v1", list(signals)),
            "fact_ids": list(references),
            "transfer_digest": self._context.transfer_digest,
            "context_digest": self._context.digest,
        }
        request_digest = record_digest(
            "clearproof/observation-request/v1",
            {
                "tenant_id": self._principal.tenant_id,
                "actor_id": self._principal.actor_id,
                "idempotency_key": idempotency_key,
                **request,
            },
        )

        async def persist(tx):
            started = time.monotonic_ns()
            inspection, decision = await self._evaluate_transaction(
                tx, credential_id, proof, signals, references, fact_trust=fact_trust, now=now
            )
            duration = time.monotonic_ns() - started
            record = TimedObservationRecord(
                evaluation_duration_ns=duration,
                **{**request, "fact_ids": references},
                tenant_id=self._principal.tenant_id,
                actor_id=self._principal.actor_id,
                request_digest=request_digest,
                policy_digest=self._context.policy_digest,
                manifest_digest=inspection.manifest_digest,
                proof_profile=inspection.proof_profile,
                assurance=self._verifier.artifacts.manifest.assurance,
                observed_at=now,
                cryptographic_valid=inspection.cryptographic_valid,
                policy=decision,
            )
            await tx.put("observation", record.digest, record.model_dump(mode="json"))
            return record.report()

        return await self._store.run_idempotent("observe-proof", idempotency_key, request, persist)


async def read_observation(
    db: Database,
    cipher: RecordCipher,
    principal: Principal,
    observation_id: str,
) -> dict | None:
    """Read a historical local observation without rerunning current acceptance."""
    principal = Principal.model_validate(principal)
    principal.require("policy:read")
    principal.require("evidence:decrypt")
    value = await PilotStore(db, cipher, principal).get("observation", observation_id)
    if value is None:
        return None
    return decode_observation(value, tenant_id=principal.tenant_id, observation_id=observation_id).report()


def decode_observation(value: dict, *, tenant_id: str, observation_id: str) -> ObservationRecord:
    record = parse_observation(value)
    if record.tenant_id != tenant_id or record.digest != observation_id:
        raise ValueError("Observation scope or identity mismatch")
    return record
