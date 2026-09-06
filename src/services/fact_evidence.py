"""Atomic encrypted retention and authenticated current loading of fact attestations."""

from src.auth.principal import Principal
from src.policy.evaluator import PolicyFacts
from src.policy.fact_approval import FactTrustError, FactTrustStore, SignedFactApproval
from src.protocol.canonical import record_digest
from src.protocol.transfer import Transfer, VerificationContext
from src.storage.database import Database
from src.storage.pilot import PilotStore
from src.storage.pilot_cipher import RecordCipher


def fact_evidence_id(signed: SignedFactApproval) -> str:
    return record_digest("clearproof/fact-evidence/v1", signed.model_dump(mode="json"))


class FactEvidenceService:
    def __init__(self, db: Database, cipher: RecordCipher, principal: Principal, trust: FactTrustStore):
        self._principal = Principal.model_validate(principal)
        self._store = PilotStore(db, cipher, self._principal)
        self._trust = trust

    async def retain(
        self,
        approvals: tuple[SignedFactApproval, ...],
        *,
        transfer: Transfer,
        context: VerificationContext,
        now: int,
    ) -> tuple[str, ...]:
        self._principal.require("facts:ingest")
        self._principal.require("evidence:decrypt")
        self._trust.verify_for_context(
            approvals, transfer=transfer, context=context, tenant_id=self._principal.tenant_id, now=now
        )
        signed = tuple(SignedFactApproval.model_validate(a) for a in approvals)
        unique = {fact_evidence_id(a): a for a in signed}
        async with self._store.transaction() as tx:
            for identifier in sorted(unique):
                value = unique[identifier].model_dump(mode="json")
                old = await tx.get("fact-evidence", identifier)
                if old is not None:
                    if old.get("signed") != value:
                        raise FactTrustError("Retained fact evidence identity mismatch")
                    continue
                await tx.put(
                    "fact-evidence",
                    identifier,
                    {
                        "schema_version": "clearproof-retained-fact-v1",
                        "signed": value,
                        "received_at": now,
                        "received_by": self._principal.actor_id,
                    },
                )
        return tuple(sorted(unique))

    async def load_current(
        self,
        identifiers: tuple[str, ...],
        *,
        transfer: Transfer,
        context: VerificationContext,
        now: int,
    ) -> PolicyFacts:
        self._principal.require("policy:read")
        self._principal.require("evidence:decrypt")
        if type(identifiers) is not tuple or len(identifiers) > 64 or len(set(identifiers)) != len(identifiers):
            raise FactTrustError("Expected at most 64 distinct fact references")
        async with self._store.transaction() as tx:
            approvals = []
            for identifier in identifiers:
                record = await tx.get("fact-evidence", identifier)
                if record is None:
                    raise FactTrustError("Fact evidence unavailable in this tenant")
                signed = SignedFactApproval.model_validate(record["signed"])
                if fact_evidence_id(signed) != identifier:
                    raise FactTrustError("Retained fact evidence identity mismatch")
                approvals.append(signed)
            return self._trust.verify_for_context(
                tuple(approvals), transfer=transfer, context=context, tenant_id=self._principal.tenant_id, now=now
            )
