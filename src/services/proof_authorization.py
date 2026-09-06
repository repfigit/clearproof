"""Atomic local pilot authorization; no payment or counterparty delivery."""

import base64
import hashlib

from src.policy.fact_approval import FactTrustStore
from src.protocol.canonical import record_digest
from src.protocol.transfer_information import validate_transfer_information
from src.prover.pilot_verifier import PilotProof, public_signals
from src.sar.pilot_envelope import MAX_PAYLOAD_BYTES, RecipientTrustStore, seal_pilot_envelope
from src.services.proof_inspection import ProofInspectionService
from src.storage.pilot import ReplayConflict


class AuthorizationRejected(ValueError):
    """Current verified evidence did not yield ALLOW; nothing was retained."""


class ProofAuthorizationService(ProofInspectionService):
    async def authorize(
        self,
        credential_id: str,
        proof: bytes,
        signals: list[str],
        fact_ids: tuple[str, ...],
        *,
        fact_trust: FactTrustStore,
        pii: bytes,
        recipient_trust: RecipientTrustStore,
        recipient_key_id: str,
        idempotency_key: str,
        now: int,
    ) -> dict:
        """Consume once after current inspection and ALLOW in the same transaction.

        An exact retry returns the original historical receipt, including after
        expiry or trust changes. It does not reauthorize or execute a transfer.
        Trust and transfer configuration must be supplied by the authenticated
        server. This is not an HTTP request interface or an offline certificate.
        """
        for role in ("proof:consume", "proof:generate", "proof:inspect", "policy:read", "evidence:decrypt"):
            self._principal.require(role)
        if type(now) is not int or not 0 <= now < 2**53:
            raise ValueError("Invalid authorization clock")
        if type(pii) is not bytes or not 1 <= len(pii) <= MAX_PAYLOAD_BYTES:
            raise ValueError("Expected 1–32768 payload bytes")
        validate_transfer_information(pii, self._inputs["transfer"], self._context)
        PilotProof.parse(proof)
        signals = public_signals(signals)
        fact_ids = tuple(fact_ids)
        if len(fact_ids) > 64 or len(set(fact_ids)) != len(fact_ids):
            raise ValueError("Expected at most 64 distinct fact references")
        fact_ids = tuple(sorted(fact_ids))
        request = {
            "credential_id": credential_id,
            "proof_digest": hashlib.sha256(proof).hexdigest(),
            "signals": list(signals),
            "fact_ids": list(fact_ids),
            "transfer_digest": self._context.transfer_digest,
            "context_digest": self._context.digest,
            "recipient_key_id": recipient_key_id,
        }
        nullifier = format(int(signals[3]), "064x")

        async def persist(tx):
            if await tx.is_consumed(nullifier):
                raise ReplayConflict("Authorization is already consumed")
            inspection, decision = await self._evaluate_transaction(
                tx, credential_id, proof, signals, fact_ids, fact_trust=fact_trust, now=now
            )
            if not inspection.cryptographic_valid or decision is None or decision.outcome != "ALLOW":
                raise AuthorizationRejected("Current proof and policy must yield ALLOW")
            envelope = seal_pilot_envelope(
                pii,
                recipient_trust,
                recipient_key_id,
                self._inputs["transfer"],
                self._context,
                proof_digest=request["proof_digest"],
                now=now,
            )
            envelope_digest = record_digest("clearproof/pilot-envelope/v1", envelope)
            proof_id = record_digest("clearproof/authorized-proof/v1", {**request, "envelope_digest": envelope_digest})
            receipt = {
                "schema_version": "clearproof-local-authorization-v1",
                "tenant_id": self._principal.tenant_id,
                "actor_id": self._principal.actor_id,
                "proof_id": proof_id,
                "transfer_digest": self._context.transfer_digest,
                "context_digest": self._context.digest,
                "policy_digest": decision.policy_digest,
                "manifest_digest": inspection.manifest_digest,
                "proof_profile": inspection.proof_profile,
                "nullifier": nullifier,
                "authorized_at": now,
                "expires_at": int(signals[5]),
                "outcome": "ALLOW",
                "execution": "not-requested",
                "envelope_digest": envelope_digest,
                "recipient_key_id": recipient_key_id,
            }
            receipt_id = record_digest("clearproof/local-authorization/v1", receipt)
            await tx.put(
                "proof",
                proof_id,
                {
                    "schema_version": "clearproof-retained-proof-v1",
                    **request,
                    "proof_base64": base64.b64encode(proof).decode("ascii"),
                    "context": self._context.model_dump(mode="json"),
                    "transfer": self._inputs["transfer"].model_dump(mode="json"),
                    "policy_evaluation": decision.model_dump(mode="json"),
                    "recipient_envelope": envelope,
                },
            )
            await tx.put("receipt", receipt_id, receipt)
            await tx.consume(nullifier, proof_id)
            return {"receipt_id": receipt_id, **receipt}

        # Payload fingerprints stay inside the encrypted idempotency request digest;
        # public identifiers bind randomized ciphertext, never a guessable PII hash.
        return await self._store.run_idempotent(
            "consume-proof", idempotency_key, {**request, "payload_digest": hashlib.sha256(pii).hexdigest()}, persist
        )
