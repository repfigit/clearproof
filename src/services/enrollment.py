"""Durable enrollment acceptance, prior to authenticated issuance-root publication."""

from src.auth.principal import Principal
from src.protocol.enrollment import EnrollmentConsent
from src.storage.database import Database
from src.storage.pilot import PilotStore
from src.storage.pilot_cipher import RecordCipher


class EnrollmentService:
    def __init__(
        self, db: Database, cipher: RecordCipher, principal: Principal, *, chain_id: int, registry_address: str
    ):
        self._principal = Principal.model_validate(principal)
        self._store = PilotStore(db, cipher, self._principal)
        self._chain_id, self._registry_address = chain_id, registry_address

    async def enroll(self, consent: EnrollmentConsent, signature: str, *, idempotency_key: str, now: int) -> dict:
        consent = EnrollmentConsent.model_validate(consent)
        # Check time/audience/issuer/signature even on retries. An expired consent
        # cannot initiate an operation; inspecting a prior result is a separate read.
        consent.verify(
            signature,
            principal=self._principal,
            chain_id=self._chain_id,
            registry_address=self._registry_address,
            now=now,
        )
        request = {"consent": consent.model_dump(mode="json"), "signature": signature}

        async def persist(tx):
            credential = consent.credential
            await tx.put(
                "credential",
                credential.credential_nonce,
                {
                    "schema_version": "clearproof-enrolled-credential-v1",
                    **request,
                    "credential_commitment": credential.commitment,
                    "accepted_by": self._principal.actor_id,
                    "accepted_at": now,
                },
            )
            return {"credential_id": credential.credential_nonce, "status": "awaiting-root-publication"}

        return await self._store.run_idempotent("issue-credential", idempotency_key, request, persist)
