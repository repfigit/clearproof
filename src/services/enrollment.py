"""Durable enrollment acceptance, prior to authenticated issuance-root publication."""

from src.auth.principal import Principal
from src.protocol.credential import PilotCredential
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.transfer import Epoch, Hex32, OpaqueId, Record
from src.storage.database import Database
from src.storage.pilot import PilotStore, PilotTransaction
from src.storage.pilot_cipher import RecordCipher


class EnrollmentNotFound(LookupError):
    """No enrollment exists in the authenticated tenant."""


class EnrollmentIneligible(ValueError):
    """Enrollment is revoked, expired, inconsistent or failed screening."""


class EnrollmentIntegrityError(ValueError):
    """Persisted enrollment identity or commitment is inconsistent."""


async def load_unrevoked_enrollment(tx: PilotTransaction, credential_id: str, *, now: int) -> PilotCredential:
    """Read enrollment and revocation in the caller's tenant transaction.

    This is one proving precondition. Root membership, holder knowledge and
    current authorization context still require independent verification.
    """
    stored = await tx.get("credential", credential_id)
    if stored is None:
        raise EnrollmentNotFound("Enrollment not found")
    consent = EnrollmentConsent.model_validate(stored["consent"])
    credential = consent.credential
    if (
        credential.tenant_id != tx.tenant_id
        or credential.credential_nonce != credential_id
        or credential.commitment != stored["credential_commitment"]
    ):
        raise EnrollmentIntegrityError("Enrollment identity or commitment failed")
    if (
        type(now) is not int
        or now < stored["accepted_at"]
        or not credential.issued_at <= now < credential.expires_at
        or not credential.sanctions_clear
    ):
        raise EnrollmentIneligible("Enrollment facts or validity failed")
    if await tx.get("revocation", credential_id) is not None:
        raise EnrollmentIneligible("Enrollment is revoked")
    return credential


class RevocationRequest(Record):
    credential_id: Hex32
    idempotency_key: OpaqueId
    # A bounded code avoids freeform PII in revocation reasons.
    reason_code: OpaqueId


class RevocationRecord(Record):
    credential_id: Hex32
    credential_commitment: str
    revoked_by: OpaqueId
    revoked_at: Epoch
    reason_code: OpaqueId


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

    async def revoke(self, request: RevocationRequest, *, now: int) -> dict:
        request = RevocationRequest.model_validate(request)
        self._principal.require("credential:revoke")
        stored = await self._store.get("credential", request.credential_id)
        if stored is None:
            raise EnrollmentNotFound("Enrollment not found")
        consent = EnrollmentConsent.model_validate(stored["consent"])
        self._principal.require_issuer(consent.credential.issuer_did, "credential:revoke")
        if consent.credential.tenant_id != self._principal.tenant_id:
            raise ValueError("Stored enrollment tenant mismatch")
        # Credential records are immutable. Scope checks precede even cached
        # retries; losing issuer scope must not expose a prior operation result.
        revocation = RevocationRecord(
            credential_id=request.credential_id,
            credential_commitment=consent.credential.commitment,
            revoked_by=self._principal.actor_id,
            revoked_at=now,
            reason_code=request.reason_code,
        )
        if now < stored["accepted_at"]:
            raise EnrollmentIneligible("Revocation precedes enrollment")

        async def persist(tx):
            await tx.put("revocation", request.credential_id, revocation.model_dump(mode="json"))
            return {"credential_id": request.credential_id, "status": "revoked", "revoked_at": now}

        return await self._store.run_idempotent(
            "revoke-credential", request.idempotency_key, request.model_dump(mode="json"), persist
        )
