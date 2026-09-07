"""Durable tenant/issuer-bound wallet ownership; no mutation of existing credentials."""

import hashlib
import secrets

from src.auth.principal import Principal
from src.protocol.wallet_ownership import (
    ATTESTATION_TTL,
    CHALLENGE_TTL,
    WalletAttestation,
    WalletChallenge,
    WalletCredentialExtension,
    WalletOwnershipError,
)
from src.services.enrollment import EnrollmentIneligible, load_unrevoked_enrollment
from src.storage.pilot import PilotStore, RecordConflict


class WalletEvidenceNotFound(WalletOwnershipError):
    pass


class WalletChallengeLimit(WalletOwnershipError):
    pass


class WalletOwnershipService:
    # Hard, per-tenant daily bound, enforced under the same transaction lock as
    # challenge creation. This bounds retained challenge growth and lookup work.
    DAILY_CHALLENGE_LIMIT = 256

    def __init__(self, db, cipher, principal: Principal, *, chain_id: int, registry_address: str):
        self.principal = Principal.model_validate(principal)
        self.store = PilotStore(db, cipher, self.principal)
        self.chain_id, self.registry_address = chain_id, registry_address

    async def _credential(self, tx, credential_id, now):
        credential = await load_unrevoked_enrollment(
            tx, credential_id, chain_id=self.chain_id, registry_address=self.registry_address, now=now
        )
        self.principal.require_issuer(credential.issuer_did)
        return credential

    def _context(self, challenge: WalletChallenge, *, actor: bool = False, revoke: bool = False):
        self.principal.require_issuer(
            challenge.credential.issuer_did, "credential:revoke" if revoke else "credential:issue"
        )
        if (challenge.tenant_id, challenge.chain_id, challenge.registry_address) != (
            self.principal.tenant_id,
            self.chain_id,
            self.registry_address,
        ):
            raise WalletOwnershipError("Wallet evidence context mismatch")
        if actor and challenge.actor_id != self.principal.actor_id:
            raise WalletOwnershipError("Challenge belongs to another actor")

    async def challenge(self, credential_id: str, *, now: int) -> WalletChallenge:
        async with self.store.transaction() as tx:
            credential = await self._credential(tx, credential_id, now)
            bucket = "day-" + str(now // 86400)
            quota = await tx.read("wallet-quota", bucket)
            count = quota.value["count"] if quota else 0
            if count >= self.DAILY_CHALLENGE_LIMIT:
                raise WalletChallengeLimit("Daily tenant wallet challenge limit reached")
            challenge = WalletChallenge(
                tenant_id=self.principal.tenant_id,
                actor_id=self.principal.actor_id,
                credential=credential,
                chain_id=self.chain_id,
                registry_address=self.registry_address,
                nonce=secrets.token_hex(32),
                timestamp=now,
                expires_at=now + CHALLENGE_TTL,
            )
            # A single challenge per actor/credential/time bucket additionally
            # bounds accidental retry storms. No wallet or issuer is an index key.
            slot = hashlib.sha256(
                f"{self.principal.actor_id}/{credential_id}/{now // CHALLENGE_TTL}".encode()
            ).hexdigest()
            await tx.put("wallet-challenge-slot", slot, {"nonce": challenge.nonce})
            await tx.put("wallet-challenge", challenge.nonce, challenge.model_dump(mode="json"))
            await tx.put(
                "wallet-quota", bucket, {"count": count + 1}, expected_revision=quota.revision if quota else None
            )
            return challenge

    async def verify(self, nonce: str, signature: str, *, now: int) -> WalletAttestation:
        async with self.store.transaction() as tx:
            stored = await tx.get("wallet-challenge", nonce)
            if stored is None:
                raise WalletEvidenceNotFound("Wallet challenge not found")
            challenge = WalletChallenge.model_validate(stored)
            self._context(challenge, actor=True)
            if challenge.nonce != nonce or not challenge.timestamp <= now < challenge.expires_at:
                raise WalletOwnershipError("Wallet challenge is expired or mismatched")
            credential = await self._credential(tx, challenge.credential.credential_nonce, now)
            if credential != challenge.credential:
                raise WalletOwnershipError("Challenge credential changed")
            challenge.verify_signature(signature)
            attestation = WalletAttestation(
                attestation_id=nonce,
                challenge=challenge,
                signature=signature,
                issued_at=now,
                expires_at=now + ATTESTATION_TTL,
            )
            # The immutable nonce-keyed attestation is also the consumption marker.
            # Check/verify/insert all execute under the tenant transaction lock.
            await tx.put("wallet-attestation", nonce, attestation.model_dump(mode="json"))
            return attestation

    async def _attestation(self, tx, attestation_id, *, revoke=False):
        stored = await tx.get("wallet-attestation", attestation_id)
        if stored is None:
            raise WalletEvidenceNotFound("Wallet attestation not found")
        attestation = WalletAttestation.model_validate(stored)
        self._context(attestation.challenge, revoke=revoke)
        if attestation.attestation_id != attestation_id:
            raise WalletOwnershipError("Wallet attestation identifier mismatch")
        attestation.challenge.verify_signature(attestation.signature)
        return attestation

    async def _active(self, tx, attestation_id, now):
        attestation = await self._attestation(tx, attestation_id)
        if not attestation.issued_at <= now < attestation.expires_at:
            raise WalletOwnershipError("Wallet attestation is outside its validity interval")
        if await tx.get("wallet-revocation", attestation_id) is not None:
            raise WalletOwnershipError("Wallet attestation is revoked")
        credential = await self._credential(tx, attestation.challenge.credential.credential_nonce, now)
        if credential != attestation.challenge.credential:
            raise WalletOwnershipError("Wallet attestation credential changed")
        return attestation

    async def status(self, attestation_id: str, *, now: int) -> dict:
        async with self.store.transaction() as tx:
            attestation = await self._attestation(tx, attestation_id)
            # Eligibility errors do not become a successful verification flag.
            try:
                await self._active(tx, attestation_id, now)
                active, reason = True, None
            except (WalletOwnershipError, EnrollmentIneligible) as exc:
                active, reason = False, str(exc)
            return {
                "attestation_id": attestation_id,
                "wallet_ownership_verified": active,
                "issued_at": attestation.issued_at,
                "expires_at": attestation.expires_at,
                "reason": reason,
            }

    async def revoke(self, attestation_id: str, *, now: int) -> dict:
        async with self.store.transaction() as tx:
            attestation = await self._attestation(tx, attestation_id, revoke=True)
            if now < attestation.issued_at:
                raise WalletOwnershipError("Revocation precedes attestation")
            prior = await tx.get("wallet-revocation", attestation_id)
            if prior is None:
                prior = {"attestation_id": attestation_id, "revoked_at": now, "revoked_by": self.principal.actor_id}
                await tx.put("wallet-revocation", attestation_id, prior)
            return {"attestation_id": attestation_id, "revoked": True, "revoked_at": prior["revoked_at"]}

    async def issue_extension(self, attestation_id: str, *, now: int) -> WalletCredentialExtension:
        async with self.store.transaction() as tx:
            attestation = await self._active(tx, attestation_id, now)
            extension = WalletCredentialExtension(
                credential_commitment=attestation.challenge.credential.commitment,
                attestation_digest=attestation.digest_scalar,
                issued_at=attestation.issued_at,
                expires_at=min(attestation.expires_at, attestation.challenge.credential.expires_at),
                wallet_ownership_verified=True,
            )
            prior = await tx.get("wallet-extension", attestation_id)
            if prior is None:
                await tx.put("wallet-extension", attestation_id, extension.model_dump(mode="json"))
            elif WalletCredentialExtension.model_validate(prior) != extension:
                raise RecordConflict("Stored wallet extension differs from retained evidence")
            return extension
