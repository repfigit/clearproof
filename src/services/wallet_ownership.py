"""Durable tenant/issuer-bound wallet ownership; no mutation of existing credentials."""

import hashlib
import secrets
import time
from typing import Awaitable, Callable

from src.auth.principal import Principal
from src.chain.wallet_account import WalletAccountRPCError
from src.protocol.wallet_ownership import (
    ATTESTATION_TTL,
    CHALLENGE_TTL,
    WalletAttestation,
    WalletAttestationV2,
    WalletChallenge,
    WalletChallengeV2,
    WalletCredentialExtension,
    WalletOwnershipError,
    _delegation_record,
    load_attestation,
    load_challenge,
)
from src.services.enrollment import EnrollmentIneligible, load_unrevoked_enrollment
from src.storage.pilot import PilotStore, RecordConflict


class WalletEvidenceNotFound(WalletOwnershipError):
    pass


class WalletChallengeLimit(WalletOwnershipError):
    pass


class WalletDelegationReview(WalletOwnershipError):
    """Delegated or malformed-indicator wallet: evidence stays, eligibility pauses."""


class WalletOwnershipService:
    # Hard, per-tenant daily bound, enforced under the same transaction lock as
    # challenge creation. This bounds retained challenge growth and lookup work.
    DAILY_CHALLENGE_LIMIT = 256

    def __init__(
        self,
        db,
        cipher,
        principal: Principal,
        *,
        chain_id: int,
        registry_address: str,
        clock: Callable[[], int] | None = None,
        account_probe: Callable[[str], Awaitable[dict]] | None = None,
        chain_verifier: Callable[..., Awaitable[tuple[bool, str]]] | None = None,
        delegation_recheck_seconds: int = 3600,
    ):
        self.principal = Principal.model_validate(principal)
        self.store = PilotStore(db, cipher, self.principal)
        self.chain_id, self.registry_address = chain_id, registry_address
        self.clock = clock or (lambda: int(time.time()))
        # Optional async callable address -> delegation probe dict
        # ({delegated, delegate, indicator_malformed, has_code}). When absent,
        # delegation status is recorded as unchecked; attestations never fail
        # closed on the probe being unconfigured.
        self.account_probe = account_probe
        # Optional async callable (address, message, signature) -> (valid, method)
        # for ERC-1271/ERC-6492 smart-account verification.
        self.chain_verifier = chain_verifier
        if type(delegation_recheck_seconds) is not int or delegation_recheck_seconds <= 0:
            raise WalletOwnershipError("Invalid delegation re-check interval")
        self.delegation_recheck_seconds = delegation_recheck_seconds

    def _time(self, now: int | None) -> int:
        value = self.clock() if now is None else now
        if type(value) is not int or not 0 <= value < 2**53:
            raise WalletOwnershipError("Invalid wallet evidence evaluation time")
        return value

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

    async def challenge(
        self, credential_id: str, *, now: int | None = None, siwe_domain: str | None = None
    ) -> WalletChallenge | WalletChallengeV2:
        async with self.store.transaction() as tx:
            now = self._time(now)
            credential = await self._credential(tx, credential_id, now)
            bucket = "day-" + str(now // 86400)
            quota = await tx.read("wallet-quota", bucket)
            count = quota.value["count"] if quota else 0
            if count >= self.DAILY_CHALLENGE_LIMIT:
                raise WalletChallengeLimit("Daily tenant wallet challenge limit reached")
            fields = {
                "tenant_id": self.principal.tenant_id,
                "actor_id": self.principal.actor_id,
                "credential": credential,
                "chain_id": self.chain_id,
                "registry_address": self.registry_address,
                "nonce": secrets.token_hex(32),
                "timestamp": now,
                "expires_at": now + CHALLENGE_TTL,
            }
            if siwe_domain is None:
                challenge = WalletChallenge.model_validate(fields)
            else:
                # SIWE (ERC-4361) profile: the resource binds the enrolled
                # credential so the signed message itself identifies what the
                # attestation covers.
                challenge = WalletChallengeV2.model_validate(
                    {
                        **fields,
                        "siwe_domain": siwe_domain,
                        "siwe_resource": f"urn:clearproof:credential:{credential.credential_nonce}",
                    }
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

    async def _probe_delegation(self, address: str, *, now: int | None = None) -> dict:
        """Run the delegation probe, returning a normalized RAW status record.

        The record carries an internal ``has_code`` flag for smart-account
        dispatch; it MUST be stripped (``_delegation_status``) before storage —
        stored attestation delegation records carry exactly the five schema keys.
        Probe absence or failure is recorded honestly (checked=False) rather
        than guessed: an unchecked wallet is a review state, not a pass.
        """
        checked_at = self._time(now)
        if self.account_probe is None:
            return _delegation_record(False, None, None, checked_at, "delegation check not configured")
        try:
            result = await self.account_probe(address)
        except Exception as exc:  # noqa: BLE001 - any probe failure is recorded, never swallowed as "not delegated"
            return _delegation_record(False, None, None, checked_at, f"delegation check failed: {exc}")
        if not isinstance(result, dict) or not isinstance(result.get("delegated"), bool):
            return _delegation_record(False, None, None, checked_at, "delegation check returned an invalid record")
        raw = _delegation_record(
            True,
            result["delegated"],
            result.get("delegate") if isinstance(result.get("delegate"), str) else None,
            checked_at,
            "delegation indicator malformed" if result.get("indicator_malformed") else None,
        )
        raw["has_code"] = bool(result.get("has_code"))
        return raw

    @staticmethod
    def _delegation_status(raw: dict) -> dict:
        """Strip internal probe keys for storage (the five schema keys only)."""
        return {key: raw.get(key) for key in ("checked", "delegated", "delegate", "checked_at", "reason")}

    @staticmethod
    def _delegation_log_entries(log: dict | None) -> list:
        if not isinstance(log, dict):
            return []
        entries = log.get("entries")
        return list(entries) if isinstance(entries, list) else []

    @staticmethod
    def _delegation_log_payload(entries: list) -> dict:
        return {"entries": entries}

    @staticmethod
    def _delegation_review(delegation: dict) -> str | None:
        """A delegated or malformed-indicator wallet must not silently pass."""
        if delegation.get("delegated") is True:
            delegate = delegation.get("delegate")
            return f"wallet delegated to {delegate}" if delegate else "wallet carries a delegation indicator"
        if delegation.get("reason") == "delegation indicator malformed":
            return "delegation indicator is malformed"
        return None

    async def _recheck_delegation(self, tx, attestation, now: int) -> dict:
        """Re-run the delegation probe when the last check is older than the interval.

        This is the standing re-check for whitelisted addresses: every status
        or extension evaluation refreshes the delegation picture at most once
        per interval, appending to the per-attestation delegation log that the
        evidence export reports. External schedulers can force an immediate
        check via recheck_delegation().
        """
        delegation = getattr(attestation, "delegation", None)
        current = dict(delegation) if isinstance(delegation, dict) else None
        log_record = await tx.read("wallet-delegation-log", attestation.attestation_id)
        entries = self._delegation_log_entries(log_record.value if log_record else None)
        if entries:
            current = entries[-1]
        if current is None:
            return {"delegation": None, "history": entries}
        if current.get("checked") and now - current.get("checked_at", 0) < self.delegation_recheck_seconds:
            return {"delegation": current, "history": entries}
        fresh = await self._probe_delegation(attestation.challenge.credential.subject_wallet, now=now)
        entries.append(self._delegation_status(fresh))
        await tx.put(
            "wallet-delegation-log",
            attestation.attestation_id,
            self._delegation_log_payload(entries),
            expected_revision=log_record.revision if log_record else None,
        )
        return {"delegation": fresh, "history": entries}

    async def recheck_delegation(self, attestation_id: str, *, now: int | None = None) -> dict:
        """Force an immediate delegation re-check (scheduler entry point)."""
        async with self.store.transaction() as tx:
            attestation = await self._attestation(tx, attestation_id)
            now = self._time(now)
            if not attestation.issued_at <= now < attestation.expires_at:
                raise WalletOwnershipError("Wallet attestation is outside its validity interval")
            result = await self._recheck_delegation(tx, attestation, now)
            if result["delegation"] is None:
                raise WalletOwnershipError("Delegation check is not configured for this attestation")
            review = self._delegation_review(result["delegation"])
            return {
                "attestation_id": attestation_id,
                "delegation": result["delegation"],
                "delegation_review": review,
                "history": result["history"],
            }

    async def verify(
        self, nonce: str, signature: str, *, now: int | None = None
    ) -> WalletAttestation | WalletAttestationV2:
        async with self.store.transaction() as tx:
            stored = await tx.get("wallet-challenge", nonce)
            if stored is None:
                raise WalletEvidenceNotFound("Wallet challenge not found")
            challenge = load_challenge(stored)
            self._context(challenge, actor=True)
            evaluated_at = self._time(now)
            if challenge.nonce != nonce or not challenge.timestamp <= evaluated_at < challenge.expires_at:
                raise WalletOwnershipError("Wallet challenge is expired or mismatched")
            credential = await self._credential(tx, challenge.credential.credential_nonce, evaluated_at)
            if credential != challenge.credential:
                raise WalletOwnershipError("Challenge credential changed")
            now = self._time(now)
            if not challenge.timestamp <= now < min(challenge.expires_at, credential.expires_at):
                raise WalletOwnershipError("Wallet challenge or credential expired during verification")
            if isinstance(challenge, WalletChallengeV2):
                probe = await self._probe_delegation(challenge.credential.subject_wallet, now=now)
                method = "eoa"
                is_contract_wallet = bool(probe.get("has_code"))
                if is_contract_wallet:
                    # Smart account (or EIP-7702-delegated EOA): verify through
                    # the contract's ERC-1271/ERC-6492 path on-chain. A 65-byte
                    # signature is not accepted on code-bearing wallets.
                    if len(signature) == 132:
                        raise WalletOwnershipError(
                            "Smart-account wallet cannot be verified with a 65-byte EOA signature"
                        )
                    if self.chain_verifier is None:
                        raise WalletOwnershipError(
                            "Smart-account verification requires chain access (WALLET_OWNERSHIP_RPC_URL)"
                        )
                    try:
                        valid, verified_method = await self.chain_verifier(
                            challenge.credential.subject_wallet, challenge.message(), signature
                        )
                    except WalletAccountRPCError as exc:
                        raise WalletOwnershipError(f"Smart-account verification unavailable: {exc}") from exc
                    if not valid:
                        raise WalletOwnershipError("Invalid wallet ownership signature")
                    method = verified_method
                else:
                    if len(signature) != 132:
                        raise WalletOwnershipError("EOA wallet verification requires a 65-byte signature")
                    challenge.verify_signature(signature)
                attestation = WalletAttestationV2(
                    attestation_id=nonce,
                    challenge=challenge,
                    signature=signature,
                    method=method,
                    issued_at=now,
                    expires_at=now + ATTESTATION_TTL,
                    delegation=self._delegation_status(probe),
                )
            else:
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
        attestation = load_attestation(stored)
        self._context(attestation.challenge, revoke=revoke)
        if attestation.attestation_id != attestation_id:
            raise WalletOwnershipError("Wallet attestation identifier mismatch")
        if isinstance(attestation, WalletAttestationV2) and attestation.method != "eoa":
            # ERC-1271/ERC-6492 signatures are not re-verified with ecrecover on
            # later reads: the standing code/delegation re-check (below, via
            # _active) is the deliberate cheap check. Full re-verification would
            # require chain access on every read — a documented limitation.
            pass
        else:
            attestation.challenge.verify_signature(attestation.signature)
        return attestation

    async def _active(self, tx, attestation_id, now):
        attestation = await self._attestation(tx, attestation_id)
        now = self._time(now)
        if not attestation.issued_at <= now < attestation.expires_at:
            raise WalletOwnershipError("Wallet attestation is outside its validity interval")
        if await tx.get("wallet-revocation", attestation_id) is not None:
            raise WalletOwnershipError("Wallet attestation is revoked")
        credential = await self._credential(tx, attestation.challenge.credential.credential_nonce, now)
        if credential != attestation.challenge.credential:
            raise WalletOwnershipError("Wallet attestation credential changed")
        if hasattr(attestation, "delegation"):
            # Standing EBA ¶86 re-check: refresh at most once per interval; a
            # delegated or malformed-indicator wallet pauses eligibility.
            result = await self._recheck_delegation(tx, attestation, now)
            if result["delegation"] is not None:
                review = self._delegation_review(result["delegation"])
                if review:
                    raise WalletDelegationReview(f"Wallet delegation review required: {review}")
        return attestation

    async def status(self, attestation_id: str, *, now: int | None = None) -> dict:
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
                "delegation": dict(attestation.delegation) if isinstance(attestation, WalletAttestationV2) else None,
            }

    async def assert_active(
        self, attestation_id: str, *, subject_wallet: str | None = None, now: int | None = None
    ) -> WalletAttestation | WalletAttestationV2:
        """Public eligibility check for credential issuance: active, unrevoked, no delegation review.

        When subject_wallet is given, the attestation must belong to exactly that
        wallet — an attestation cannot upgrade a credential for a different subject.
        """
        async with self.store.transaction() as tx:
            attestation = await self._active(tx, attestation_id, now)
            if (
                subject_wallet is not None
                and attestation.challenge.credential.subject_wallet.lower() != subject_wallet.lower()
            ):
                raise WalletOwnershipError("Wallet attestation belongs to a different subject wallet")
            return attestation

    async def delegation_evidence(self, attestation_id: str, *, now: int | None = None) -> dict:
        """Full evidence-export inputs: attestation record, delegation log, credential binding."""
        async with self.store.transaction() as tx:
            attestation = await self._attestation(tx, attestation_id)
            now = self._time(now)
            if not attestation.issued_at <= now < attestation.expires_at:
                raise WalletOwnershipError("Wallet attestation is outside its validity interval")
            log = await tx.get("wallet-delegation-log", attestation_id)
            return {
                "attestation_record": attestation.model_dump(mode="json"),
                "initial_delegation": (
                    dict(attestation.delegation) if isinstance(attestation, WalletAttestationV2) else None
                ),
                "rechecks": self._delegation_log_entries(log),
                "message": attestation.challenge.message(),
                "message_format": (
                    "eip-4361" if isinstance(attestation.challenge, WalletChallengeV2) else "clearproof-canonical-v1"
                ),
                "credential_nonce": attestation.challenge.credential.credential_nonce,
                "subject_wallet": attestation.challenge.credential.subject_wallet,
            }

    async def revoke(self, attestation_id: str, *, now: int | None = None) -> dict:
        async with self.store.transaction() as tx:
            attestation = await self._attestation(tx, attestation_id, revoke=True)
            now = self._time(now)
            if now < attestation.issued_at:
                raise WalletOwnershipError("Revocation precedes attestation")
            prior = await tx.get("wallet-revocation", attestation_id)
            if prior is None:
                prior = {"attestation_id": attestation_id, "revoked_at": now, "revoked_by": self.principal.actor_id}
                await tx.put("wallet-revocation", attestation_id, prior)
            return {"attestation_id": attestation_id, "revoked": True, "revoked_at": prior["revoked_at"]}

    async def issue_extension(self, attestation_id: str, *, now: int | None = None) -> WalletCredentialExtension:
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
