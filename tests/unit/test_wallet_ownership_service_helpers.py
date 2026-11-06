"""Focused unit tests for wallet-ownership service helpers (no PostgreSQL)."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from eth_account.messages import encode_defunct

from src.chain.wallet_account import WalletAccountRPCError
from src.protocol.wallet_ownership import (
    WalletAttestationV2,
    WalletChallenge,
    WalletChallengeV2,
    WalletOwnershipError,
)
from src.services.wallet_ownership import WalletDelegationReview, WalletOwnershipService


@pytest.fixture
def challenge(wallet_enrollment):
    wallet, consent, principal = wallet_enrollment
    value = WalletChallenge(
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        credential=consent.credential,
        chain_id=consent.chain_id,
        registry_address=consent.registry_address,
        nonce="ef" * 32,
        timestamp=1100,
        expires_at=1400,
    )
    signature = "0x" + wallet.sign_message(encode_defunct(text=value.message())).signature.hex()
    return value, signature


@pytest.fixture
def challenge_v2(wallet_enrollment):
    wallet, consent, principal = wallet_enrollment
    value = WalletChallengeV2(
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        credential=consent.credential,
        chain_id=consent.chain_id,
        registry_address=consent.registry_address,
        nonce="cd" * 32,
        timestamp=1100,
        expires_at=1400,
        siwe_domain="clearproof.example",
        siwe_resource=f"urn:clearproof:credential:{consent.credential.credential_nonce}",
    )
    signature = "0x" + wallet.sign_message(encode_defunct(text=value.message())).signature.hex()
    return value, signature


def _service(wallet_enrollment, **kwargs):
    _, consent, principal = wallet_enrollment
    return WalletOwnershipService(
        SimpleNamespace(),
        None,  # type: ignore[arg-type]
        principal,
        chain_id=consent.chain_id,
        registry_address=consent.registry_address,
        **kwargs,
    )


def _v2_attestation(challenge_v2, *, delegation=None, method="eoa", signature=None):
    challenge, default_sig = challenge_v2
    return WalletAttestationV2(
        attestation_id=challenge.nonce,
        challenge=challenge,
        signature=signature or default_sig,
        method=method,
        issued_at=1200,
        expires_at=1200 + 86400,
        delegation=delegation
        or {"checked": True, "delegated": False, "delegate": None, "checked_at": 1200, "reason": None},
    )


class _FakeTx:
    def __init__(self, storage=None):
        self.storage = storage if storage is not None else {}

    async def get(self, kind, key):
        return self.storage.get((kind, key))

    async def put(self, kind, key, value, expected_revision=None):
        self.storage[(kind, key)] = value


def test_invalid_delegation_recheck_interval(wallet_enrollment):
    with pytest.raises(WalletOwnershipError, match="Invalid delegation re-check interval"):
        _service(wallet_enrollment, delegation_recheck_seconds=0)


@pytest.mark.asyncio
async def test_probe_delegation_without_configured_probe(wallet_enrollment):
    _, consent, _ = wallet_enrollment
    service = _service(wallet_enrollment, clock=lambda: 9999)
    result = await service._probe_delegation(consent.credential.subject_wallet, now=1200)
    assert result["checked"] is False
    assert result["checked_at"] == 1200
    assert result["reason"] == "delegation check not configured"


@pytest.mark.asyncio
async def test_probe_delegation_records_failures_and_malformed_results(wallet_enrollment):
    _, consent, _ = wallet_enrollment
    address = consent.credential.subject_wallet

    async def broken(_addr: str) -> dict:
        raise RuntimeError("rpc down")

    service = _service(wallet_enrollment, account_probe=broken)
    failed = await service._probe_delegation(address, now=1200)
    assert failed["checked"] is False
    assert "failed" in (failed.get("reason") or "")

    async def invalid(_addr: str) -> dict:
        return {"delegated": "yes"}

    service.account_probe = invalid
    invalid_result = await service._probe_delegation(address, now=1201)
    assert invalid_result["checked"] is False
    assert invalid_result["reason"] == "delegation check returned an invalid record"

    async def malformed_indicator(_addr: str) -> dict:
        return {"delegated": False, "delegate": 123, "indicator_malformed": True, "has_code": True}

    service.account_probe = malformed_indicator
    malformed = await service._probe_delegation(address, now=1202)
    assert malformed["checked"] is True
    assert malformed["reason"] == "delegation indicator malformed"
    assert malformed["has_code"] is True


def test_delegation_review_branches():
    review = WalletOwnershipService._delegation_review({"delegated": True, "delegate": "0x" + "1" * 40})
    assert review.startswith("wallet delegated")
    assert WalletOwnershipService._delegation_review({"delegated": True, "delegate": None}) == (
        "wallet carries a delegation indicator"
    )
    assert WalletOwnershipService._delegation_review({"reason": "delegation indicator malformed"}) == (
        "delegation indicator is malformed"
    )
    assert WalletOwnershipService._delegation_review({"delegated": False, "reason": None}) is None


@pytest.mark.asyncio
async def test_recheck_delegation_paths(wallet_enrollment, challenge_v2):
    attestation = _v2_attestation(challenge_v2)
    tx = _FakeTx()

    async def probe(_addr: str) -> dict:
        return {"delegated": False, "delegate": None, "indicator_malformed": False, "has_code": False}

    service = _service(wallet_enrollment, account_probe=probe, delegation_recheck_seconds=60)

    empty = await service._recheck_delegation(
        tx,
        SimpleNamespace(challenge=attestation.challenge, attestation_id=attestation.attestation_id),
        1300,
    )
    assert empty == {"delegation": None, "history": []}

    delegation = {"checked": True, "delegated": False, "delegate": None, "checked_at": 1200, "reason": None}
    attestation = attestation.model_copy(update={"delegation": delegation})
    skipped = await service._recheck_delegation(tx, attestation, 1230)
    assert skipped["history"] == []
    assert skipped["delegation"]["checked_at"] == 1200

    refreshed = await service._recheck_delegation(tx, attestation, 1300)
    assert len(refreshed["history"]) == 1
    assert refreshed["history"][0]["checked_at"] == 1300
    assert tx.storage[("wallet-delegation-log", attestation.attestation_id)] == refreshed["history"]

    attestation_v1 = SimpleNamespace(
        delegation=attestation.delegation,
        challenge=attestation.challenge,
        attestation_id=attestation.attestation_id,
    )
    from_log = await service._recheck_delegation(tx, attestation_v1, 1400)
    assert len(from_log["history"]) == 2


@pytest.mark.asyncio
async def test_recheck_delegation_api_errors(wallet_enrollment, challenge_v2):
    attestation = _v2_attestation(challenge_v2)
    storage = {("wallet-attestation", attestation.attestation_id): attestation.model_dump(mode="json")}

    @asynccontextmanager
    async def transaction():
        yield _FakeTx(storage)

    service = _service(wallet_enrollment, account_probe=AsyncMock())
    service.store = SimpleNamespace(transaction=transaction)

    with pytest.raises(WalletOwnershipError, match="outside its validity interval"):
        await service.recheck_delegation(attestation.attestation_id, now=attestation.expires_at)

    with patch.object(service, "_recheck_delegation", AsyncMock(return_value={"delegation": None, "history": []})):
        with pytest.raises(WalletOwnershipError, match="not configured"):
            await service.recheck_delegation(attestation.attestation_id, now=1250)


@pytest.mark.asyncio
async def test_verify_v2_smart_account_branches(wallet_enrollment, challenge_v2):
    challenge, _ = challenge_v2
    storage = {
        ("wallet-challenge", challenge.nonce): challenge.model_dump(mode="json"),
    }

    @asynccontextmanager
    async def transaction():
        yield _FakeTx(storage)

    async def probe(_addr: str) -> dict:
        return {"delegated": False, "delegate": None, "indicator_malformed": False, "has_code": True}

    service = _service(wallet_enrollment, account_probe=probe, chain_verifier=None)
    service.store = SimpleNamespace(transaction=transaction)

    async def credential(_tx, _credential_id, _now):
        return challenge.credential

    service._credential = credential

    with pytest.raises(WalletOwnershipError, match="65-byte EOA signature"):
        await service.verify(challenge.nonce, "0x" + "ab" * 65, now=1200)

    with pytest.raises(WalletOwnershipError, match="requires chain access"):
        await service.verify(challenge.nonce, "0x" + "ab" * 120, now=1200)

    async def reject(_address: str, _message: str, _signature: str) -> tuple[bool, str]:
        return False, "erc-1271"

    service.chain_verifier = reject
    with pytest.raises(WalletOwnershipError, match="Invalid wallet ownership signature"):
        await service.verify(challenge.nonce, "0x" + "ab" * 120, now=1200)

    async def rpc_fail(*_args):
        raise WalletAccountRPCError("offline")

    service.chain_verifier = rpc_fail
    with pytest.raises(WalletOwnershipError, match="unavailable"):
        await service.verify(challenge.nonce, "0x" + "ab" * 120, now=1200)

    async def accept(_address: str, _message: str, _signature: str) -> tuple[bool, str]:
        return True, "erc-6492"

    service.chain_verifier = accept
    attestation = await service.verify(challenge.nonce, "0x" + "ab" * 120, now=1200)
    assert attestation.method == "erc-6492"

    async def probe_eoa(_addr: str) -> dict:
        return {"delegated": False, "delegate": None, "indicator_malformed": False, "has_code": False}

    service.account_probe = probe_eoa
    with pytest.raises(WalletOwnershipError, match="65-byte signature"):
        await service.verify(challenge.nonce, "0x" + "ab" * 64, now=1200)


@pytest.mark.asyncio
async def test_active_delegation_review_and_public_helpers(wallet_enrollment, challenge_v2):
    attestation = _v2_attestation(
        challenge_v2,
        delegation={
            "checked": True,
            "delegated": True,
            "delegate": "0x" + "2" * 40,
            "checked_at": 1200,
            "reason": None,
        },
    )
    storage = {
        ("wallet-attestation", attestation.attestation_id): attestation.model_dump(mode="json"),
        ("wallet-delegation-log", attestation.attestation_id): [],
    }

    @asynccontextmanager
    async def transaction():
        yield _FakeTx(storage)

    async def probe(_addr: str) -> dict:
        return {"delegated": True, "delegate": "0x" + "2" * 40, "indicator_malformed": False, "has_code": False}

    service = _service(wallet_enrollment, account_probe=probe, delegation_recheck_seconds=3600)
    service.store = SimpleNamespace(transaction=transaction)

    async def credential(_tx, _credential_id, _now):
        return attestation.challenge.credential

    service._credential = credential

    with pytest.raises(WalletDelegationReview, match="delegation review required"):
        await service.assert_active(attestation.attestation_id, now=1250)

    attestation_safe = _v2_attestation(challenge_v2, method="erc-1271", signature="0x" + "ab" * 120)
    storage[("wallet-attestation", attestation_safe.attestation_id)] = attestation_safe.model_dump(mode="json")
    loaded = await service.assert_active(attestation_safe.attestation_id, now=1250)
    assert loaded.method == "erc-1271"

    with pytest.raises(WalletOwnershipError, match="different subject wallet"):
        await service.assert_active(attestation_safe.attestation_id, subject_wallet="0x" + "99" * 20, now=1250)

    evidence = await service.delegation_evidence(attestation_safe.attestation_id, now=1250)
    assert evidence["message_format"] == "eip-4361"
    assert evidence["credential_nonce"] == attestation_safe.challenge.credential.credential_nonce

    with pytest.raises(WalletOwnershipError, match="outside its validity interval"):
        await service.delegation_evidence(attestation_safe.attestation_id, now=attestation_safe.expires_at)
