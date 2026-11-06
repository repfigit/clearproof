"""Focused unit tests for wallet-ownership service helpers (no PostgreSQL)."""

from types import SimpleNamespace

import pytest

from src.protocol.wallet_ownership import WalletOwnershipError
from src.services.wallet_ownership import WalletOwnershipService


def test_invalid_delegation_recheck_interval(wallet_enrollment):
    _, consent, principal = wallet_enrollment
    with pytest.raises(WalletOwnershipError, match="Invalid delegation re-check interval"):
        WalletOwnershipService(
            SimpleNamespace(),
            None,  # type: ignore[arg-type]
            principal,
            chain_id=consent.chain_id,
            registry_address=consent.registry_address,
            delegation_recheck_seconds=0,
        )


@pytest.mark.asyncio
async def test_probe_delegation_without_configured_probe(wallet_enrollment):
    _, consent, principal = wallet_enrollment
    service = WalletOwnershipService(
        SimpleNamespace(),
        None,  # type: ignore[arg-type]
        principal,
        chain_id=consent.chain_id,
        registry_address=consent.registry_address,
    )
    result = await service._probe_delegation(consent.credential.subject_wallet)
    assert result["checked"] is False
    assert result["reason"] == "delegation check not configured"


def test_delegation_review_branches():
    review = WalletOwnershipService._delegation_review({"delegated": True, "delegate": "0x" + "1" * 40})
    assert review.startswith("wallet delegated")
    assert WalletOwnershipService._delegation_review({"delegated": True, "delegate": None}) == (
        "wallet carries a delegation indicator"
    )
    assert WalletOwnershipService._delegation_review({"reason": "delegation indicator malformed"}) == (
        "delegation indicator is malformed"
    )
