"""Discovery failures must reject before proving or encrypting a payload."""

import base64
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from src.protocol.discovery_profile import DiscoveryInvalid, DiscoveryUnavailable, DiscoveryUnsupported


@pytest.fixture
def request_and_route(monkeypatch):
    from src.api.routes import proof

    for name in ("PII_ENVELOPE_MODE", "BENEFICIARY_HPKE_PUBLIC_KEY", "HPKE_DISCOVERY_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    request = proof.ProofGenerateRequest(
        credential_id="test-credential",
        wallet_address="0x" + "1" * 40,
        amount_usd=100,
        asset="USDC",
        destination_wallet="0x" + "2" * 40,
        destination_vasp_did="did:web:beneficiary.example",
        jurisdiction="US",
        idempotency_key="synthetic-transfer",
    )
    return request, proof


@pytest.mark.parametrize(
    "error,status",
    [(DiscoveryInvalid("invalid"), 422), (DiscoveryUnsupported("legacy"), 422), (DiscoveryUnavailable("timeout"), 503)],
)
async def test_discovery_failures_reject(request_and_route, monkeypatch, error, status):
    request, route = request_and_route
    resolver = AsyncMock(side_effect=error)
    monkeypatch.setattr("src.protocol.discovery.resolve_hpke_public_key", resolver)
    with pytest.raises(HTTPException) as caught:
        await route._resolve_recipient_key(request)
    assert caught.value.status_code == status
    resolver.assert_awaited_once_with(request.destination_vasp_did)


async def test_no_key_and_disabled_discovery_rejects(request_and_route, monkeypatch):
    request, route = request_and_route
    monkeypatch.setenv("HPKE_DISCOVERY_ENABLED", "0")
    with pytest.raises(HTTPException, match="HPKE v2 requires"):
        await route._resolve_recipient_key(request)


async def test_legacy_requires_explicit_operator_selection(request_and_route, monkeypatch):
    request, route = request_and_route
    resolver = AsyncMock(side_effect=AssertionError("Legacy mode must not attempt discovery"))
    monkeypatch.setattr("src.protocol.discovery.resolve_hpke_public_key", resolver)
    monkeypatch.setenv("PII_ENVELOPE_MODE", "legacy-v1")
    assert await route._resolve_recipient_key(request) is None
    resolver.assert_not_awaited()
    request.beneficiary_hpke_public_key = "requested-hpke"
    with pytest.raises(HTTPException, match="conflicts"):
        await route._resolve_recipient_key(request)


async def test_invalid_explicit_key_never_uses_discovery(request_and_route, monkeypatch):
    request, route = request_and_route
    resolver = AsyncMock(side_effect=AssertionError("No fallback for invalid supplied key"))
    monkeypatch.setattr("src.protocol.discovery.resolve_hpke_public_key", resolver)
    for key in ("", "A" * 43 + "=", "age1key"):
        request.beneficiary_hpke_public_key = key
        with pytest.raises(HTTPException, match="Invalid beneficiary"):
            await route._resolve_recipient_key(request)
    resolver.assert_not_awaited()


async def test_valid_key_is_usable(request_and_route):
    from src.protocol.discovery_profile import decode_hpke_key
    from src.sar.hpke_envelope import generate_keypair

    request, route = request_and_route
    _, public = generate_keypair()
    request.beneficiary_hpke_public_key = base64.urlsafe_b64encode(public).decode()
    assert await route._resolve_recipient_key(request) == decode_hpke_key(request.beneficiary_hpke_public_key)
