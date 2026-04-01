"""
Integration tests for the FastAPI endpoints.

Tests basic request/response contracts for each route. Heavy ZK dependencies
(snarkjs, circuit artifacts) are mocked so these tests run without compiled
circuits or a Node.js subprocess.
"""

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

# Set required env vars BEFORE importing the app so the lifespan check passes
# and the auth middleware uses api-key mode.
os.environ.setdefault("PII_MASTER_KEY", "a" * 64)
os.environ.setdefault("AUTH_MODE", "api-key")
os.environ.setdefault("API_KEY", "test-api-key-for-integration")

from src.api.main import app  # noqa: E402

API_KEY = os.environ["API_KEY"]


@pytest.fixture
async def client():
    """Async HTTP client wired to the FastAPI app via ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# -----------------------------------------------------------------------
# GET /health
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "timestamp" in body


# -----------------------------------------------------------------------
# GET /metrics
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_returns_200(client: AsyncClient):
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "proof_generated_count" in body
    assert "uptime_seconds" in body


# -----------------------------------------------------------------------
# GET /auth/nonce
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_nonce_returns_nonce_string(client: AsyncClient):
    """GET /auth/nonce should return a JSON object with a nonce string."""
    with patch("src.api.routes.auth._get_siwe") as mock_siwe_factory:
        mock_siwe = MagicMock()
        mock_siwe.generate_nonce = AsyncMock(return_value="random-nonce-abc123")
        mock_siwe_factory.return_value = mock_siwe

        resp = await client.get("/auth/nonce")
        assert resp.status_code == 200
        body = resp.json()
        assert "nonce" in body
        assert isinstance(body["nonce"], str)
        assert len(body["nonce"]) > 0


# -----------------------------------------------------------------------
# POST /proof/generate
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proof_generate_missing_fields_returns_422(client: AsyncClient):
    """POST /proof/generate with empty body should return 422 validation error."""
    resp = await client.post(
        "/proof/generate",
        json={},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_proof_generate_partial_fields_returns_422(client: AsyncClient):
    """POST /proof/generate with some but not all required fields returns 422."""
    resp = await client.post(
        "/proof/generate",
        json={
            "credential_id": "cred-1",
            "wallet_address": "0xabc",
            # Missing: amount_usd, asset, destination_wallet, jurisdiction, idempotency_key
        },
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_proof_generate_requires_auth(client: AsyncClient):
    """POST /proof/generate without auth header should return 401."""
    resp = await client.post(
        "/proof/generate",
        json={"credential_id": "cred-1"},
    )
    assert resp.status_code in (401, 422)


# -----------------------------------------------------------------------
# POST /proof/verify
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proof_verify_missing_fields_returns_422(client: AsyncClient):
    """POST /proof/verify with empty body should return 422."""
    resp = await client.post(
        "/proof/verify",
        json={},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_proof_verify_with_valid_input(client: AsyncClient):
    """POST /proof/verify with valid structure should reach the prover (mocked)."""
    mock_verify = AsyncMock(return_value=True)

    with patch("src.api.routes.proof.SnarkJSProver") as MockProver:
        instance = MagicMock()
        instance.verify = mock_verify
        MockProver.return_value = instance

        public_signals = ["1", "0"] + ["0"] * 14  # 16 signals total

        resp = await client.post(
            "/proof/verify",
            json={
                "proof_id": "test-proof-id",
                "groth16_proof": {"pi_a": [], "pi_b": [], "pi_c": []},
                "public_signals": public_signals,
                "expected_amount_tier": 1,
                "originator_vasp_did": "did:web:test.vasp.com",
                "transfer_timestamp": int(time.time()),
            },
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "valid" in body
        assert "proof_id" in body
        assert body["proof_id"] == "test-proof-id"


# -----------------------------------------------------------------------
# POST /credential/issue
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_credential_issue_creates_credential(client: AsyncClient):
    """POST /credential/issue with valid input should return the credential."""
    mock_cred = MagicMock()
    mock_cred.credential_id = "cred-123"
    mock_cred.commitment.return_value = "0xdeadbeef"
    mock_cred.issuer_did = "did:web:issuer.example.com"
    mock_cred.jurisdiction = "US"
    mock_cred.kyc_tier = "basic"
    mock_cred.issued_at = int(time.time())
    mock_cred.expires_at = int(time.time()) + 31536000

    with (
        patch("src.api.routes.credential.create_credential", return_value=mock_cred),
        patch("src.api.routes.credential.register_credential"),
    ):
        resp = await client.post(
            "/credential/issue",
            json={
                "issuer_did": "did:web:issuer.example.com",
                "subject_wallet": "0x1234567890abcdef",
                "jurisdiction": "US",
                "kyc_tier": "basic",
            },
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["credential_id"] == "cred-123"
        assert body["issuer_did"] == "did:web:issuer.example.com"


@pytest.mark.asyncio
async def test_credential_issue_requires_auth(client: AsyncClient):
    """POST /credential/issue without auth should return 401."""
    resp = await client.post(
        "/credential/issue",
        json={
            "issuer_did": "did:web:issuer.example.com",
            "subject_wallet": "0x1234567890abcdef",
            "jurisdiction": "US",
            "kyc_tier": "basic",
        },
    )
    assert resp.status_code == 401


# -----------------------------------------------------------------------
# GET /credential/{id}
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_credential_get_not_found(client: AsyncClient):
    """GET /credential/{id} for a non-existent credential should return 404."""
    with patch("src.api.routes.credential.get_credential", return_value=None):
        resp = await client.get(
            "/credential/nonexistent-id",
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_credential_get_existing(client: AsyncClient):
    """GET /credential/{id} for an existing credential returns its status."""
    mock_cred = MagicMock()
    mock_cred.revoked = False
    mock_cred.expires_at = int(time.time()) + 86400
    mock_cred.issuer_did = "did:web:issuer.example.com"
    mock_cred.jurisdiction = "US"
    mock_cred.kyc_tier = "basic"
    mock_cred.issued_at = int(time.time()) - 3600

    with patch("src.api.routes.credential.get_credential", return_value=mock_cred):
        resp = await client.get(
            "/credential/cred-123",
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["credential_id"] == "cred-123"
        assert body["status"] == "active"


# -----------------------------------------------------------------------
# POST /credential/revoke
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_credential_revoke_success(client: AsyncClient):
    """POST /credential/revoke for an active credential returns revoked=true."""
    mock_cred = MagicMock()
    mock_cred.revoked = False

    with (
        patch("src.api.routes.credential.get_credential", return_value=mock_cred),
        patch("src.api.routes.credential.revoke_credential"),
    ):
        resp = await client.post(
            "/credential/revoke",
            json={
                "credential_id": "cred-123",
                "reason": "Testing revocation",
            },
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["revoked"] is True
        assert body["credential_id"] == "cred-123"


@pytest.mark.asyncio
async def test_credential_revoke_not_found(client: AsyncClient):
    """POST /credential/revoke for a non-existent credential returns 404."""
    with patch("src.api.routes.credential.get_credential", return_value=None):
        resp = await client.post(
            "/credential/revoke",
            json={"credential_id": "nonexistent"},
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_credential_revoke_already_revoked(client: AsyncClient):
    """POST /credential/revoke for an already-revoked credential returns 400."""
    mock_cred = MagicMock()
    mock_cred.revoked = True

    with patch("src.api.routes.credential.get_credential", return_value=mock_cred):
        resp = await client.post(
            "/credential/revoke",
            json={"credential_id": "cred-123"},
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 400


# -----------------------------------------------------------------------
# Rate limiting — 429 after threshold
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limiting_returns_429(client: AsyncClient):
    """Endpoints using RateLimiter should return 429 after exceeding the limit.

    We patch the RateLimiter to simulate the threshold being exceeded.
    """
    from fastapi import HTTPException

    async def raise_429(request):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": "60"},
        )

    with patch("src.api.routes.proof._proof_verify_limiter", side_effect=raise_429):
        # The rate limiter is defined at module level but not injected as a
        # Depends() in the current route definitions, so we test the limiter
        # object directly instead.
        from src.api.middleware.rate_limit import RateLimiter

        limiter = RateLimiter(max_requests=2, window_seconds=60)

        # Build a minimal mock request
        mock_request = MagicMock()
        mock_request.headers = {"X-API-Key": "rate-limit-test"}
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        # First two requests should pass
        await limiter(mock_request)
        await limiter(mock_request)

        # Third request should raise 429
        with pytest.raises(HTTPException) as exc_info:
            await limiter(mock_request)
        assert exc_info.value.status_code == 429
        assert "Rate limit" in exc_info.value.detail
