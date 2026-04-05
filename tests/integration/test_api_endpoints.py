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
    resp = await client.get("/metrics", headers={"X-API-Key": API_KEY})
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
    assert resp.status_code == 401


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
    # Patch the _prover singleton directly — patching the class doesn't affect
    # the already-instantiated module-level singleton used by the endpoint.
    with patch("src.api.routes.proof._prover.verify", new_callable=AsyncMock, return_value=True) as mock_verify:
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
        # Verify the prover was actually invoked
        mock_verify.assert_called_once()


# -----------------------------------------------------------------------
# POST /credential/issue
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_credential_issue_creates_credential(client: AsyncClient):
    """POST /credential/issue with valid input should return the credential."""
    # The endpoint constructs zkKYCCredential internally and calls _registry.issue().
    # Mock _registry.issue() to return a known commitment without touching state.
    with patch("src.api.routes.credential._registry.issue", new_callable=AsyncMock) as mock_issue:
        mock_issue.return_value = "0xdeadbeef"
        resp = await client.post(
            "/credential/issue",
            json={
                "issuer_did": "did:web:issuer.example.com",
                "subject_wallet": "0x1234567890abcdef",
                "jurisdiction": "US",
                "kyc_tier": "retail",
            },
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["credential_id"] is not None
        assert body["commitment"] == "0xdeadbeef"
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
    with patch("src.api.routes.credential._registry.get", return_value=None):
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
    mock_cred.kyc_tier = "retail"
    mock_cred.issued_at = int(time.time()) - 3600
    mock_cred.credential_id = "cred-123"

    with patch("src.api.routes.credential._registry.get", return_value=mock_cred):
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
        patch("src.api.routes.credential._registry.get", return_value=mock_cred),
        patch("src.api.routes.credential._registry.revoke"),
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
    with patch("src.api.routes.credential._registry.get", return_value=None):
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

    with patch("src.api.routes.credential._registry.get", return_value=mock_cred):
        resp = await client.post(
            "/credential/revoke",
            json={"credential_id": "cred-123"},
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 400


# -----------------------------------------------------------------------
# POST /proof/generate — happy path
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proof_generate_happy_path(client: AsyncClient):
    """POST /proof/generate with valid input should return a hybrid payload."""
    mock_credential = MagicMock()
    mock_credential.revoked = False
    mock_credential.sanctions_clear = True
    mock_credential.issuer_did = "did:web:issuer.example.com"
    mock_credential.kyc_tier = "retail"
    mock_credential.issued_at = int(time.time()) - 3600
    mock_credential.expires_at = int(time.time()) + 86400

    mock_proof_json = {"pi_a": ["1", "2"], "pi_b": [["3", "4"], ["5", "6"]], "pi_c": ["7", "8"]}
    mock_public_signals = ["1", "0"] + ["0"] * 14

    mock_witness = {
        "left_neighbor": "100",
        "right_neighbor": "200",
        "left_path": {"siblings": ["1", "2", "3"], "indices": [0, 1, 0]},
        "right_path": {"siblings": ["4", "5", "6"], "indices": [1, 0, 1]},
    }

    mock_issuer_witness = {"siblings": ["10", "20", "30"], "indices": [0, 1, 0]}

    with (
        patch("src.api.routes.proof._cred_registry.get", return_value=mock_credential),
        patch("src.api.routes.proof._cred_registry.get_commitment", return_value="12345"),
        patch("src.api.routes.proof._issuer_registry.generate_membership_witness", new_callable=AsyncMock, return_value=mock_issuer_witness),
        patch("src.api.routes.proof._issuer_registry.get_root", return_value="99999"),
        patch("src.api.routes.proof.SanctionsMerkleTree.load") as mock_tree_load,
        patch("src.api.routes.proof._prover.fullprove", new_callable=AsyncMock, return_value=(mock_proof_json, mock_public_signals)) as mock_fullprove,
        patch("src.api.routes.proof._load_vk", return_value={"vk_alpha_1": []}),
        patch("src.api.routes.proof._audit_log.append"),
        patch("src.registry.credential_registry._poseidon_hash", new_callable=AsyncMock, return_value="42"),
        patch("src.sar.encryption.encrypt_pii", return_value=(b"0" * 12, b"encrypted-pii")),
        patch("src.sar.encryption.derive_key", return_value=b"k" * 32),
    ):
        mock_tree = MagicMock()
        mock_tree.root = "55555"
        mock_tree.generate_nonmembership_witness = AsyncMock(return_value=mock_witness)
        mock_tree_load.return_value = mock_tree

        resp = await client.post(
            "/proof/generate",
            json={
                "credential_id": "cred-1",
                "wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
                "amount_usd": 500.0,
                "asset": "USDC",
                "destination_wallet": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "jurisdiction": "US",
                "idempotency_key": "test-idempotency-key-001",
            },
            headers={"X-API-Key": API_KEY},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "compliance_proof" in body
        assert "encrypted_pii" in body
        assert body["compliance_proof"]["jurisdiction"] == "US"
        mock_fullprove.assert_called_once()


# -----------------------------------------------------------------------
# Rate limiting — 429 after threshold
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limiter_unit_returns_429():
    """RateLimiter enforces request limits and raises 429 after threshold.

    Note: This is a unit test of the RateLimiter component, not an
    integration test of rate limiting at the endpoint level. The limiter
    is injected via Depends() in the route definitions.
    """
    from fastapi import HTTPException
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
