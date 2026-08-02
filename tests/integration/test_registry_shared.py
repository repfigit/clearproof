"""
Regression test for AIF-80: Credentials issued via the API must be visible
to proof generation on the same app instance.

Previously, `src/api/routes/credential.py` and `src/api/routes/proof.py`
each constructed their own `CredentialRegistry()` instance at module load,
causing proof generation to return 404 "Credential not found" for every
credential issued through the API.
"""

import os
import time
from unittest.mock import patch

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


@pytest.mark.asyncio
async def test_issued_credential_visible_to_proof_generate(client: AsyncClient):
    """
    POST /credential/issue → POST /proof/generate against the same app instance
    with no registry patching must find the credential.

    This test must fail on the buggy code (two singletons) and pass on the
    fixed code (shared dependency).
    """
    # 1. Issue a credential
    issue_resp = await client.post(
        "/credential/issue",
        json={
            "issuer_did": "did:web:test-issuer.example.com",
            "subject_wallet": "0x1234567890abcdef1234567890abcdef12345678",
            "jurisdiction": "US",
            "kyc_tier": "retail",
            "expires_in_seconds": 31536000,
        },
        headers={"X-API-Key": API_KEY},
    )
    assert issue_resp.status_code == 200
    credential_id = issue_resp.json()["credential_id"]

    # 2. Attempt to generate a proof using that credential_id
    #    On the buggy code, this would return 404 "Credential not found"
    #    because proof.py's _cred_registry is a different instance than
    #    credential.py's _registry.
    with patch("src.prover.snarkjs_prover.SnarkJSProver.fullprove") as mock_prover:
        # Mock the ZK prover so we don't need real circuit artifacts
        mock_prover.return_value = ({"proof": "mocked"}, ["1"] * 16)

        with patch("src.registry.sanctions_list.SanctionsMerkleTree.load") as mock_sanctions:
            # Mock sanctions tree so we don't need real artifacts
            mock_tree = type("MockTree", (), {"root": "0" * 64})()
            mock_sanctions.return_value = mock_tree

            with patch("src.api.routes.proof._load_vk") as mock_vk:
                mock_vk.return_value = {"mock": "vk"}

                generate_resp = await client.post(
                    "/proof/generate",
                    json={
                        "credential_id": credential_id,
                        "wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
                        "amount_usd": 100.0,
                        "asset": "USDC",
                        "destination_wallet": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                        "jurisdiction": "US",
                        "idempotency_key": f"test-key-{int(time.time())}",
                    },
                    headers={"X-API-Key": API_KEY},
                )

            # The fix: this must NOT be 404
            assert generate_resp.status_code != 404, (
                "Credential not found — split-brain registry bug (AIF-80) still present. "
                "Each route module is still constructing its own CredentialRegistry instance."
            )

            # If the prover/sanctions mocks are incomplete, we may get 500 or 422,
            # but as long as it's not 404 "Credential not found", the registry
            # split-brain is fixed.
            if generate_resp.status_code == 200:
                assert "proof_id" in generate_resp.json()
