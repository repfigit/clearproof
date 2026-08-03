import pytest
from unittest.mock import AsyncMock, patch
import time
import hashlib
import os

# Set required env vars BEFORE importing the app so the lifespan check passes
# and the auth middleware uses api-key mode.
os.environ.setdefault("PII_MASTER_KEY", "a" * 64)
os.environ.setdefault("AUTH_MODE", "api-key")
os.environ.setdefault("API_KEY", "test-api-key-for-integration")

from httpx import ASGITransport, AsyncClient
from src.api.main import app
from src.chain.reader import get_chain_reader

API_KEY = "test-api-key-for-integration"


@pytest.fixture
async def client():
    """Async HTTP client wired to the FastAPI app via ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_jurisdiction_verification_in_verify_proof(client):
    """Test that jurisdiction verification is performed in /proof/verify endpoint."""
    mock_vasp_info = ("0x0000000000000000000000000000000000000000", "US", "", True, 0)
    
    with patch("src.api.routes.proof._prover.verify", new_callable=AsyncMock, return_value=True), \
         patch("src.api.routes.proof.get_chain_reader") as mock_get_chain_reader:
        
        mock_chain_reader = AsyncMock()
        mock_chain_reader.get_vasp_info = AsyncMock(return_value=mock_vasp_info)
        mock_get_chain_reader.return_value = mock_chain_reader
        
        public_signals = ["1", "0"] + ["0"] * 14  # 16 signals total
        # Set the jurisdiction code to US (0x5553 = 21843)
        public_signals[6] = "21843"
        
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
        
        # Should succeed since jurisdiction matches
        assert resp.status_code == 200
        
        # Check that the jurisdiction_matches_vasp field is present in the response
        json_resp = resp.json()
        assert "jurisdiction_matches_vasp" in json_resp["compliance_attestations"]
        assert json_resp["compliance_attestations"]["jurisdiction_matches_vasp"] == True


@pytest.mark.asyncio
async def test_jurisdiction_mismatch_in_verify_proof(client):
    """Test that jurisdiction mismatch is detected in /proof/verify endpoint."""
    mock_vasp_info = ("0x0000000000000000000000000000000000000000", "EU", "", True, 0)
    
    with patch("src.api.routes.proof._prover.verify", new_callable=AsyncMock, return_value=True), \
         patch("src.api.routes.proof.get_chain_reader") as mock_get_chain_reader:
        
        mock_chain_reader = AsyncMock()
        mock_chain_reader.get_vasp_info = AsyncMock(return_value=mock_vasp_info)
        mock_get_chain_reader.return_value = mock_chain_reader
        
        public_signals = ["1", "0"] + ["0"] * 14  # 16 signals total
        # Set the jurisdiction code to US (0x5553 = 21843) but VASP is registered as EU
        public_signals[6] = "21843"
        
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
        
        # Should succeed but jurisdiction_matches_vasp should be False
        assert resp.status_code == 200
        
        # Check that the jurisdiction_matches_vasp field is present in the response
        json_resp = resp.json()
        assert "jurisdiction_matches_vasp" in json_resp["compliance_attestations"]
        assert json_resp["compliance_attestations"]["jurisdiction_matches_vasp"] == False