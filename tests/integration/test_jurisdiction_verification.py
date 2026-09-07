"""Legacy jurisdiction observation does not invent success or change acceptance."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.main import app
from src.api.middleware.auth import JWTAuthDependency
from src.api.routes import proof as proof_routes
from src.prover.tier_mapping import get_thresholds


@pytest.mark.parametrize(
    "registry_code,active,lookup_error,configured,expected",
    [
        ("US", True, False, True, True),
        ("EU", True, False, True, False),
        ("US", False, False, True, None),
        ("?", True, False, True, None),
        ("A1", True, False, True, None),
        ("US", True, True, True, None),
        ("US", True, False, False, None),
    ],
)
async def test_jurisdiction_observation(monkeypatch, registry_code, active, lookup_error, configured, expected):
    reader = SimpleNamespace(
        get_vasp_info=AsyncMock(
            return_value=("0x" + "11" * 20, registry_code, "", active, 1),
            side_effect=RuntimeError("lookup unavailable") if lookup_error else None,
        )
    )
    monkeypatch.setattr(app.state, "chain_reader", reader if configured else None, raising=False)
    monkeypatch.setattr(proof_routes._prover, "verify", AsyncMock(return_value=True))
    signals = ["0"] * 16
    signals[0], signals[4], signals[6] = "1", "1", str(0x5553)
    thresholds = get_thresholds("US")
    signals[8:11] = [str(thresholds[k]) for k in ("tier2", "tier3", "tier4")]
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[JWTAuthDependency] = lambda: {"sub": "observation-test"}
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/proof/verify",
                json={
                    "proof_id": "jurisdiction-test",
                    "groth16_proof": {},
                    "public_signals": signals,
                    "expected_amount_tier": 1,
                    "originator_vasp_did": "did:web:vasp.example",
                    "transfer_timestamp": int(time.time()),
                },
            )
        assert response.status_code == 200
        result = response.json()
        assert result["valid"] is True
        assert result["rejection_reasons"] == []
        assert result["compliance_attestations"]["jurisdiction_matches_vasp"] is expected
        assert result["compliance_attestations"]["jurisdiction_observation"] == (
            "unverified" if expected is None else "match" if expected else "mismatch"
        )
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)
