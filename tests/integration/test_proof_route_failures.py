"""Proof preconditions must work inside the API's running event loop."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


@pytest.fixture
def route(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "synthetic-api-key")
    from src.api.routes import proof

    return proof


@pytest.mark.parametrize("age", [0, 100, 101])
async def test_sanctions_check_awaits_database_with_age_boundary(route, monkeypatch, caplog, age):
    from src.storage import sanctions

    database = object()
    store = SimpleNamespace(get_current=AsyncMock(return_value=SimpleNamespace(updated_at=1000 - age)))
    factory = Mock(return_value=store)
    monkeypatch.setattr(sanctions, "SanctionsStore", factory)
    monkeypatch.setattr(route.time, "time", lambda: 1000)
    monkeypatch.setenv("SANCTIONS_MAX_AGE_SECONDS", "100")
    await route._check_sanctions_staleness(database)
    store.get_current.assert_awaited_once()
    factory.assert_called_once_with(database)
    assert ("Sanctions root is" in caplog.text) is (age > 100)


async def test_sanctions_missing_root_fails_closed(route, monkeypatch):
    from src.storage import sanctions

    store = SimpleNamespace(get_current=AsyncMock(return_value=None))
    monkeypatch.setattr(sanctions, "SanctionsStore", Mock(return_value=store))
    with pytest.raises(RuntimeError, match="No sanctions root"):
        await route._check_sanctions_staleness(object())
    await route._check_sanctions_staleness(None)


@pytest.fixture
def request_data(route):
    return route.ProofGenerateRequest(
        credential_id="synthetic",
        wallet_address="0x" + "1" * 40,
        amount_usd=10,
        asset="USDC",
        destination_wallet="0x" + "2" * 40,
        jurisdiction="US",
        idempotency_key="synthetic-retry",
    )


@pytest.mark.parametrize(
    "state,expected", [("missing", 404), ("revoked", 403), ("expired", 410), ("expiry-boundary", 410)]
)
async def test_credentials_rejected_before_proving(route, monkeypatch, request_data, state, expected):
    from fastapi import HTTPException

    monkeypatch.setattr(route, "_get_db", lambda _app: None)
    monkeypatch.setattr(route.time, "time", lambda: 1000)
    credential = (
        None
        if state == "missing"
        else SimpleNamespace(revoked=state == "revoked", expires_at=999 if state == "expired" else 1000)
    )
    registry = SimpleNamespace(get=Mock(return_value=credential))
    with pytest.raises(HTTPException) as error:
        await route.generate_proof(request_data, SimpleNamespace(app=None), _cred_registry=registry)
    assert error.value.status_code == expected


async def test_required_originator_name_blocks_before_storage(route, monkeypatch, request_data):
    from fastapi import HTTPException

    storage = Mock()
    monkeypatch.setattr(route, "_get_db", storage)
    request_data.amount_usd = 10000
    with pytest.raises(HTTPException) as error:
        await route.generate_proof(request_data, SimpleNamespace(app=None))
    assert error.value.status_code == 422
    storage.assert_not_called()


async def test_idempotent_result_is_returned_without_regenerating(route, monkeypatch, request_data):
    from src.storage import proofs, sanctions

    database = object()
    monkeypatch.setattr(route, "_get_db", lambda _app: database)
    monkeypatch.setattr(
        sanctions,
        "SanctionsStore",
        Mock(
            return_value=SimpleNamespace(
                get_current=AsyncMock(return_value=SimpleNamespace(updated_at=route.time.time()))
            )
        ),
    )
    store = SimpleNamespace(check_idempotency=AsyncMock(return_value="cached-digest"))
    monkeypatch.setattr(proofs, "ProofStore", Mock(return_value=store))
    registry = SimpleNamespace(get=Mock())
    assert await route.generate_proof(request_data, SimpleNamespace(app=None), _cred_registry=registry) == {
        "status": "already_generated",
        "result_hash": "cached-digest",
    }
    registry.get.assert_not_called()
    store.check_idempotency.assert_awaited_once_with(request_data.idempotency_key)


async def test_verification_failure_does_not_log_untrusted_data(route, monkeypatch, caplog, sample_compliance_proof):
    from fastapi import HTTPException

    monkeypatch.setattr(route._prover, "verify", AsyncMock(side_effect=ValueError("synthetic-private-marker")))
    request = route.ProofVerifyRequest(
        proof_id="synthetic",
        groth16_proof={},
        public_signals=sample_compliance_proof.public_signals,
        expected_amount_tier=2,
        originator_vasp_did="did:web:synthetic.example",
        transfer_timestamp=1000,
    )
    with pytest.raises(HTTPException) as error:
        await route.verify_proof(request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace())))
    assert error.value.status_code == 503
    assert "synthetic-private-marker" not in caplog.text


async def test_generation_uses_request_application_database(route, monkeypatch, request_data):
    from httpx import ASGITransport, AsyncClient

    from src.api.main import create_app
    from src.storage import proofs, sanctions

    application = create_app()
    database = object()
    application.state.db = database
    roots = Mock(
        return_value=SimpleNamespace(get_current=AsyncMock(return_value=SimpleNamespace(updated_at=route.time.time())))
    )
    monkeypatch.setattr(sanctions, "SanctionsStore", roots)
    monkeypatch.setattr(
        proofs,
        "ProofStore",
        Mock(return_value=SimpleNamespace(check_idempotency=AsyncMock(return_value="request-app-result"))),
    )
    # The independently constructed app must not read the module-global app's state.
    application.dependency_overrides[route.JWTAuthDependency] = lambda: {"sub": "synthetic"}
    application.dependency_overrides[route._proof_generate_limiter] = lambda: None
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://local") as client:
        response = await client.post("/proof/generate", json=request_data.model_dump())
    assert response.status_code == 200
    assert response.json() == {"status": "already_generated", "result_hash": "request-app-result"}
    roots.assert_called_once_with(database)


@pytest.mark.parametrize("signals", [[], ["not-decimal"] + ["0"] * 15])
async def test_invalid_verification_signals_return_client_error(route, monkeypatch, signals):
    from fastapi import HTTPException

    monkeypatch.setattr(route._prover, "verify", AsyncMock(return_value=False))
    request = route.ProofVerifyRequest(
        proof_id="synthetic",
        groth16_proof={},
        public_signals=signals,
        expected_amount_tier=2,
        originator_vasp_did="did:web:synthetic.example",
        transfer_timestamp=1000,
    )
    with pytest.raises(HTTPException) as error:
        await route.verify_proof(request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace())))
    assert error.value.status_code == 400


@pytest.mark.parametrize(
    "result",
    [
        None,
        (),
        ("id", "US", "", False, 1),
        ("id", "US", "", True, 0),
        ("id", "bad", "", True, 1),
        ("id", "us", "", True, 1),
        RuntimeError("unavailable"),
    ],
)
async def test_unavailable_or_invalid_chain_observation_is_unverified(
    route, monkeypatch, sample_compliance_proof, result
):
    monkeypatch.setattr(route._prover, "verify", AsyncMock(return_value=False))
    reader = SimpleNamespace(get_vasp_info=AsyncMock())
    if isinstance(result, Exception):
        reader.get_vasp_info.side_effect = result
    else:
        reader.get_vasp_info.return_value = result
    request = route.ProofVerifyRequest(
        proof_id="synthetic",
        groth16_proof={},
        public_signals=sample_compliance_proof.public_signals,
        expected_amount_tier=2,
        originator_vasp_did="did:web:synthetic.example",
        transfer_timestamp=1000,
    )
    response = await route.verify_proof(
        request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(chain_reader=reader)))
    )
    assert response.valid is False
    assert "groth16_invalid" in response.rejection_reasons
    assert response.compliance_attestations["jurisdiction_matches_vasp"] is None
    assert response.compliance_attestations["jurisdiction_observation"] == "unverified"
