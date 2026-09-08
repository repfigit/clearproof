"""Pilot route dependency failures and HTTP error mapping, without database I/O."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from src.auth.principal import Principal


@pytest.fixture
def principal():
    return Principal(tenant_id="synthetic-tenant", actor_id="synthetic-actor", roles=("evidence:decrypt",))


DEPENDENCIES = [
    ("wallet_ownership", "wallet_service", {}),
    ("enrollment", "enrollment_service", {}),
    ("policy", "review_service", {}),
    ("events", "event_service", {"ingestion": False}),
]


@pytest.mark.parametrize("module,function,kwargs", DEPENDENCIES)
@pytest.mark.parametrize("state", ["absent", "none", "not-ready"])
def test_route_dependencies_reject_unavailable_database(principal, module, function, kwargs, state):
    routes = import_module(f"src.api.routes.{module}")
    app_state = SimpleNamespace()
    if state != "absent":
        app_state.db = None if state == "none" else SimpleNamespace(is_ready=False)
    request = SimpleNamespace(app=SimpleNamespace(state=app_state))
    with pytest.raises(HTTPException) as error:
        getattr(routes, function)(request, principal, **kwargs)
    assert error.value.status_code == 503
    assert "database" in error.value.detail.lower()


@pytest.mark.parametrize(
    "module,function,kwargs,failure",
    [
        (*dependency, failure)
        for dependency in DEPENDENCIES
        for failure in ("missing-key", "invalid-chain", "invalid-key")
        if failure != "invalid-chain" or dependency[0] in ("wallet_ownership", "enrollment")
    ],
)
def test_route_dependencies_minimize_configuration_errors(principal, monkeypatch, module, function, kwargs, failure):
    routes = import_module(f"src.api.routes.{module}")
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.delenv("PII_ROTATED_KEYS", raising=False)
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "12" * 20)
    if failure == "invalid-chain":
        monkeypatch.setenv("PILOT_CHAIN_ID", "synthetic-invalid-chain")
    elif failure == "missing-key":
        monkeypatch.delenv("PII_MASTER_KEY")
    else:
        monkeypatch.setenv("PII_MASTER_KEY", "synthetic-invalid-key")
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db=SimpleNamespace(is_ready=True))))
    with pytest.raises(HTTPException) as error:
        getattr(routes, function)(request, principal, **kwargs)
    assert error.value.status_code == 503
    assert "configuration" in error.value.detail.lower()
    assert "synthetic-invalid" not in error.value.detail
    assert "PII_MASTER_KEY" not in error.value.detail


@pytest.mark.parametrize("failure,status", [("limit", 429), ("integrity", 503)])
async def test_wallet_evidence_maps_limit_and_integrity_errors(failure, status):
    from src.api.routes.wallet_ownership import invoke
    from src.services.enrollment import EnrollmentIntegrityError
    from src.services.wallet_ownership import WalletChallengeLimit

    error_type = WalletChallengeLimit if failure == "limit" else EnrollmentIntegrityError
    operation = AsyncMock(side_effect=error_type("Synthetic test failure"))
    with pytest.raises(HTTPException) as error:
        await invoke(operation())
    assert error.value.status_code == status
    if failure == "integrity":
        assert error.value.detail == "Retained enrollment integrity failed"
    operation.assert_awaited_once()


@pytest.mark.parametrize("failure,status", [("ineligible", 422), ("conflict", 409)])
async def test_enrollment_revocation_maps_service_rejection(failure, status):
    from src.api.routes.enrollment import revoke
    from src.services.enrollment import EnrollmentIneligible
    from src.storage.pilot import RecordConflict

    error_type = EnrollmentIneligible if failure == "ineligible" else RecordConflict
    service = SimpleNamespace(revoke=AsyncMock(side_effect=error_type("Synthetic internal detail")))
    # The handler forwards an already validated request; this test isolates error mapping.
    body = object()
    with pytest.raises(HTTPException) as error:
        await revoke(body, service)
    assert error.value.status_code == status
    assert "Synthetic internal detail" not in error.value.detail
    assert service.revoke.call_args.args == (body,)
