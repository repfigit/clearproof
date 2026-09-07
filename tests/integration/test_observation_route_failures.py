"""Observation HTTP failure mapping; durable behavior has PostgreSQL tests."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.auth.principal import Principal, TenantPrincipalDependency


@pytest.fixture
def route_case(monkeypatch):
    from src.api.routes import pilot_proof

    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.delenv("PII_ROTATED_KEYS", raising=False)
    app = FastAPI()
    app.include_router(pilot_proof.router)
    principal = Principal(
        tenant_id="synthetic-tenant", actor_id="synthetic-actor", roles=("policy:read", "evidence:decrypt")
    )
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    app.state.db = SimpleNamespace(is_ready=True)
    return app, pilot_proof


CASES = [
    ("read", {"observation_id": "ab" * 32}, "read_observation"),
    (
        "report",
        {"cohort_id": "synthetic-cohort", "cases": [{"case_id": "case", "observation_id": None}]},
        "observation_cohort_report",
    ),
    ("list", {"limit": 1}, "list_observations"),
]


async def post(app, operation, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post(f"/pilot/proof/observations/{operation}", **kwargs)


@pytest.mark.parametrize("operation,body,service_name", CASES)
@pytest.mark.parametrize("ready", [None, False])
async def test_observation_routes_reject_unavailable_database(route_case, operation, body, service_name, ready):
    app, _ = route_case
    app.state.db = None if ready is None else SimpleNamespace(is_ready=False)
    response = await post(app, operation, json=body)
    assert response.status_code == 503
    assert response.json() == {"detail": "Pilot database is unavailable"}


@pytest.mark.parametrize("operation,body,service_name", CASES)
async def test_observation_routes_reject_invalid_encryption_configuration(
    route_case,
    monkeypatch,
    operation,
    body,
    service_name,
):
    app, routes = route_case
    monkeypatch.delenv("PII_MASTER_KEY")
    called = AsyncMock()
    monkeypatch.setattr(routes, service_name, called)
    response = await post(app, operation, json=body)
    assert response.status_code == 503
    assert "PII_MASTER_KEY" not in response.text
    called.assert_not_called()


@pytest.mark.parametrize("operation,body,service_name", CASES)
@pytest.mark.parametrize("error", [ValueError, TypeError])
async def test_observation_routes_minimize_storage_failures(
    route_case, monkeypatch, operation, body, service_name, error
):
    app, routes = route_case
    called = AsyncMock(side_effect=error("synthetic-private-storage-detail"))
    monkeypatch.setattr(routes, service_name, called)
    response = await post(app, operation, json=body)
    assert response.status_code == 503
    assert "synthetic-private-storage-detail" not in response.text
    called.assert_awaited_once()
    assert called.call_args.args[2].tenant_id == "synthetic-tenant"


@pytest.mark.parametrize("operation,body,service_name", CASES)
async def test_observation_routes_return_service_results(route_case, monkeypatch, operation, body, service_name):
    app, routes = route_case
    expected = {"synthetic": "service-result", "authorization_consumed": False}
    called = AsyncMock(return_value=expected)
    monkeypatch.setattr(routes, service_name, called)
    response = await post(app, operation, json=body)
    assert response.status_code == 200
    assert response.json() == expected
    called.assert_awaited_once()


async def test_missing_observation_is_404(route_case, monkeypatch):
    app, routes = route_case
    monkeypatch.setattr(routes, "read_observation", AsyncMock(return_value=None))
    response = await post(app, "read", json={"observation_id": "ab" * 32})
    assert response.status_code == 404
    assert response.json() == {"detail": "Observation is unavailable"}


@pytest.mark.parametrize("operation,body,service_name", CASES)
@pytest.mark.parametrize(
    "raw", [b"{", b'{"unknown":1}', b'{"observation_id":"synthetic","observation_id":"duplicate"}']
)
async def test_invalid_observation_body_rejects_before_storage(route_case, operation, body, service_name, raw):
    app, _ = route_case
    app.state.db = None
    response = await post(app, operation, content=raw)
    assert response.status_code == 422


async def test_observation_pagination_rejects_query_selectors(route_case):
    app, _ = route_case
    app.state.db = None
    response = await post(app, "list", json={"limit": 1}, params={"after": "ab" * 32})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid observation page"}


@pytest.mark.parametrize("operation,body,service_name", CASES)
@pytest.mark.parametrize("roles", [("policy:read",), ("evidence:decrypt",), ("tenant:admin",)])
async def test_observation_reads_require_both_explicit_roles(
    route_case, monkeypatch, operation, body, service_name, roles
):
    app, routes = route_case
    principal = Principal(tenant_id="synthetic-tenant", actor_id="synthetic-actor", roles=roles)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    called = AsyncMock()
    monkeypatch.setattr(routes, service_name, called)
    response = await post(app, operation, json=body)
    assert response.status_code == 403
    assert response.json() == {"detail": "Required role is not granted"}
    called.assert_not_called()
