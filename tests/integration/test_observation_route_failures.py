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


@pytest.fixture
def inspection_case(route_case):
    import json

    from tests.unit.test_pilot_verifier import synthetic_proof

    app, routes = route_case
    principal = Principal(
        tenant_id="synthetic-tenant",
        actor_id="synthetic-actor",
        roles=("proof:inspect", "evidence:decrypt", "policy:read", "observations:write"),
    )
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    target = routes.InspectionTarget(configuration=None, verifier=None)
    app.state.pilot_inspection_targets = {(principal.tenant_id, "synthetic-target"): target}
    body = {
        "target_id": "synthetic-target",
        "credential_id": "synthetic-credential",
        "proof_json": json.dumps(synthetic_proof()),
        "public_signals": ["0"] * 8,
    }
    return app, routes, body


async def inspect_post(app, body):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post("/pilot/proof/inspect", json=body)


@pytest.mark.parametrize(
    "failure,status,detail",
    [
        ("missing-targets", 503, "Pilot inspection configuration is unavailable"),
        ("invalid-targets", 503, "Pilot inspection configuration is unavailable"),
        ("foreign-tenant", 404, "Pilot inspection target is unavailable"),
        ("invalid-target", 503, "Pilot inspection configuration is unavailable"),
        ("missing-db", 503, "Pilot database is unavailable"),
        ("unready-db", 503, "Pilot database is unavailable"),
        ("missing-key", 503, "Pilot inspection configuration is unavailable"),
    ],
)
async def test_inspection_configuration_rejects_before_service(inspection_case, monkeypatch, failure, status, detail):
    app, routes, body = inspection_case
    from unittest.mock import Mock

    constructor = Mock(side_effect=AssertionError("Service must not initialize"))
    monkeypatch.setattr(routes.ProofInspectionService, "__init__", constructor)
    if failure == "missing-targets":
        del app.state.pilot_inspection_targets
    elif failure == "invalid-targets":
        app.state.pilot_inspection_targets = []
    elif failure == "foreign-tenant":
        target = next(iter(app.state.pilot_inspection_targets.values()))
        app.state.pilot_inspection_targets = {("foreign", body["target_id"]): target}
    elif failure == "invalid-target":
        app.state.pilot_inspection_targets = {("synthetic-tenant", body["target_id"]): {}}
    elif failure == "missing-db":
        app.state.db = None
    elif failure == "unready-db":
        app.state.db.is_ready = False
    else:
        monkeypatch.delenv("PII_MASTER_KEY")
    response = await inspect_post(app, body)
    assert response.status_code == status
    assert response.json() == {"detail": detail}
    constructor.assert_not_called()


@pytest.mark.parametrize("error", [ValueError, TypeError, KeyError, RuntimeError])
async def test_inspection_service_configuration_errors_are_minimized(inspection_case, monkeypatch, error):
    from unittest.mock import Mock

    app, routes, body = inspection_case
    constructor = Mock(side_effect=error("synthetic-private-configuration"))
    monkeypatch.setattr(routes.ProofInspectionService, "__init__", constructor)
    response = await inspect_post(app, body)
    assert response.status_code == 503
    assert response.json() == {"detail": "Pilot inspection configuration is unavailable"}
    constructor.assert_called_once()


@pytest.mark.parametrize("failure", ["missing-enrollment", "invalid-proof", "invalid-type", "runtime"])
async def test_inspection_service_rejections_are_minimized(inspection_case, monkeypatch, failure):
    from src.services.enrollment import EnrollmentNotFound

    app, routes, body = inspection_case
    error = {
        "missing-enrollment": EnrollmentNotFound,
        "invalid-proof": ValueError,
        "invalid-type": TypeError,
        "runtime": RuntimeError,
    }[failure]
    monkeypatch.setattr(routes.ProofInspectionService, "__init__", lambda *args: None)
    called = AsyncMock(side_effect=error("synthetic-private-error"))
    monkeypatch.setattr(routes.ProofInspectionService, "inspect", called)
    response = await inspect_post(app, body)
    assert response.status_code == (404 if failure == "missing-enrollment" else 422)
    assert "synthetic-private-error" not in response.text
    called.assert_awaited_once()
    assert called.call_args.args[0] == body["credential_id"]
    assert type(called.call_args.kwargs["now"]) is int


@pytest.mark.parametrize(
    "changes",
    [
        {"proof_json": "invalid"},
        {"public_signals": ["01"] * 8},
        {"target_id": ""},
        {"artifact_path": "/synthetic/operator-only"},
    ],
)
async def test_invalid_inspection_input_precedes_configuration(inspection_case, changes):
    app, _, body = inspection_case
    del app.state.pilot_inspection_targets
    response = await inspect_post(app, {**body, **changes})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid pilot proof input"}


@pytest.mark.parametrize("operation", ["evaluate", "observe"])
@pytest.mark.parametrize("failure", ["fact-trust", "enrollment", "value", "type", "runtime"])
async def test_evaluation_and_observation_failure_mapping(inspection_case, monkeypatch, operation, failure):
    from unittest.mock import Mock

    from src.services.enrollment import EnrollmentNotFound

    app, routes, values = inspection_case
    model = routes.EvaluationBody if operation == "evaluate" else routes.ObservationBody
    extra = {"idempotency_key": "synthetic-retry"} if operation == "observe" else {}
    body = model.model_validate({**values, "fact_ids": (), **extra})
    error = {"enrollment": EnrollmentNotFound, "value": ValueError, "type": TypeError, "runtime": RuntimeError}
    called = AsyncMock(side_effect=error.get(failure, ValueError)("synthetic-private-fact-error"))
    service = SimpleNamespace(**{operation: called})
    target = SimpleNamespace(fact_trust=None if failure == "fact-trust" else Mock(spec=routes.FactTrustStore))
    prepared = AsyncMock(return_value=(service, target, body, body.proof_json.encode(), tuple(body.public_signals)))
    monkeypatch.setattr(routes, "prepare_inspection", prepared)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(f"/pilot/proof/{operation}", json={})
    expected = 503 if failure == "fact-trust" else 404 if failure == "enrollment" else 422
    assert response.status_code == expected
    assert "synthetic-private-fact-error" not in response.text
    prepared.assert_awaited_once()
    if failure == "fact-trust":
        called.assert_not_called()
    else:
        called.assert_awaited_once()
        assert called.call_args.args[0] == body.credential_id
        if operation == "observe":
            assert called.call_args.kwargs["idempotency_key"] == body.idempotency_key


async def test_observation_conflict_has_stable_http_status(inspection_case, monkeypatch):
    from unittest.mock import Mock

    app, routes, values = inspection_case
    body = routes.ObservationBody.model_validate({**values, "fact_ids": (), "idempotency_key": "synthetic-retry"})
    service = SimpleNamespace(observe=AsyncMock(side_effect=routes.RecordConflict("synthetic-private-conflict")))
    target = SimpleNamespace(fact_trust=Mock(spec=routes.FactTrustStore))
    monkeypatch.setattr(routes, "prepare_inspection", AsyncMock(return_value=(service, target, body, b"{}", ())))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/pilot/proof/observe", json={})
    assert response.status_code == 409
    assert response.json() == {"detail": "Observation request or idempotency conflict"}
