"""Process-local metrics and liveness retain their documented API boundaries."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def case(monkeypatch):
    from src.api.middleware import auth
    from src.api.routes import health

    monkeypatch.setattr(auth, "AUTH_MODE", "api-key")
    monkeypatch.setattr(auth, "API_KEY", "synthetic-metrics-key")
    clock = SimpleNamespace(time=lambda: 1000.0)
    monkeypatch.setattr(health, "time", clock)
    metrics = health._MetricsStore()
    monkeypatch.setattr(health, "metrics", metrics)
    app = FastAPI()
    app.include_router(health.router)
    app.state.db = None
    return app, metrics, clock


async def test_empty_metrics_are_zero_and_require_authentication(case):
    app, _, _ = case
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/metrics")).status_code == 401
        response = await client.get("/metrics", headers={"X-API-Key": "synthetic-metrics-key"})
    assert response.status_code == 200
    assert response.json() == {
        "proof_generated_count": 0,
        "proof_verified_count": 0,
        "avg_proof_generation_ms": 0.0,
        "avg_proof_verification_ms": 0.0,
        "credential_issued_count": 0,
        "credential_revoked_count": 0,
        "uptime_seconds": 0.0,
    }


async def test_metrics_compute_independent_averages_and_round_for_transport(case):
    app, metrics, clock = case
    metrics.proof_generated_count = 3
    metrics.proof_generation_total_ms = 100.0
    metrics.proof_verified_count = 2
    metrics.proof_verification_total_ms = 25.0
    metrics.credential_issued_count = 7
    metrics.credential_revoked_count = 1
    clock.time = lambda: 1001.234
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/metrics", headers={"X-API-Key": "synthetic-metrics-key"})
    assert response.status_code == 200
    assert response.json() == {
        "proof_generated_count": 3,
        "proof_verified_count": 2,
        "avg_proof_generation_ms": 33.33,
        "avg_proof_verification_ms": 12.5,
        "credential_issued_count": 7,
        "credential_revoked_count": 1,
        "uptime_seconds": 1.23,
    }


async def test_health_is_unauthenticated_liveness_without_database_readiness(case):
    from src.version import VERSION

    app, _, clock = case
    clock.time = lambda: 1234.9
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": VERSION, "timestamp": 1234}
