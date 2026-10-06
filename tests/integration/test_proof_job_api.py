"""Authenticated HTTP admission and operations against an owned real queue.

These transport tests use a synthetic target descriptor, not a proving backend.
Actual cryptographic handoff is covered by test_proof_job_acceptance.py.
"""

import json
import os
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from src.api.routes import proof_jobs as route
from src.auth.principal import Principal, TenantPrincipalDependency
from src.services.proof_inspection import CurrentStatementConfiguration
from src.services.proof_jobs import ProvingTarget
from src.storage.keyring import KeyRing, KeyVersion
from src.storage.proof_jobs import ProofJobQueue
from tests.integration.test_pilot_storage import cipher
from tests.integration.test_pilot_storage import db as db
from tests.unit.test_pilot_compliance import synthetic_case

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")
ROLES = ("proof:generate", "policy:read", "evidence:decrypt")


@pytest.fixture
async def api(db, monkeypatch):
    _, _, inputs = synthetic_case(with_trust=True, evaluated_at=int(time.time()))
    credential = inputs.pop("credential")
    inputs.pop("now")
    from src.registry.pilot_sanctions import PilotSanctionsTree

    fake = SimpleNamespace(
        verifier=SimpleNamespace(
            artifacts=SimpleNamespace(manifest=SimpleNamespace(digest=inputs["context"].artifact_manifest_digest)),
            bundle=b"SYNTHETIC-TRANSPORT-TARGET",
        )
    )
    app = FastAPI()
    app.include_router(route.router)
    app.state.db = db
    who = Principal(tenant_id=credential.tenant_id, actor_id="job-holder", roles=ROLES)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: who
    app.state.pilot_proving_targets = {
        (who.tenant_id, "synthetic-target"): ProvingTarget(
            CurrentStatementConfiguration(**inputs), fake, PilotSanctionsTree([])
        )
    }
    monkeypatch.setattr(route, "load_keyring", lambda: KeyRing(KeyVersion("current", b"a" * 32, 0)))
    body = {
        "target_id": "synthetic-target",
        "credential_id": credential.credential_nonce,
        "holder_secret": "123456",
        "idempotency_key": "synthetic-job",
    }
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://synthetic.local") as client:
        yield client, app, who, body, ProofJobQueue(db, cipher())


async def test_admission_read_cancel_retry_and_opaque_ownership(api):
    client, app, who, body, queue = api
    response = await client.post("/pilot/proof/jobs", json=body)
    assert response.status_code == 202 and response.headers["Cache-Control"] == "no-store"
    job = response.json()["job_id"]
    assert response.headers["Location"] == f"/pilot/proof/jobs/{job}"
    assert "holder_secret" not in response.text
    assert (await client.post("/pilot/proof/jobs", json=body)).json()["job_id"] == job
    assert (await client.get(f"/pilot/proof/jobs/{job}")).json()["status"] == "queued"
    changed = await client.post("/pilot/proof/jobs", json={**body, "holder_secret": "654321"})
    assert changed.status_code == 409
    for scope in ({"tenant_id": "other-tenant"}, {"actor_id": "other-actor"}):
        stranger = Principal.model_validate({**who.model_dump(), **scope})
        app.dependency_overrides[TenantPrincipalDependency] = lambda: stranger
        for method, path in ((client.get, ""), (client.post, "/cancel"), (client.post, "/retry")):
            assert (await method(f"/pilot/proof/jobs/{job}{path}")).status_code == 404
    app.dependency_overrides[TenantPrincipalDependency] = lambda: who
    assert (await client.post(f"/pilot/proof/jobs/{job}/retry")).status_code == 202
    assert (await client.post(f"/pilot/proof/jobs/{job}/cancel")).json()["status"] == "cancelled"
    assert (await client.post(f"/pilot/proof/jobs/{job}/retry")).status_code == 409
    assert await queue.claim() is None


async def test_admission_accepts_api_clock_ahead_of_database_without_extending_deadline(api, monkeypatch):
    client, app, who, body, _ = api
    target = app.state.pilot_proving_targets[(who.tenant_id, body["target_id"])]
    database_now = target.deadline - 301

    async def database_clock(self, cur):
        return database_now

    monkeypatch.setattr(ProofJobQueue, "_clock", database_clock)
    response = await client.post("/pilot/proof/jobs", json=body)
    assert response.status_code == 202
    job = response.json()
    assert job["created_at"] == database_now
    assert job["expires_at"] == database_now + 300 < target.deadline
    database_now += 2
    repeated = await client.post("/pilot/proof/jobs", json=body)
    assert repeated.status_code == 202
    assert repeated.json()["job_id"] == job["job_id"]
    assert repeated.json()["expires_at"] == job["expires_at"]


async def test_running_cancellation_acknowledgement_and_completion_conflicts(api):
    client, _, _, body, queue = api
    job = (await client.post("/pilot/proof/jobs", json=body)).json()["job_id"]
    claim = await queue.claim()
    cancel = await client.post(f"/pilot/proof/jobs/{job}/cancel")
    assert cancel.status_code == 202 and cancel.json()["status"] == "cancelling"
    await queue.finish(claim, error="worker_interrupted")
    assert (await client.get(f"/pilot/proof/jobs/{job}")).json()["status"] == "cancelled"
    other = (await client.post("/pilot/proof/jobs", json={**body, "idempotency_key": "second"})).json()["job_id"]
    await queue.finish(await queue.claim(), result={"synthetic": True})
    assert (await client.post(f"/pilot/proof/jobs/{other}/cancel")).status_code == 409
    assert (await client.post(f"/pilot/proof/jobs/{other}/retry")).status_code == 409
    # Deliberately malformed trusted-worker output does not escape via HTTP.
    result = (await client.get(f"/pilot/proof/jobs/{other}")).json()
    assert not result["result_available"] and "result" not in result


@pytest.mark.parametrize("missing", ROLES)
async def test_role_denial_precedes_even_malformed_private_upload(api, missing):
    client, app, who, _, _ = api
    app.dependency_overrides[TenantPrincipalDependency] = lambda: Principal.model_validate(
        {**who.model_dump(), "roles": tuple(role for role in ROLES if role != missing)}
    )
    response = await client.post("/pilot/proof/jobs", content=b"PRIVATE-MALFORMED" * 300)
    assert response.status_code == 403 and "PRIVATE" not in response.text


@pytest.mark.parametrize("attack", ["extra", "zero", "out-of-field", "duplicate", "bad-json", "oversize"])
async def test_input_is_bounded_and_never_echoed(api, attack):
    client, _, _, body, _ = api
    if attack == "extra":
        payload = json.dumps({**body, "executable": "PRIVATE-ATTACK"})
    elif attack in ("zero", "out-of-field"):
        payload = json.dumps({**body, "holder_secret": "0" if attack == "zero" else str(2**255)})
    elif attack == "duplicate":
        payload = json.dumps(body)[:-1] + ',"holder_secret":"PRIVATE-ATTACK"}'
    else:
        payload = "PRIVATE-ATTACK" * (300 if attack == "oversize" else 1)
    response = await client.post("/pilot/proof/jobs", content=payload)
    assert response.status_code == (413 if attack == "oversize" else 422)
    assert "PRIVATE-ATTACK" not in response.text


async def test_queue_backpressure_and_configuration_errors(api):
    client, app, _, body, queue = api
    await queue.configure(max_concurrent=1, max_pending=1, max_tenant_pending=1)
    assert (await client.post("/pilot/proof/jobs", json=body)).status_code == 202
    full = await client.post("/pilot/proof/jobs", json={**body, "idempotency_key": "second"})
    assert full.status_code == 429 and full.headers["Retry-After"] == "5"
    assert (await client.post("/pilot/proof/jobs", json={**body, "target_id": "missing"})).status_code == 404
    app.state.pilot_proving_targets = None
    assert (await client.post("/pilot/proof/jobs", json=body)).status_code == 503
    app.state.db = None
    assert (await client.get("/pilot/proof/jobs/" + "a" * 64)).status_code == 503


async def test_operation_payloads_and_query_overrides_are_rejected(api):
    client, _, _, body, _ = api
    job = (await client.post("/pilot/proof/jobs", json=body)).json()["job_id"]
    assert (await client.get(f"/pilot/proof/jobs/{job}?tenant_id=other")).status_code == 422
    for operation in ("cancel", "retry"):
        assert (await client.post(f"/pilot/proof/jobs/{job}/{operation}", content=b"1")).status_code == 422
    assert (await client.get("/pilot/proof/jobs/invalid")).status_code == 422


async def test_invalid_operator_targets_fail_without_echoing_configuration(api):
    from dataclasses import replace

    client, app, who, body, _ = api
    key = (who.tenant_id, "synthetic-target")
    original = app.state.pilot_proving_targets[key]
    for invalid in (
        object(),
        replace(
            original,
            configuration=replace(
                original.configuration, context=original.configuration.context.model_copy(update={"tenant_id": "other"})
            ),
        ),
    ):
        app.state.pilot_proving_targets[key] = invalid
        response = await client.post("/pilot/proof/jobs", json=body)
        assert response.status_code == 503 and "holder_secret" not in response.text


async def test_corrupt_retained_ciphertext_is_not_exposed_or_replaced(api):
    client, _, _, body, queue = api
    job = (await client.post("/pilot/proof/jobs", json=body)).json()["job_id"]
    async with queue._db.connection() as conn:
        await conn.execute("UPDATE proof_jobs SET request_ciphertext=%s", (b"SYNTHETIC-BAD-CIPHERTEXT" * 2,))
    assert (await client.get(f"/pilot/proof/jobs/{job}")).status_code == 503
    assert (await client.post("/pilot/proof/jobs", json=body)).status_code == 503


@pytest.mark.parametrize("operation", ["enqueue", "cancel", "retry"])
async def test_database_and_operator_failures_have_stable_503_diagnostics(api, monkeypatch, operation):
    from psycopg import OperationalError

    client, _, _, body, _ = api

    async def failed(*args, **kwargs):
        raise OperationalError("SYNTHETIC-PRIVATE-PROVIDER-DETAIL")

    if operation == "enqueue":
        monkeypatch.setattr(route.ProofJobService, "enqueue", failed)
        response = await client.post("/pilot/proof/jobs", json=body)
    else:
        monkeypatch.setattr(ProofJobQueue, operation, failed)
        response = await client.post("/pilot/proof/jobs/" + "a" * 64 + "/" + operation)
    assert response.status_code == 503 and "PRIVATE" not in response.text


async def test_authentication_is_required_before_job_lookup(api):
    client, app, _, _, _ = api
    app.dependency_overrides.clear()
    response = await client.get("/pilot/proof/jobs/" + "a" * 64)
    assert response.status_code == 401


async def test_missing_encryption_keyring_is_operator_failure(api, monkeypatch):
    client, _, _, body, _ = api

    def failed():
        raise RuntimeError("PRIVATE-KEYRING-DETAIL")

    monkeypatch.setattr(route, "load_keyring", failed)
    response = await client.post("/pilot/proof/jobs", json=body)
    assert response.status_code == 503 and "PRIVATE" not in response.text
