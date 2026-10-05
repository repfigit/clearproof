"""Real PostgreSQL queue limits, secrecy, ownership, recovery and fencing."""

import asyncio
import json
import os
import time
from dataclasses import replace

import pytest
from fastapi import HTTPException

from src.auth.principal import Principal
from src.storage.pilot_cipher import RecordIntegrityError
from src.storage.proof_jobs import LeaseLost, ProofJobError, ProofJobQueue, job_identifier
from tests.integration.test_pilot_storage import cipher
from tests.integration.test_pilot_storage import db as db

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")
ROLES = ("proof:generate", "policy:read", "evidence:decrypt")
PRIVATE_INPUT = {"target_id": "synthetic-target", "holder_secret": "SYNTHETIC-SECRET"}


def principal(tenant="tenant-a", actor="actor-a", roles=ROLES):
    return Principal(tenant_id=tenant, actor_id=actor, roles=roles)


@pytest.fixture
def queue(db):
    return ProofJobQueue(db, cipher())


async def enqueue(queue, key="same-key", who=None, **kwargs):
    return await queue.enqueue(
        who or principal(),
        key,
        kwargs.pop("request", PRIVATE_INPUT),
        expires_at=kwargs.pop("expires_at", int(time.time()) + 240),
        **kwargs,
    )


async def sql(db, statement, params=()):
    async with db.connection() as conn:
        cursor = await conn.execute(statement, params)
        return await cursor.fetchall() if cursor.description else None


async def test_request_result_privacy_and_reconnect(queue, db):
    job = await enqueue(queue)
    assert job.status == "queued" and job.attempts == 0
    assert "SECRET" not in repr(job) and "holder_secret" not in json.dumps(job.metadata())
    claim = await queue.claim()
    assert claim.snapshot.request == PRIVATE_INPUT and "SECRET" not in repr(claim)
    assert await queue.heartbeat(claim) == "proving"
    assert await queue.finish(claim, result={"proof": "SYNTHETIC-PRIVATE-PROOF"}) == "completed"
    await db.close()
    await db.connect()
    retained = await queue.read(principal(), job.job_id)
    assert retained.result == {"proof": "SYNTHETIC-PRIVATE-PROOF"}
    for row in await sql(db, "SELECT row_to_json(r)::text FROM proof_jobs r"):
        assert "SECRET" not in row[0] and "PRIVATE-PROOF" not in row[0]
    assert "PRIVATE-PROOF" not in repr(retained)
    with pytest.raises(ProofJobError, match="already_completed"):
        await queue.cancel(principal(), job.job_id)
    with pytest.raises(LeaseLost):
        await queue.finish(claim, result={"proof": "replacement"})


async def test_concurrent_idempotency_scope_and_conflict(queue):
    expiry = int(time.time()) + 240
    jobs = await asyncio.gather(*[enqueue(queue, expires_at=expiry) for _ in range(8)])
    assert len({job.job_id for job in jobs}) == 1
    for who, body, deadline in [
        (principal(actor="other"), PRIVATE_INPUT, expiry),
        (principal(), {**PRIVATE_INPUT, "holder_secret": "DIFFERENT"}, expiry),
        (principal(), PRIVATE_INPUT, expiry + 1),
    ]:
        with pytest.raises(ProofJobError, match="idempotency_conflict"):
            await enqueue(queue, who=who, request=body, expires_at=deadline)
    other = await enqueue(queue, who=principal("tenant-b"), expires_at=expiry)
    assert other.job_id != jobs[0].job_id
    for who in (principal("tenant-b"), principal(actor="other")):
        for operation in (queue.read, queue.cancel, queue.retry):
            with pytest.raises(ProofJobError, match="not_found"):
                await operation(who, jobs[0].job_id)


@pytest.mark.parametrize("missing", ROLES)
async def test_permission_denial_precedes_database_writes(queue, db, missing):
    who = principal(roles=tuple(role for role in ROLES if role != missing))
    for operation, args in (
        (enqueue, (queue,)),
        (queue.read, (who, "a" * 64)),
        (queue.cancel, (who, "a" * 64)),
        (queue.retry, (who, "a" * 64)),
    ):
        with pytest.raises(HTTPException) as error:
            await operation(*args, **({"who": who} if operation is enqueue else {}))
        assert error.value.status_code == 403
    assert (await sql(db, "SELECT count(*) FROM proof_jobs"))[0][0] == 0


async def test_admission_and_claim_limits_apply_across_queue_instances(queue, db):
    await queue.configure(max_concurrent=2, max_pending=4, max_tenant_pending=2)
    await enqueue(queue, "a1")
    await enqueue(queue, "a2")
    with pytest.raises(ProofJobError, match="queue_full"):
        await enqueue(queue, "a3")
    await enqueue(queue, "b1", principal("tenant-b"))
    await enqueue(queue, "b2", principal("tenant-b"))
    with pytest.raises(ProofJobError, match="queue_full"):
        await enqueue(queue, "c1", principal("tenant-c"))
    copies = [ProofJobQueue(db, cipher()) for _ in range(6)]
    claims = [c for c in await asyncio.gather(*[copy.claim() for copy in copies]) if c is not None]
    assert len(claims) == 2 and len({c.snapshot.job_id for c in claims}) == 2
    with pytest.raises(ProofJobError, match="active_workers"):
        await queue.configure(max_concurrent=1, max_pending=4, max_tenant_pending=2)
    assert await queue.cancel(claims[0].snapshot.principal, claims[0].snapshot.job_id) == "cancelling"
    assert await queue.claim() is None  # Cancellation retains the active slot.
    assert await queue.heartbeat(claims[0]) == "cancelling"
    assert await queue.finish(claims[0], error="worker_interrupted") == "cancelled"
    assert await queue.claim() is not None


async def test_empty_queue_and_queued_cancellation(queue):
    assert await queue.claim() is None
    job = await enqueue(queue)
    assert await queue.retry(principal(), job.job_id) == "queued"
    assert await queue.cancel(principal(), job.job_id) == "cancelled"
    assert await queue.cancel(principal(), job.job_id) == "cancelled"
    assert await queue.claim() is None
    with pytest.raises(ProofJobError, match="retry_unavailable"):
        await queue.retry(principal(), job.job_id)


async def test_expired_lease_is_fenced_and_recovered(queue, db):
    job = await enqueue(queue)
    old = await queue.claim()
    assert await queue.retry(principal(), job.job_id) == "proving"
    with pytest.raises(LeaseLost):
        await queue.heartbeat(replace(old, token="f" * 64))
    await sql(db, "UPDATE proof_jobs SET lease_expires_at=0")
    new = await queue.claim()
    assert new.snapshot.job_id == job.job_id and new.snapshot.attempts == 2 and new.token != old.token
    with pytest.raises(LeaseLost):
        await queue.finish(old, result={"proof": "stale"})
    with pytest.raises(LeaseLost):
        await queue.heartbeat(old)
    await queue.finish(new, error="prover_failed", retryable=True)
    assert await queue.claim() is None  # Backoff has not elapsed.
    await sql(db, "UPDATE proof_jobs SET available_at=0")
    third = await queue.claim()
    assert third.snapshot.attempts == 3
    assert await queue.finish(third, error="prover_failed", retryable=True) == "failed"
    with pytest.raises(ProofJobError, match="retry_unavailable"):
        await queue.retry(principal(), job.job_id)


async def test_manual_retry_is_bounded_and_cannot_bypass_admission(queue, db):
    await queue.configure(max_concurrent=1, max_pending=1, max_tenant_pending=1)
    job = await enqueue(queue, "first")
    claim = await queue.claim()
    assert await queue.finish(claim, error="current_state_rejected") == "failed"
    other = await enqueue(queue, "other")
    with pytest.raises(ProofJobError, match="queue_full"):
        await queue.retry(principal(), job.job_id)
    await queue.cancel(principal(), other.job_id)
    assert await queue.retry(principal(), job.job_id) == "queued"
    claim = await queue.claim()
    assert await queue.finish(claim, error="configuration_changed") == "failed"
    assert (await queue.read(principal(), job.job_id)).attempts == 2


async def test_expiry_and_lease_cleanup_never_returns_expired_success(queue, db):
    job = await enqueue(queue)
    claim = await queue.claim()
    await sql(
        db, "UPDATE proof_jobs SET expires_at=created_at-1,created_at=created_at-299,retain_until=retain_until-299"
    )
    assert await queue.heartbeat(claim) == "job_expired"
    assert await queue.finish(claim, result={"proof": "too-late"}) == "failed"
    assert (await queue.read(principal(), job.job_id)).last_error == "job_expired"
    with pytest.raises(ProofJobError, match="retry_unavailable"):
        await queue.retry(principal(), job.job_id)
    await enqueue(queue, "queued-expiry")
    await sql(db, "UPDATE proof_jobs SET created_at=0,expires_at=1,retain_until=86400 WHERE status='queued'")
    assert await queue.claim() is None
    # Rows past the fixed retention horizon are purged by enqueue/claim maintenance.
    assert (await sql(db, "SELECT count(*) FROM proof_jobs WHERE created_at=0"))[0][0] == 0


@pytest.mark.parametrize("status", ["proving", "cancelling"])
async def test_dead_worker_recovery_respects_cancellation_and_attempt_limit(queue, db, status):
    job = await enqueue(queue)
    claim = await queue.claim()
    if status == "cancelling":
        await queue.cancel(principal(), job.job_id)
    await sql(db, "UPDATE proof_jobs SET attempts=3,lease_expires_at=0")
    assert await queue.claim() is None
    retained = await queue.read(principal(), job.job_id)
    assert retained.status == ("cancelled" if status == "cancelling" else "failed")
    with pytest.raises(LeaseLost):
        await queue.finish(claim, error="worker_interrupted")


async def test_key_rotation_and_ciphertext_tampering(queue, db):
    job = await enqueue(queue)
    rotated = ProofJobQueue(db, cipher(key=b"b" * 32, old=b"a" * 32))
    claim = await rotated.claim()
    await rotated.finish(claim, result={"proof": "retained"})
    assert (await rotated.read(principal(), job.job_id)).result == {"proof": "retained"}
    with pytest.raises(RecordIntegrityError):
        await ProofJobQueue(db, cipher(key=b"b" * 32)).read(principal(), job.job_id)
    await sql(db, "UPDATE proof_jobs SET request_ciphertext=decode('00','hex') || substring(request_ciphertext from 2)")
    with pytest.raises(RecordIntegrityError):
        await rotated.read(principal(), job.job_id)


@pytest.mark.parametrize("bad", [None, [], {"oversized": "x" * 17000}, {"float": 1.5}])
async def test_invalid_requests_reject_before_storage(queue, bad):
    with pytest.raises(ProofJobError, match="invalid_job_request"):
        await enqueue(queue, request=bad)


@pytest.mark.parametrize("offset", [-1, 0, 301])
async def test_invalid_expiry_rejects(queue, offset):
    with pytest.raises(ProofJobError, match="invalid_job_expiry"):
        await enqueue(queue, expires_at=int(time.time()) + offset)


@pytest.mark.parametrize("bad", [None, "", "a" * 63, "g" * 64])
def test_invalid_identifiers_reject(bad):
    with pytest.raises(ProofJobError, match="invalid_job_id"):
        job_identifier(bad)


@pytest.mark.parametrize("limits", [(True, 2, 2), (0, 2, 2), (5, 2, 2), (1, 1025, 2), (1, 2, 65)])
async def test_invalid_limits_reject(queue, limits):
    with pytest.raises(ProofJobError, match="invalid_queue_limit"):
        await queue.configure(max_concurrent=limits[0], max_pending=limits[1], max_tenant_pending=limits[2])


async def test_invalid_completions_cannot_update_a_lease(queue):
    await enqueue(queue)
    claim = await queue.claim()
    for kwargs in (
        {},
        {"result": {}, "error": "prover_failed"},
        {"error": "PRIVATE-DETAIL"},
        {"result": []},
        {"result": {"size": "x" * 17000}},
        {"result": {"size": ["x" * 4000] * 5}},
        {"result": {}, "retryable": "false"},
    ):
        with pytest.raises(ProofJobError):
            await queue.finish(claim, **kwargs)
    assert await queue.heartbeat(claim) == "proving"


@pytest.mark.parametrize("attack", ["scope", "input", "missing", "principal"])
async def test_authenticated_but_invalid_stored_payload_scope_is_rejected(queue, db, attack):
    job = await enqueue(queue)
    value = {"principal": principal().model_dump(mode="json"), "input": PRIVATE_INPUT}
    if attack == "scope":
        value["principal"]["tenant_id"] = "other-tenant"
    elif attack == "input":
        value["input"] = []
    elif attack == "missing":
        del value["principal"]
    else:
        value["principal"]["roles"] = ["unknown-role"]
    sealed = cipher().seal("tenant-a", "proof-job-request", job.job_id, 1, value)
    await sql(
        db,
        """UPDATE proof_jobs SET request_key_id=%s,request_content_tag=%s,
        request_nonce=%s,request_ciphertext=%s""",
        (sealed["key_id"], sealed["content_tag"], sealed["nonce"], sealed["ciphertext"]),
    )
    with pytest.raises(RecordIntegrityError, match="scope is inconsistent"):
        await queue.read(principal(), job.job_id)


async def test_corrupt_job_is_quarantined_without_poisoning_other_tenants(queue, db):
    job = await enqueue(queue)
    await sql(db, "UPDATE proof_jobs SET request_nonce=decode(repeat('ff',12),'hex')")
    assert await queue.claim() is None
    retained = await queue.read(principal(), job.job_id)
    assert retained.status == "failed" and retained.last_error == "stored_input_rejected"
    assert retained.request == {} and retained.result is None
    healthy = await enqueue(queue, "healthy", who=principal("tenant-b"))
    assert (await queue.claim()).snapshot.job_id == healthy.job_id
