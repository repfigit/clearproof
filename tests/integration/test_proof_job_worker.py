"""Real queue fencing around worker failure, cancellation and cleanup."""

import asyncio
import os
from types import SimpleNamespace

import pytest

from src.prover.pilot_prover import PilotProvingError
from src.prover.proof_job_worker import ProofJobWorker
from src.storage.proof_jobs import ProofJobError
from tests.integration.test_proof_job_queue import db as db
from tests.integration.test_proof_job_queue import enqueue, principal
from tests.integration.test_proof_job_queue import queue as queue

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")


def worker(queue, execute):
    return ProofJobWorker(SimpleNamespace(queue=queue, execute=execute))


async def test_successful_job_handoff_and_empty_worker(queue):
    job = await enqueue(queue)

    async def execute(claim):
        return await queue.finish(claim, result={"proof": "synthetic"})

    target = worker(queue, execute)
    assert await target.run_once()
    assert (await queue.read(principal(), job.job_id)).status == "completed"
    assert not await target.run_once()


@pytest.mark.parametrize(
    "failure,error,retry",
    [
        (PilotProvingError("private-detail"), "prover_failed", True),
        (ProofJobError("configuration_changed"), "configuration_changed", False),
        (ProofJobError("proving_target_not_found"), "current_state_rejected", False),
        (ValueError("SYNTHETIC-PRIVATE-DETAIL"), "current_state_rejected", False),
        (RuntimeError("SYNTHETIC-PRIVATE-DETAIL"), "worker_interrupted", True),
        (TimeoutError("SYNTHETIC-PRIVATE-DETAIL"), "worker_interrupted", True),
    ],
)
async def test_failures_are_sanitized_and_only_transient_work_retries(queue, failure, error, retry):
    job = await enqueue(queue)

    async def execute(claim):
        raise failure

    assert await worker(queue, execute).run_once()
    retained = await queue.read(principal(), job.job_id)
    assert retained.last_error == error and retained.result is None
    assert retained.status == ("queued" if retry else "failed")
    assert "PRIVATE" not in str(retained.metadata())


@pytest.mark.parametrize("state", ["cancelling", "job_expired", "lease-failure"])
async def test_watchdog_reaps_before_fenced_acknowledgement(queue, monkeypatch, state):
    job = await enqueue(queue)
    started, cleaned = asyncio.Event(), asyncio.Event()

    async def execute(claim):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            cleaned.set()

    target = worker(queue, execute)

    async def watch(claim):
        await started.wait()
        if state == "cancelling":
            assert await queue.cancel(principal(), job.job_id) == "cancelling"
        elif state == "lease-failure":
            raise RuntimeError("PRIVATE-DB-ERROR")
        return state

    original = queue.finish

    async def finish(*args, **kwargs):
        assert cleaned.is_set()
        return await original(*args, **kwargs)

    monkeypatch.setattr(target, "_watch", watch)
    monkeypatch.setattr(queue, "finish", finish)
    assert await target.run_once()
    retained = await queue.read(principal(), job.job_id)
    assert retained.status == {"cancelling": "cancelled", "job_expired": "failed", "lease-failure": "queued"}[state]


async def test_repeated_worker_shutdown_waits_for_cleanup_before_release(queue, monkeypatch):
    job = await enqueue(queue)
    started, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def execute(claim):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()

    target = worker(queue, execute)
    task = asyncio.create_task(target.run_once())
    await started.wait()
    task.cancel()
    await cleaning.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    assert await queue.claim() is None
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await queue.read(principal(), job.job_id)).status == "queued"


async def test_failed_finish_is_not_repeated_with_an_uncertain_commit(queue, monkeypatch):
    job = await enqueue(queue)

    async def execute(claim):
        raise PilotProvingError("private-detail")

    original = queue.finish
    calls = []

    async def finish(*args, **kwargs):
        calls.append(1)
        await original(*args, **kwargs)
        raise TimeoutError("connection lost after commit")

    monkeypatch.setattr(queue, "finish", finish)
    assert await worker(queue, execute).run_once()
    assert calls == [1]
    assert (await queue.read(principal(), job.job_id)).status == "queued"


async def test_poll_loop_stops_and_handles_claim_observation_timeout(queue, monkeypatch):
    stop = asyncio.Event()
    calls = []
    target = worker(queue, None)

    async def run_once():
        calls.append(1)
        if len(calls) == 1:
            raise TimeoutError
        stop.set()
        return True

    monkeypatch.setattr(target, "run_once", run_once)
    await target.run(stop)
    assert len(calls) == 2


async def test_actual_heartbeat_detects_requested_cancellation(queue):
    job = await enqueue(queue)
    claim = await queue.claim()
    await queue.cancel(principal(), job.job_id)
    assert await worker(queue, None)._watch(claim) == "cancelling"


async def test_watchdog_refreshes_lease_until_cancellation(queue):
    job = await enqueue(queue)
    claim = await queue.claim()
    target = worker(queue, None)
    watch = asyncio.create_task(target._watch(claim))
    await asyncio.sleep(0.02)
    await queue.cancel(principal(), job.job_id)
    assert await asyncio.wait_for(watch, 5) == "cancelling"


async def test_execution_deadline_timeout_does_not_publish_result(queue):
    from dataclasses import replace

    job = await enqueue(queue)
    claim = await queue.claim()

    async def execute(claim):
        await asyncio.Event().wait()

    expired = replace(claim, snapshot=replace(claim.snapshot, expires_at=0))
    with pytest.raises(TimeoutError):
        await worker(queue, execute)._execute(expired)
    assert (await queue.read(principal(), job.job_id)).result is None
