"""Enrolled synthetic holder -> durable queue -> real proof -> fresh retrieval."""

import os
import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.prover.proof_job_worker import ProofJobWorker
from src.services.enrollment import EnrollmentService, RevocationRequest
from src.services.proof_jobs import GenerationBody
from tests.integration.pilot_job_setup import provision
from tests.integration.test_pilot_storage import cipher
from tests.integration.test_pilot_storage import db as db

pytestmark = pytest.mark.skipif(
    not os.getenv("DATABASE_URL") or not os.getenv("CLEARPROOF_PILOT_TEST_ARTIFACTS"),
    reason="requires real PostgreSQL and an explicit unapproved pilot artifact bundle",
)


def body(credential, key="real-job"):
    return GenerationBody(
        target_id="synthetic-target",
        credential_id=credential.credential_nonce,
        holder_secret="123456",
        idempotency_key=key,
    )


async def test_actual_job_survives_reconnect_and_returns_only_current_proof(db):
    jobs, who, operator, credential = await provision(db)
    admitted = await jobs.enqueue(who, body(credential))
    assert (await jobs.enqueue(who, body(credential))).job_id == admitted.job_id
    await db.close()
    await db.connect()
    assert await ProofJobWorker(jobs).run_once()
    response = await jobs.read(who, admitted.job_id)
    assert response["status"] == "completed" and response["result_available"]
    assert not response["authorization_consumed"]
    result = response["result"]
    verifier = jobs.targets[(who.tenant_id, "synthetic-target")].prover.verifier
    assert (
        await verifier.inspect(
            result["proof_json"].encode(), result["public_signals"], expected_signals=result["public_signals"]
        )
    ).cryptographic_valid
    target = jobs.targets[(who.tenant_id, "synthetic-target")]
    altered = list(result["public_signals"])
    altered[0] = str(int(altered[0]) + 1)
    with pytest.raises(ValueError, match="differs from current statement"):
        async with jobs.preparation(who, target).current_result(
            credential.credential_nonce, altered, now=int(time.time())
        ):
            pytest.fail("Tampered statement escaped the freshness guard")
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT row_to_json(r)::text FROM proof_jobs r")).fetchall()
    assert all('"holder_secret"' not in row[0] and '"pi_a"' not in row[0] for row in rows)
    target = jobs.targets[(who.tenant_id, "synthetic-target")]
    pins = target.configuration.root_pins
    await EnrollmentService(
        db, cipher(), operator, chain_id=pins.chain_id, registry_address=pins.registry_address
    ).revoke(
        RevocationRequest(
            credential_id=credential.credential_nonce, reason_code="synthetic-test", idempotency_key="revoke-after-job"
        ),
        now=int(time.time()),
    )
    stale = await jobs.read(who, admitted.job_id)
    assert stale["status"] == "completed" and not stale["result_available"]
    assert stale["result_error"] == "current_state_rejected" and "result" not in stale
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("src.services.proof_jobs.time.time", lambda: admitted.expires_at)
        expired = await jobs.read(who, admitted.job_id)
    assert expired["result_error"] == "job_expired" and "result" not in expired


async def test_target_replacement_rejects_queued_statement_without_proving(db):
    jobs, who, _, credential = await provision(db)
    job = await jobs.enqueue(who, body(credential))
    key = (who.tenant_id, "synthetic-target")
    original = jobs.targets[key]
    changed = original.configuration.context.model_copy(
        update={"evaluated_at": original.configuration.context.evaluated_at + 1}
    )
    jobs.targets[key] = replace(original, configuration=replace(original.configuration, context=changed))
    assert await ProofJobWorker(jobs).run_once()
    result = await jobs.read(who, job.job_id)
    assert result["status"] == "failed" and result["last_error"] == "configuration_changed"
    assert "result" not in result


@pytest.mark.parametrize("mutation", ["revocation", "root", "target"])
async def test_state_changes_during_actual_proving_discard_result(db, monkeypatch, mutation):
    from src.protocol.root_snapshot import RootSnapshot, sign_root
    from src.prover.pilot_prover import PilotProver
    from src.services.root_publication import RootPublicationService

    jobs, who, operator, credential = await provision(db)
    key = (who.tenant_id, "synthetic-target")
    target = jobs.targets[key]
    original = PilotProver.prove

    async def prove_then_change(prover, *args, **kwargs):
        result = await original(prover, *args, **kwargs)
        now = int(time.time())
        if mutation == "revocation":
            pins = target.configuration.root_pins
            await EnrollmentService(
                db, cipher(), operator, chain_id=pins.chain_id, registry_address=pins.registry_address
            ).revoke(
                RevocationRequest(
                    credential_id=credential.credential_nonce,
                    reason_code="synthetic-test",
                    idempotency_key="in-flight-revoke",
                ),
                now=now,
            )
        elif mutation == "root":
            prior = target.configuration.sanctions.snapshot
            successor = RootSnapshot.model_validate(
                {
                    **prior.model_dump(),
                    "revision": prior.revision + 1,
                    "previous_digest": prior.digest,
                    "issued_at": now,
                }
            )
            await RootPublicationService(db, cipher(), operator, target.configuration.root_trust).publish(
                sign_root(successor, Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)),
                idempotency_key="in-flight-root",
                now=now,
            )
        else:
            changed = target.configuration.context.model_copy(update={"evaluated_at": now})
            jobs.targets[key] = replace(target, configuration=replace(target.configuration, context=changed))
        return result

    monkeypatch.setattr(PilotProver, "prove", prove_then_change)
    job = await jobs.enqueue(who, body(credential))
    assert await ProofJobWorker(jobs).run_once()
    retained = await jobs.read(who, job.job_id)
    assert retained["status"] == "failed" and "result" not in retained
    assert retained["last_error"] == ("configuration_changed" if mutation == "target" else "current_state_rejected")
