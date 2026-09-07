"""Real PostgreSQL proof persistence with a controlled cryptographic boundary."""

import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from tests.integration.test_pilot_storage import db as database_fixture

db = database_fixture
pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")


@pytest.fixture
def generation(db, monkeypatch, sample_compliance_proof):
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("PII_ENVELOPE_MODE", "legacy-v1")
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "synthetic")
    from src.api.routes import proof

    credential = SimpleNamespace(
        revoked=False,
        sanctions_clear=True,
        issuer_did="did:web:synthetic.example",
        kyc_tier="retail",
        issued_at=int(time.time()) - 10,
        expires_at=int(time.time()) + 3600,
    )
    registry = SimpleNamespace(get=Mock(return_value=credential), get_commitment=Mock(return_value="123"))
    monkeypatch.setattr(proof, "_check_sanctions_staleness", AsyncMock())
    monkeypatch.setattr(proof.SanctionsMerkleTree, "load", Mock(return_value=SimpleNamespace(root="123")))
    monkeypatch.setattr(proof, "_poseidon_hash", AsyncMock(return_value="123"))
    monkeypatch.setattr(proof, "_load_vk", Mock(return_value={}))
    monkeypatch.setattr(
        proof._prover, "fullprove", AsyncMock(return_value=({}, sample_compliance_proof.public_signals))
    )
    request = proof.ProofGenerateRequest(
        credential_id="synthetic",
        wallet_address="0x" + "1" * 40,
        amount_usd=10,
        asset="USDC",
        destination_wallet="0x" + "2" * 40,
        jurisdiction="US",
        idempotency_key="retry",
    )

    async def generate():
        return await proof.generate_proof(
            request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db=db))), _cred_registry=registry
        )

    generate.request = request
    return generate


async def counts(db):
    result = {}
    async with db.connection() as conn:
        async with conn.cursor() as cur:
            for table in ("credentials", "proofs", "nullifiers", "idempotency_keys", "audit_entries"):
                await cur.execute(f"SELECT count(*) FROM {table}")
                result[table] = (await cur.fetchone())[0]
    return result


async def test_durable_generation_and_retry(db, generation):
    first = await generation()
    assert "compliance_proof" in first
    assert await counts(db) == dict.fromkeys(
        ("credentials", "proofs", "nullifiers", "idempotency_keys", "audit_entries"), 1
    )
    retry = await generation()
    assert retry["status"] == "already_generated"
    assert (await counts(db))["proofs"] == 1


async def test_audit_failure_rolls_back_every_record(db, generation, monkeypatch):
    from src.storage.audit import PersistentAuditLog

    with monkeypatch.context() as patch:
        patch.setattr(PersistentAuditLog, "append", AsyncMock(side_effect=RuntimeError("synthetic failure")))
        with pytest.raises(RuntimeError, match="synthetic failure"):
            await generation()
    assert all(count == 0 for count in (await counts(db)).values())
    assert "compliance_proof" in await generation()


async def test_concurrent_retries_commit_once(db, generation, monkeypatch):
    import asyncio

    from src.api.routes import proof

    barrier = asyncio.Barrier(2)
    result = proof._prover.fullprove.return_value

    async def prove(inputs):
        await barrier.wait()
        return result

    monkeypatch.setattr(proof._prover, "fullprove", prove)
    responses = await asyncio.wait_for(asyncio.gather(generation(), generation()), timeout=10)
    assert sum("compliance_proof" in response for response in responses) == 1
    assert sum(response.get("status") == "already_generated" for response in responses) == 1
    assert all(count == 1 for count in (await counts(db)).values())


async def test_duplicate_nullifier_rolls_back_new_proof(db, generation):
    from fastapi import HTTPException

    await generation()
    generation.request.idempotency_key = "different-key"
    with pytest.raises(HTTPException) as error:
        await generation()
    assert error.value.status_code == 409
    assert all(count == 1 for count in (await counts(db)).values())
