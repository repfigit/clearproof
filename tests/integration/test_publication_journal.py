"""Real PostgreSQL publication reservations, restart and uncertain-send behavior."""

import asyncio
import os

import pytest

from src.protocol.canonical import record_digest
from src.storage.pilot import RecordConflict
from src.storage.publication_journal import PublicationJournal
from tests.integration import test_pilot_storage as fixtures
from tests.integration.test_pilot_storage import cipher, store
from tests.unit.test_publication_journal import transaction_case

db = fixtures.db

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")


async def seed(database, tenant="tenant-a"):
    target = store(database, tenant)
    proof, nullifier = "01" * 32, "02" * 32
    receipt = dict(tenant_id=tenant, proof_id=proof, nullifier=nullifier, outcome="ALLOW", expires_at=100)
    receipt_id = record_digest("clearproof/local-authorization/v1", receipt)
    async with target.transaction() as tx:
        await tx.put("proof", proof, {"synthetic_storage_fixture": True})
        await tx.put("receipt", receipt_id, receipt)
        await tx.consume(nullifier, proof)
    account, transaction, binding = transaction_case()
    binding = binding.model_copy(update={"receipt_id": receipt_id})
    return PublicationJournal(database, cipher(), target._principal), account, transaction, binding


async def test_reservation_restart_encryption_and_global_nonce_exclusion(db):
    journal, account, transaction, binding = await seed(db)
    raw = bytes(account.sign_transaction(transaction).raw_transaction)
    identity = await journal.reserve(binding, raw, now=1)
    assert await journal.reserve(binding, raw, now=2) == identity
    before = await journal.inspect(identity)
    assert not before["broadcast_claimed"] and before["chain_outcome"] == "not-established"
    await db.close()
    await db.connect()
    assert await journal.inspect(identity) == before
    other, _, _, other_binding = await seed(db, "tenant-b")
    assert await other.inspect(identity) is None
    with pytest.raises(RecordConflict):
        await other.reserve(other_binding, raw, now=2)
    changed = bytes(account.sign_transaction({**transaction, "nonce": 5}).raw_transaction)
    with pytest.raises(RecordConflict):
        await journal.reserve(binding, changed, now=2)
    with pytest.raises(ValueError):
        await journal.reserve(binding, raw, now=100)
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT row_to_json(p)::text FROM pilot_publications p")).fetchall()
        assert len(rows) == 1 and raw.hex() not in rows[0][0] and "synthetic-calldata" not in rows[0][0]


async def test_competing_broadcast_and_lost_response_do_not_send_again(db):
    journal, account, transaction, binding = await seed(db)
    raw = bytes(account.sign_transaction(transaction).raw_transaction)
    identity = await journal.reserve(binding, raw, now=1)
    calls = []

    async def revalidate(value):
        assert value == binding

    async def lost_response(value):
        calls.append(value)
        raise TimeoutError("Synthetic response lost after send")

    results = await asyncio.gather(
        *(journal.broadcast_once(identity, revalidate=revalidate, send_raw=lost_response) for _ in range(2)),
        return_exceptions=True,
    )
    assert sum(isinstance(r, TimeoutError) for r in results) == 1
    assert sum(isinstance(r, RecordConflict) for r in results) == 1
    assert calls == [raw]
    await db.close()
    await db.connect()
    recovered = PublicationJournal(db, cipher(), journal.principal)
    assert (await recovered.inspect(identity))["broadcast_claimed"]
    with pytest.raises(RecordConflict):
        await recovered.broadcast_once(identity, revalidate=revalidate, send_raw=lost_response)
    assert calls == [raw]


async def test_failed_revalidation_leaves_intent_unclaimed_and_wrong_rpc_hash_stays_uncertain(db):
    journal, account, transaction, binding = await seed(db)
    raw = bytes(account.sign_transaction(transaction).raw_transaction)
    identity = await journal.reserve(binding, raw, now=1)
    calls = []

    async def stale(_):
        raise ValueError("Synthetic source changed")

    async def current(_):
        pass

    async def wrong_hash(value):
        calls.append(value)
        return bytes(32)

    with pytest.raises(ValueError, match="source"):
        await journal.broadcast_once(identity, revalidate=stale, send_raw=wrong_hash)
    assert not calls and not (await journal.inspect(identity))["broadcast_claimed"]
    with pytest.raises(ValueError, match="RPC"):
        await journal.broadcast_once(identity, revalidate=current, send_raw=wrong_hash)
    assert calls == [raw] and (await journal.inspect(identity))["broadcast_claimed"]
