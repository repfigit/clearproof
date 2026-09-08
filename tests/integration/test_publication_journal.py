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


def observation(identity, retained, status="not-found"):
    value = dict(
        schema_version="clearproof-publication-observation-v1",
        intent_id=identity,
        transaction_hash=retained["transaction_hash"],
        phase="publish",
        anchor_number=10,
        anchor_hash="aa" * 32,
        block_tag="latest",
        minimum_confirmations=1,
        confirmations=0,
        execution="not-established",
        registry_effect="not-established",
        current_authorization="not-evaluated",
        resubmission="not-authorized",
        status=status,
    )
    if status == "confirmed-success":
        value.update(
            inclusion_number=10,
            inclusion_hash="aa" * 32,
            confirmations=1,
            execution="succeeded",
            registry_effect="statement-published-at-inclusion",
        )
    return value


async def test_publication_history_survives_restart_and_retains_reversals(db):
    from src.storage.publication_history import PublicationHistory

    journal, account, transaction, binding = await seed(db)
    identity = await journal.reserve(binding, bytes(account.sign_transaction(transaction).raw_transaction), now=1)
    retained = await journal.inspect(identity)
    history = PublicationHistory(journal)
    successful = observation(identity, retained, "confirmed-success")
    first = await history.append(identity, successful, policy_digest="11" * 32, observed_at=20)
    assert await history.append(identity, successful, policy_digest="11" * 32, observed_at=20) == first
    missing = observation(identity, retained)
    second = await history.append(identity, missing, policy_digest="11" * 32, observed_at=21)
    assert second["previous_observation_id"] == first["observation_id"] and second["sequence"] == 2
    await db.close()
    await db.connect()
    first_page = await history.page(identity, limit=1)
    second_page = await history.page(identity, after=first_page["next_after"], limit=1)
    assert first_page["items"] == [first] and second_page["items"] == [second]
    assert second_page["next_after"] is None and second_page["current_chain_state"] == "not-established"
    assert not (await journal.inspect(identity))["broadcast_claimed"]
    with pytest.raises(RecordConflict):
        await history.append(identity, successful, policy_digest="11" * 32, observed_at=19)
    other, *_ = await seed(db, "tenant-b")
    assert not (await PublicationHistory(other).page(identity))["items"]
    async with db.connection() as conn:
        rows = await (
            await conn.execute("SELECT row_to_json(o)::text FROM pilot_publication_observations o")
        ).fetchall()
        assert len(rows) == 2 and all("confirmed-success" not in row[0] for row in rows)


async def test_publication_history_rejects_substituted_transaction_and_invalid_status(db):
    from src.storage.publication_history import PublicationHistory

    journal, account, transaction, binding = await seed(db)
    identity = await journal.reserve(binding, bytes(account.sign_transaction(transaction).raw_transaction), now=1)
    history = PublicationHistory(journal)
    value = observation(identity, await journal.inspect(identity))
    for change in (
        {"transaction_hash": "00" * 32},
        {"intent_id": "00" * 32},
        {"status": "confirmed-success"},
        {"confirmations": 1},
        {"resubmission": "authorized"},
    ):
        with pytest.raises(ValueError):
            await history.append(identity, {**value, **change}, policy_digest="11" * 32, observed_at=20)
    assert not (await history.page(identity))["items"]


async def test_recovery_service_records_only_successfully_reconciled_observations(db):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from src.chain.publication_reconciliation import PublicationChainPolicy
    from src.services.publication_recovery import PublicationRecoveryService

    journal, account, transaction, binding = await seed(db)
    identity = await journal.reserve(binding, bytes(account.sign_transaction(transaction).raw_transaction), now=1)
    reconciler = SimpleNamespace(
        journal=journal,
        policy=PublicationChainPolicy(
            chain_id=binding.chain_id,
            registry=binding.registry,
            runtime_sha256=binding.runtime_sha256,
            block_tag="latest",
        ),
        reconcile=AsyncMock(side_effect=ValueError("Synthetic inconsistent RPC observation")),
    )
    service = PublicationRecoveryService(reconciler)
    with pytest.raises(ValueError):
        await service.observe(identity, now=20)
    assert not (await service.history.page(identity))["items"]
    reconciler.reconcile.side_effect = None
    reconciler.reconcile.return_value = observation(identity, await journal.inspect(identity))
    result = await service.observe(identity, now=20)
    assert result["sequence"] == 1 and result["observation"]["status"] == "not-found"

    reconciler.reconcile.return_value = {**reconciler.reconcile.return_value, "block_tag": "finalized"}
    with pytest.raises(ValueError, match="policy"):
        await service.observe(identity, now=21)
    assert len((await service.history.page(identity))["items"]) == 1


async def test_explicit_same_transaction_rebroadcast_is_bounded_and_compare_and_swap(db):
    journal, account, transaction, binding = await seed(db)
    raw = bytes(account.sign_transaction(transaction).raw_transaction)
    identity = await journal.reserve(binding, raw, now=1)
    sent = []

    async def current(_):
        pass

    async def lost(value):
        sent.append(value)
        raise TimeoutError("Synthetic response loss")

    with pytest.raises(TimeoutError):
        await journal.broadcast_once(identity, revalidate=current, send_raw=lost)
    results = await asyncio.gather(
        *(journal.rebroadcast_once(identity, expected_attempts=1, revalidate=current, send_raw=lost) for _ in range(2)),
        return_exceptions=True,
    )
    assert sum(isinstance(r, TimeoutError) for r in results) == 1
    assert sum(isinstance(r, RecordConflict) for r in results) == 1
    with pytest.raises(TimeoutError):
        await journal.rebroadcast_once(identity, expected_attempts=2, revalidate=current, send_raw=lost)
    with pytest.raises(ValueError):
        await journal.rebroadcast_once(identity, expected_attempts=3, revalidate=current, send_raw=lost)
    assert sent == [raw, raw, raw]
    await db.close()
    await db.connect()
    assert (await journal.inspect(identity))["broadcast_attempts"] == 3


@pytest.mark.parametrize("failure", [None, "known", "nonce", "runtime", "simulation", "expired", "source", "reorg"])
async def test_missing_recovery_requires_fresh_preconditions_before_claim(db, failure):
    import hashlib
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from src.chain.publication_reconciliation import PublicationChainPolicy
    from src.services.publication_recovery import PublicationRecoveryService

    journal, account, transaction, binding = await seed(db)
    runtime = b"synthetic-runtime"
    binding = binding.model_copy(update={"runtime_sha256": hashlib.sha256(runtime).hexdigest()})
    signed = account.sign_transaction(transaction)
    raw = bytes(signed.raw_transaction)
    identity = await journal.reserve(binding, raw, now=1)
    source = AsyncMock()
    with pytest.raises(TimeoutError):
        await journal.broadcast_once(identity, revalidate=source, send_raw=AsyncMock(side_effect=TimeoutError()))
    source.reset_mock()

    class Eth:
        @property
        async def chain_id(self):
            return 31337

    eth = Eth()
    block = dict(number=10, timestamp=20, hash=b"a" * 32)
    eth.get_block = AsyncMock(return_value=block)
    eth.get_code = AsyncMock(return_value=runtime)
    eth.get_transaction_count = AsyncMock(return_value=4)
    eth.call = AsyncMock(return_value=b"")
    eth.send_raw_transaction = AsyncMock(return_value=signed.hash)
    report = observation(identity, await journal.inspect(identity))
    reconciler = SimpleNamespace(
        journal=journal,
        web3=SimpleNamespace(eth=eth),
        policy=PublicationChainPolicy(
            chain_id=31337, registry=binding.registry, runtime_sha256=binding.runtime_sha256, block_tag="latest"
        ),
        reconcile=AsyncMock(return_value=report),
    )
    now = 20
    if failure == "known":
        report["status"] = "pending"
    elif failure == "nonce":
        eth.get_transaction_count.return_value = 5
    elif failure == "runtime":
        eth.get_code.return_value = b"different"
    elif failure == "simulation":
        eth.call.side_effect = ValueError("Synthetic contract rejection")
    elif failure == "expired":
        now = 100
    elif failure == "source":
        source.side_effect = ValueError("Synthetic source invalidation")
    elif failure == "reorg":
        eth.get_block.side_effect = [block, {**block, "hash": b"b" * 32}]
    service = PublicationRecoveryService(reconciler)
    if failure:
        with pytest.raises((ValueError, RecordConflict)):
            await service.rebroadcast_missing(identity, expected_attempts=1, now=now, revalidate=source)
        eth.send_raw_transaction.assert_not_awaited()
        assert (await journal.inspect(identity))["broadcast_attempts"] == 1
    else:
        assert (
            await service.rebroadcast_missing(identity, expected_attempts=1, now=now, revalidate=source)
            == bytes(signed.hash).hex()
        )
        eth.send_raw_transaction.assert_awaited_once_with(raw)
        eth.call.assert_awaited_once()
        source.assert_awaited_once_with(binding)
        assert (await journal.inspect(identity))["broadcast_attempts"] == 2


async def test_attempt_migration_preserves_existing_claims_and_unclaimed_intents(db):
    journal, account, transaction, binding = await seed(db)
    first = await journal.reserve(binding, bytes(account.sign_transaction(transaction).raw_transaction), now=1)
    second = await journal.reserve(
        binding.model_copy(update={"phase": "mirror"}),
        bytes(account.sign_transaction({**transaction, "nonce": 5}).raw_transaction),
        now=1,
    )

    async def current(_):
        pass

    async def crash(_):
        raise TimeoutError("Synthetic pre-migration claim")

    with pytest.raises(TimeoutError):
        await journal.broadcast_once(first, revalidate=current, send_raw=crash)
    before = [await journal.inspect(first), await journal.inspect(second)]
    # Reconstruct version 18 in this fixture's isolated disposable namespace.
    from src.storage.database import _SCHEMA_MIGRATIONS
    from src.storage.pilot_schema import OBSERVATION_MIGRATION

    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT max(version) FROM schema_migrations")).fetchone())[0] == len(
            _SCHEMA_MIGRATIONS
        )
        await conn.execute("ALTER TABLE pilot_publications DROP CONSTRAINT pilot_publication_attempt_bounds")
        await conn.execute("ALTER TABLE pilot_publications DROP COLUMN broadcast_attempts")
        await conn.execute(OBSERVATION_MIGRATION)
        await conn.execute("DELETE FROM schema_migrations WHERE version>=19")
    await db.close()
    await db.connect()
    assert [await journal.inspect(first), await journal.inspect(second)] == before
    assert before[0]["broadcast_attempts"] == 1 and before[1]["broadcast_attempts"] == 0
    with pytest.raises(RecordConflict):
        await journal.broadcast_once(first, revalidate=current, send_raw=crash)


async def test_history_rejects_missing_intent_and_unknown_cursor(db):
    from src.storage.publication_history import PublicationHistory

    journal, account, transaction, binding = await seed(db)
    identity = await journal.reserve(binding, bytes(account.sign_transaction(transaction).raw_transaction), now=1)
    history = PublicationHistory(journal)
    value = observation(identity, await journal.inspect(identity))
    missing = "ff" * 32
    with pytest.raises(ValueError, match="^Publication intent is unavailable$"):
        await history.append(missing, {**value, "intent_id": missing}, policy_digest="11" * 32, observed_at=20)
    await history.append(identity, value, policy_digest="11" * 32, observed_at=20)
    with pytest.raises(ValueError, match="^History cursor does not identify a retained observation$"):
        await history.page(identity, after=99)


@pytest.mark.parametrize("corruption", ["index-mismatch", "sequence-gap", "cursor-gap"])
async def test_history_rejects_index_substitution_and_authenticated_sequence_gaps(db, corruption):
    from src.storage.publication_history import PublicationHistory

    journal, account, transaction, binding = await seed(db)
    identity = await journal.reserve(binding, bytes(account.sign_transaction(transaction).raw_transaction), now=1)
    history = PublicationHistory(journal)
    first = await history.append(
        identity,
        observation(identity, await journal.inspect(identity)),
        policy_digest="11" * 32,
        observed_at=20,
    )
    async with db.connection() as conn:
        if corruption == "index-mismatch":
            # SQL metadata is not authenticated by the encrypted payload's digest.
            await conn.execute(
                "UPDATE pilot_publication_observations SET sequence=2 WHERE tenant_id=%s AND intent_id=%s",
                (journal.store.tenant_id, identity),
            )
        else:
            # Deliberately retain an authenticated but noncontiguous history row.
            # This tests semantic chain validation beyond AEAD/digest integrity.
            value = {key: value for key, value in first.items() if key != "observation_id"}
            value["sequence"] = 2
            record_id = record_digest("clearproof/publication-observation/v1", value)
            sealed = journal.cipher.seal(journal.store.tenant_id, "publication-observation", record_id, 1, value)
            await conn.execute(
                "UPDATE pilot_publication_observations SET sequence=2, observation_id=%s, key_id=%s, "
                "content_tag=%s, cipher_nonce=%s, ciphertext=%s WHERE tenant_id=%s AND intent_id=%s",
                (
                    record_id,
                    sealed["key_id"],
                    sealed["content_tag"],
                    sealed["nonce"],
                    sealed["ciphertext"],
                    journal.store.tenant_id,
                    identity,
                ),
            )
        await conn.commit()
    message = {
        "index-mismatch": "Publication history identity differs from retained evidence",
        "sequence-gap": "Publication history chain is incomplete",
        "cursor-gap": "History cursor does not identify a retained observation",
    }[corruption]
    with pytest.raises(ValueError, match=f"^{message}$"):
        await history.page(identity, after=1 if corruption == "cursor-gap" else 0)
    assert not (await journal.inspect(identity))["broadcast_claimed"]


@pytest.mark.parametrize("mutation", ["missing", "unconsumed", "expiry"])
async def test_reservation_rejects_unavailable_consumed_authority(db, mutation):
    journal, account, transaction, binding = await seed(db)
    if mutation == "missing":
        binding = binding.model_copy(update={"receipt_id": "ab" * 32})
    elif mutation == "expiry":
        binding = binding.model_copy(update={"expires_at": 101})
    else:
        async with db.connection() as conn:
            await conn.execute("DELETE FROM pilot_consumptions")
    raw = bytes(account.sign_transaction(transaction).raw_transaction)
    with pytest.raises(ValueError, match="existing consumed receipt"):
        await journal.reserve(binding, raw, now=1)
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_publications")).fetchone())[0] == 0


@pytest.mark.parametrize("identity", [None, "", "a" * 63, "A" * 64])
async def test_publication_selector_rejects_noncanonical_identity(db, identity):
    journal, _, _, _ = await seed(db)
    with pytest.raises(ValueError, match="canonical publication intent ID"):
        await journal.inspect(identity)


async def test_retry_rejects_different_authenticated_retained_value(db):
    journal, account, transaction, binding = await seed(db)
    raw = bytes(account.sign_transaction(transaction).raw_transaction)
    identity = await journal.reserve(binding, raw, now=1)
    async with journal.store.transaction() as tx:
        value = journal._open(identity, await journal._row(tx, identity))
        value["synthetic_extra"] = "different-retained-value"
        sealed = journal.cipher.seal(tx.tenant_id, "publication-intent", identity, 1, value)
        await tx._conn.execute(
            "UPDATE pilot_publications SET key_id=%s,content_tag=%s,cipher_nonce=%s,ciphertext=%s "
            "WHERE tenant_id=%s AND intent_id=%s",
            (sealed["key_id"], sealed["content_tag"], sealed["nonce"], sealed["ciphertext"], tx.tenant_id, identity),
        )
    with pytest.raises(RecordConflict, match="intent differs from retained transaction"):
        await journal.reserve(binding, raw, now=2)
    assert not (await journal.inspect(identity))["broadcast_claimed"]


@pytest.mark.parametrize(
    "field,value", [("nonce", 5), ("phase", "mirror"), ("chain_id", 1), ("sender", "0x" + "34" * 20)]
)
async def test_publication_index_must_match_encrypted_binding(db, field, value):
    from psycopg import sql

    journal, account, transaction, binding = await seed(db)
    identity = await journal.reserve(binding, bytes(account.sign_transaction(transaction).raw_transaction), now=1)
    async with db.connection() as conn:
        await conn.execute(
            sql.SQL("UPDATE pilot_publications SET {}=%s WHERE tenant_id=%s AND intent_id=%s").format(
                sql.Identifier(field)
            ),
            (value, journal.store.tenant_id, identity),
        )
    with pytest.raises(ValueError, match="Retained publication binding is inconsistent"):
        await journal.inspect(identity)


async def test_unknown_intent_does_not_revalidate_or_broadcast(db):
    from unittest.mock import AsyncMock

    journal, _, _, _ = await seed(db)
    revalidate, send_raw = AsyncMock(), AsyncMock()
    with pytest.raises(ValueError, match="Publication intent is unavailable"):
        await journal.broadcast_once("ab" * 32, revalidate=revalidate, send_raw=send_raw)
    revalidate.assert_not_awaited()
    send_raw.assert_not_awaited()


async def test_broadcast_race_rechecks_attempt_after_both_preflight_reads(db):
    from web3 import Web3

    journal, account, transaction, binding = await seed(db)
    raw = bytes(account.sign_transaction(transaction).raw_transaction)
    identity = await journal.reserve(binding, raw, now=1)
    ready = asyncio.Barrier(2)
    sent = []

    async def revalidate(value):
        assert value == binding
        # Both callers have observed attempt zero before either claims it.
        await ready.wait()

    async def send_raw(value):
        sent.append(value)
        return Web3.keccak(value)

    results = await asyncio.wait_for(
        asyncio.gather(
            *(journal.broadcast_once(identity, revalidate=revalidate, send_raw=send_raw) for _ in range(2)),
            return_exceptions=True,
        ),
        10,
    )
    assert sum(isinstance(result, RecordConflict) for result in results) == 1
    assert results.count(bytes(Web3.keccak(raw)).hex()) == 1
    assert sent == [raw]
    assert (await journal.inspect(identity))["broadcast_attempts"] == 1
