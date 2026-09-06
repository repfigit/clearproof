"""Exercise proof persistence and upgrades against an isolated PostgreSQL schema."""

from __future__ import annotations

import asyncio
import os
import uuid

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb

from src.storage import database as database_module
from src.storage.database import Database
from src.storage.models import StoredNullifier, StoredProof
from src.storage.proofs import ProofStore
from src.storage.signals import SCALAR_FIELD

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires isolated PostgreSQL via DATABASE_URL")


@pytest.fixture
async def storage_db(monkeypatch):
    admin_url = os.environ["DATABASE_URL"]
    schema = "proof_test_" + uuid.uuid4().hex
    async with await psycopg.AsyncConnection.connect(admin_url) as conn:
        await conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    monkeypatch.setenv("DATABASE_URL", make_conninfo(admin_url, options=f"-c search_path={schema}"))
    db = Database(pool_min=1, pool_max=2)
    try:
        yield db
    finally:
        await db.close()
        async with await psycopg.AsyncConnection.connect(admin_url) as conn:
            await conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture
def stored_proof(sample_compliance_proof):
    return StoredProof.model_validate(sample_compliance_proof.model_dump())


async def test_round_trip_reconnect_and_transfer_lookup(storage_db, stored_proof):
    await storage_db.connect()
    store = ProofStore(storage_db)
    await store.store(stored_proof)
    assert await store.get_by_id(stored_proof.proof_id) == stored_proof
    assert await store.get_by_transfer_id(stored_proof.transfer_id) == stored_proof
    assert await store.get_by_id("missing") is None
    async with storage_db.connection() as conn:
        row = await (await conn.execute("SELECT jsonb_typeof(public_signals) FROM proofs")).fetchone()
        assert row == ("array",)
    await storage_db.close()
    await storage_db.connect()
    assert await store.get_by_id(stored_proof.proof_id) == stored_proof
    async with storage_db.connection() as conn:
        versions = await (await conn.execute("SELECT version FROM schema_migrations ORDER BY version")).fetchall()
        assert [row[0] for row in versions] == list(range(1, len(database_module._SCHEMA_MIGRATIONS) + 1))


async def test_concurrent_startup_is_serialized(storage_db):
    other = Database(pool_min=1, pool_max=1)
    try:
        await asyncio.gather(storage_db.connect(), storage_db.connect(), other.connect())
        assert storage_db.is_ready and other.is_ready
    finally:
        await other.close()


async def test_cancelled_startup_rolls_back_and_closes_connections(storage_db, monkeypatch):
    entered = asyncio.Event()
    connections = []

    async def pause_migration(conn):
        connections.append(conn)
        entered.set()
        await asyncio.Event().wait()

    original = database_module._SCHEMA_MIGRATIONS
    monkeypatch.setattr(database_module, "_SCHEMA_MIGRATIONS", [*original, pause_migration])
    task = asyncio.create_task(storage_db.connect())
    await asyncio.wait_for(entered.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not storage_db.is_ready
    assert all(conn.closed for conn in connections)
    async with await psycopg.AsyncConnection.connect(os.environ["DATABASE_URL"]) as conn:
        assert (await (await conn.execute("SELECT to_regclass('schema_migrations')")).fetchone())[0] is None
    monkeypatch.setattr(database_module, "_SCHEMA_MIGRATIONS", original)
    await storage_db.connect()
    assert storage_db.is_ready


async def seed_legacy_schema(proof: StoredProof, public_signals):
    """Seed the six original migrations, avoiding the new write validation."""
    async with await psycopg.AsyncConnection.connect(os.environ["DATABASE_URL"]) as conn:
        for migration in database_module._SCHEMA_MIGRATIONS[:6]:
            await conn.execute(migration)
        await conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
        await conn.execute("INSERT INTO schema_migrations SELECT generate_series(1, 6)")
        data = proof.model_dump()
        data["public_signals"] = Jsonb(public_signals)
        await conn.execute(
            sql.SQL("INSERT INTO proofs ({}) VALUES ({})").format(
                sql.SQL(", ").join(map(sql.Identifier, data)),
                sql.SQL(", ").join(sql.Placeholder() for _ in data),
            ),
            list(data.values()),
        )


@pytest.mark.parametrize("encoding", ["python-list", "json-string", "json-array"])
async def test_legacy_migration_preserves_valid_signals(storage_db, stored_proof, encoding):
    import json

    signals = stored_proof.public_signals
    encoded = {"python-list": str(signals), "json-string": json.dumps(signals), "json-array": signals}[encoding]
    await seed_legacy_schema(stored_proof, encoded)
    await storage_db.connect()
    assert await ProofStore(storage_db).get_by_id(stored_proof.proof_id) == stored_proof
    await storage_db.close()
    await storage_db.connect()
    assert await ProofStore(storage_db).get_by_id(stored_proof.proof_id) == stored_proof


@pytest.mark.parametrize("bad", ["['1'] * 1000000", "['x']", ["-1"], ["1"] * 129, " " * 17000, {"0": "1"}])
async def test_invalid_legacy_data_aborts_upgrade_without_modifying_records(storage_db, stored_proof, bad):
    await seed_legacy_schema(stored_proof, bad)
    with pytest.raises(ValueError, match="public_signals"):
        await storage_db.connect()
    assert not storage_db.is_ready
    async with await psycopg.AsyncConnection.connect(os.environ["DATABASE_URL"]) as conn:
        assert (await (await conn.execute("SELECT max(version) FROM schema_migrations")).fetchone())[0] == 6
        assert (await (await conn.execute("SELECT public_signals FROM proofs")).fetchone())[0] == bad


async def test_migration_never_executes_a_stored_expression(storage_db, stored_proof, tmp_path):
    marker = tmp_path / "must-not-exist"
    expression = f"__import__('pathlib').Path({str(marker)!r}).touch() or ['1']"
    await seed_legacy_schema(stored_proof, expression)
    with pytest.raises(ValueError, match="public_signals"):
        await storage_db.connect()
    assert not marker.exists()


async def test_failed_migration_rolls_back_ddl_and_version_then_can_retry(storage_db, monkeypatch):
    original = database_module._SCHEMA_MIGRATIONS
    monkeypatch.setattr(
        database_module,
        "_SCHEMA_MIGRATIONS",
        [*original, "CREATE TABLE must_rollback (n INTEGER); SELECT 1 / 0"],
    )
    with pytest.raises(psycopg.errors.DivisionByZero):
        await storage_db.connect()
    assert not storage_db.is_ready
    async with await psycopg.AsyncConnection.connect(os.environ["DATABASE_URL"]) as conn:
        assert (await (await conn.execute("SELECT to_regclass('must_rollback')")).fetchone())[0] is None
        assert (await (await conn.execute("SELECT to_regclass('schema_migrations')")).fetchone())[0] is None
    monkeypatch.setattr(database_module, "_SCHEMA_MIGRATIONS", original)
    await storage_db.connect()
    assert storage_db.is_ready


@pytest.mark.parametrize(
    "bad", [[], [True], [1], ["01"], ["-1"], ["1e2"], ["1\n"], [str(SCALAR_FIELD)], ["9" * 78], ["1"] * 129, "['1']"]
)
async def test_database_rejects_invalid_signals_from_other_writers(storage_db, stored_proof, bad):
    await storage_db.connect()
    await ProofStore(storage_db).store(stored_proof)
    with pytest.raises(psycopg.errors.CheckViolation):
        async with storage_db.connection() as conn:
            await conn.execute("UPDATE proofs SET public_signals = %s", (Jsonb(bad),))
    assert await ProofStore(storage_db).get_by_id(stored_proof.proof_id) == stored_proof


@pytest.mark.parametrize("bad_last_page", [False, True])
async def test_migration_pages_preserve_all_rows_and_rollback_together(storage_db, stored_proof, bad_last_page):
    proof = stored_proof.model_copy(update={"proof_id": "legacy-000"})
    await seed_legacy_schema(proof, str(proof.public_signals))
    async with await psycopg.AsyncConnection.connect(os.environ["DATABASE_URL"]) as conn:
        await conn.execute(
            """INSERT INTO proofs
            (proof_id, transfer_id, groth16_proof, public_signals, verification_key,
             originator_vasp_did, jurisdiction, amount_tier, proof_generated_at, proof_expires_at)
            SELECT 'legacy-' || lpad(n::text, 3, '0'), transfer_id, groth16_proof, public_signals,
                   verification_key, originator_vasp_did, jurisdiction, amount_tier,
                   proof_generated_at, proof_expires_at
            FROM proofs CROSS JOIN generate_series(1, 205) n WHERE proof_id = 'legacy-000'"""
        )
        if bad_last_page:
            await conn.execute(
                "UPDATE proofs SET public_signals = %s WHERE proof_id = 'legacy-205'", (Jsonb("['1'] * 1000000"),)
            )
    if bad_last_page:
        with pytest.raises(ValueError, match="public_signals"):
            await storage_db.connect()
        expected_type, expected_version = "string", 6
    else:
        await storage_db.connect()
        expected_type, expected_version = "array", len(database_module._SCHEMA_MIGRATIONS)
    async with await psycopg.AsyncConnection.connect(os.environ["DATABASE_URL"]) as conn:
        rows = await (
            await conn.execute("SELECT jsonb_typeof(public_signals), count(*) FROM proofs GROUP BY 1")
        ).fetchall()
        assert rows == [(expected_type, 206)]
        assert (await (await conn.execute("SELECT max(version) FROM schema_migrations")).fetchone())[
            0
        ] == expected_version


@pytest.mark.parametrize(
    "damage", ["DELETE FROM schema_migrations WHERE version = 3", "INSERT INTO schema_migrations VALUES (99)"]
)
async def test_unknown_migration_history_fails_closed(storage_db, stored_proof, damage):
    await seed_legacy_schema(stored_proof, str(stored_proof.public_signals))
    async with await psycopg.AsyncConnection.connect(os.environ["DATABASE_URL"]) as conn:
        await conn.execute(damage)
    with pytest.raises(RuntimeError, match="migration history"):
        await storage_db.connect()
    assert not storage_db.is_ready


async def test_mutated_model_cannot_bypass_write_validation(storage_db, stored_proof):
    await storage_db.connect()
    stored_proof.public_signals.append("__import__('os')")
    store = ProofStore(storage_db)
    with pytest.raises(ValueError, match="public_signals"):
        await store.store(stored_proof)
    assert await store.get_by_id(stored_proof.proof_id) is None


async def test_nullifier_race_and_database_failures_are_distinct(storage_db, stored_proof):
    await storage_db.connect()
    store = ProofStore(storage_db)
    await store.store(stored_proof)
    nullifier = StoredNullifier(
        nullifier_hash="nullifier-fixture",
        credential_commitment="commitment-fixture",
        transfer_id=stored_proof.transfer_id,
        proof_id=stored_proof.proof_id,
    )
    assert sorted(await asyncio.gather(store.add_nullifier(nullifier), store.add_nullifier(nullifier))) == [False, True]
    assert await store.nullifier_exists(nullifier.nullifier_hash)
    missing = nullifier.model_copy(update={"nullifier_hash": "missing", "proof_id": "absent"})
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        await store.add_nullifier(missing)


async def test_cleanup_returns_count(storage_db):
    await storage_db.connect()
    store = ProofStore(storage_db)
    await store.record_idempotency("old", "synthetic-wallet-reference", "result", ttl_seconds=-3600)
    await store.record_idempotency("live", "synthetic-wallet-reference", "result", ttl_seconds=3600)
    assert await store.cleanup_expired(max_age_hours=0) == 1
    assert await store.check_idempotency("old") is None
    assert await store.check_idempotency("live") == "result"
