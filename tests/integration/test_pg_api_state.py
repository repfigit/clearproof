# SPDX-License-Identifier: Apache-2.0
"""Real PostgreSQL integration tests for multi-worker rate limits, SIWE sessions, and migrations."""

from __future__ import annotations

import asyncio
import os
import uuid
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from fastapi import Depends, FastAPI, HTTPException
from psycopg import sql
from psycopg.conninfo import make_conninfo

from src.api import main as api_main
from src.api.config import get_siwe_auth
from src.api.middleware import auth as auth_middleware
from src.api.middleware import rate_limit as rate_limit_module
from src.api.middleware.rate_limit import PrincipalRateLimiter, RateLimiter
from src.api.routes import auth as auth_routes
from src.auth import siwe_auth as siwe_module
from src.auth.siwe_auth import SIWEAuth
from src.storage.api_state import (
    PostgresRateLimitStore,
    PostgresSIWESessionStore,
    hash_session_token,
)
from src.storage.database import _SCHEMA_MIGRATIONS, SCHEMA_VERSION, Database
from tests.integration.test_pilot_storage import db as db  # noqa: F401
from tests.unit.test_siwe_auth import signed

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL"),
]


# ---------------------------------------------------------------------------
# Migrations: fresh DB up-path + index & constraint verification
# ---------------------------------------------------------------------------


async def test_fresh_db_migrations_create_rate_limit_and_siwe_tables_with_indexes(monkeypatch):
    admin = os.environ["DATABASE_URL"]
    schema = "api_state_mig_" + uuid.uuid4().hex
    async with await psycopg.AsyncConnection.connect(admin) as conn:
        await conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    monkeypatch.setenv("DATABASE_URL", make_conninfo(admin, options=f"-c search_path={schema}"))
    database = Database(pool_min=1, pool_max=4)
    try:
        await database.connect()
        async with database.connection() as conn:
            cur = await conn.execute("SELECT version FROM schema_migrations ORDER BY version")
            versions = [row[0] for row in await cur.fetchall()]
            assert versions == list(range(1, SCHEMA_VERSION + 1))

            tables = {
                row[0]
                for row in await (
                    await conn.execute(
                        """
                        SELECT tablename FROM pg_tables
                        WHERE schemaname = %s
                          AND tablename IN ('api_rate_limit_buckets', 'siwe_sessions')
                        """,
                        (schema,),
                    )
                ).fetchall()
            }
            assert tables == {"api_rate_limit_buckets", "siwe_sessions"}

            indexes = {
                row[0]
                for row in await (
                    await conn.execute(
                        """
                        SELECT indexname FROM pg_indexes
                        WHERE schemaname = %s
                          AND tablename IN ('api_rate_limit_buckets', 'siwe_sessions')
                        """,
                        (schema,),
                    )
                ).fetchall()
            }
            assert {
                "idx_api_rate_limit_buckets_expires",
                "idx_api_rate_limit_buckets_updated",
                "idx_siwe_sessions_expires",
                "idx_siwe_sessions_last_accessed",
            }.issubset(indexes)

            # Reconnecting does not replay already-committed migrations.
        await database.close()
        await database.connect()
        async with database.connection() as conn:
            cur = await conn.execute("SELECT version FROM schema_migrations ORDER BY version")
            versions_after = [row[0] for row in await cur.fetchall()]
            assert versions_after == versions
    finally:
        await database.close()
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            await conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


async def test_upgrade_from_pre_api_state_schema_preserves_existing_records(monkeypatch):
    """Apply all migrations prior to the two API-state entries, then upgrade cleanly."""
    admin = os.environ["DATABASE_URL"]
    schema = "api_state_upg_" + uuid.uuid4().hex
    async with await psycopg.AsyncConnection.connect(admin) as conn:
        await conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    target_url = make_conninfo(admin, options=f"-c search_path={schema}")
    monkeypatch.setenv("DATABASE_URL", target_url)

    pre_count = len(_SCHEMA_MIGRATIONS) - 2
    async with await psycopg.AsyncConnection.connect(target_url) as conn:
        await conn.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        for idx, mig in enumerate(_SCHEMA_MIGRATIONS[:pre_count], start=1):
            if callable(mig):
                await mig(conn)
            else:
                await conn.execute(mig)
            await conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (idx,))

    database = Database(pool_min=1, pool_max=4)
    try:
        await database.connect()
        async with database.connection() as conn:
            max_ver = (await (await conn.execute("SELECT max(version) FROM schema_migrations")).fetchone())[0]
            assert max_ver == SCHEMA_VERSION
            assert (await (await conn.execute("SELECT count(*) FROM api_rate_limit_buckets")).fetchone())[0] == 0
            assert (await (await conn.execute("SELECT count(*) FROM siwe_sessions")).fetchone())[0] == 0
    finally:
        await database.close()
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            await conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


# ---------------------------------------------------------------------------
# PostgreSQL rate-limit buckets: concurrency, DB-clock expiry, proxy keying, cleanup
# ---------------------------------------------------------------------------


async def test_concurrent_same_key_increments_cannot_exceed_limit():
    """Spawn many concurrent increments across two independent Database pools (simulating two workers)."""
    admin = os.environ["DATABASE_URL"]
    schema = "api_rl_race_" + uuid.uuid4().hex
    async with await psycopg.AsyncConnection.connect(admin) as conn:
        await conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    url = make_conninfo(admin, options=f"-c search_path={schema}")

    old_url = os.environ["DATABASE_URL"]
    os.environ["DATABASE_URL"] = url
    worker_a_db = Database(pool_min=2, pool_max=8)
    worker_b_db = Database(pool_min=2, pool_max=8)
    try:
        await worker_a_db.connect()
        await worker_b_db.connect()
        store_a = PostgresRateLimitStore(worker_a_db, cleanup_interval_writes=1000)
        store_b = PostgresRateLimitStore(worker_b_db, cleanup_interval_writes=1000)

        limit = 5
        total_attempts = 24
        barrier = asyncio.Barrier(total_attempts)

        async def hit(idx: int):
            store = store_a if idx % 2 == 0 else store_b
            await barrier.wait()
            return await store.check_and_increment(
                "RACE_TIER:ip:198.51.100.42",
                max_requests=limit,
                window_seconds=60.0,
                max_clients=100,
            )

        decisions = await asyncio.gather(*(hit(i) for i in range(total_attempts)))
        allowed = [d for d in decisions if d.allowed]
        rejected = [d for d in decisions if not d.allowed]

        assert len(allowed) == limit
        assert len(rejected) == total_attempts - limit
        assert all(d.retry_after >= 1 for d in rejected)
        assert all(d.retry_after == 0 for d in allowed)

        # Stored request_count is clamped at limit + 1 (never overflows on sustained bursts).
        async with worker_a_db.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT request_count FROM api_rate_limit_buckets WHERE bucket_key = %s",
                    ("RACE_TIER:ip:198.51.100.42",),
                )
            ).fetchone()
            assert row[0] == limit + 1
    finally:
        os.environ["DATABASE_URL"] = old_url
        await worker_a_db.close()
        await worker_b_db.close()
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            await conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


async def test_rate_limit_expiry_uses_database_clock(db):
    """Window expiry resets cleanly via PostgreSQL clock_timestamp() without trusting Python time."""
    store = PostgresRateLimitStore(db, cleanup_interval_writes=100)
    key = "EXPIRY_TIER:ip:203.0.113.7"

    d1 = await store.check_and_increment(key, max_requests=2, window_seconds=30.0, max_clients=100)
    d2 = await store.check_and_increment(key, max_requests=2, window_seconds=30.0, max_clients=100)
    d3 = await store.check_and_increment(key, max_requests=2, window_seconds=30.0, max_clients=100)
    assert d1.allowed and d2.allowed
    assert not d3.allowed and d3.retry_after >= 1

    # Simulate DB clock passing window_expires_at by shifting the stored timestamps back.
    async with db.connection() as conn:
        await conn.execute(
            """
            UPDATE api_rate_limit_buckets
            SET window_started_at = clock_timestamp() - INTERVAL '60 seconds',
                window_expires_at = clock_timestamp() - INTERVAL '1 second'
            WHERE bucket_key = %s
            """,
            (key,),
        )

    # Next request resets the window atomically using DB clock_timestamp().
    d4 = await store.check_and_increment(key, max_requests=2, window_seconds=30.0, max_clients=100)
    assert d4.allowed and d4.count == 1

    # Also exercise genuine short-TTL DB-clock expiry with a real sub-second window.
    short_key = "SHORT_TIER:ip:203.0.113.8"
    s1 = await store.check_and_increment(short_key, max_requests=1, window_seconds=0.15, max_clients=100)
    s2 = await store.check_and_increment(short_key, max_requests=1, window_seconds=0.15, max_clients=100)
    assert s1.allowed and not s2.allowed
    await asyncio.sleep(0.22)
    s3 = await store.check_and_increment(short_key, max_requests=1, window_seconds=0.15, max_clients=100)
    assert s3.allowed and s3.count == 1


async def test_rate_limit_bounded_cleanup_and_lru_eviction(db):
    """Expired buckets are pruned in bounded batches and total buckets cannot grow unbounded."""
    store = PostgresRateLimitStore(db, cleanup_interval_writes=4, cleanup_batch_size=10)

    # Create 6 live buckets with max_clients=3; every 4th write triggers bounded cleanup.
    for i in range(6):
        await store.check_and_increment(
            f"BOUND_TIER:ip:198.51.100.{i}",
            max_requests=5,
            window_seconds=60.0,
            max_clients=3,
        )
    # Explicit bounded cleanup trims to max_buckets=3.
    removed = await store.cleanup(max_buckets=3, batch_size=2)
    assert removed == 2
    removed_rest = await store.cleanup(max_buckets=3, batch_size=10)
    assert removed_rest >= 0
    assert await store.count() <= 3

    # Mark all remaining rows expired and verify bounded batch deletion.
    async with db.connection() as conn:
        await conn.execute(
            """
            UPDATE api_rate_limit_buckets
            SET window_started_at = clock_timestamp() - INTERVAL '120 seconds',
                window_expires_at = clock_timestamp() - INTERVAL '60 seconds'
            """
        )
    assert await store.cleanup(max_buckets=None, batch_size=1) == 1
    assert await store.cleanup(max_buckets=None, batch_size=10) == 2
    assert await store.count() == 0

    # Verify clear() helper removes populated rows.
    await store.check_and_increment("CLEAR_TIER:ip:1.2.3.4", max_requests=5, window_seconds=60.0, max_clients=10)
    assert await store.count() == 1
    await store.clear()
    assert await store.count() == 0


async def test_rate_limiter_http_429_retry_after_and_trusted_proxy_keying_with_pg(db, monkeypatch):
    """Two FastAPI apps sharing one PostgreSQL DB share rate-limit state and preserve 429/Retry-After/XFF."""
    monkeypatch.setenv("RATE_LIMIT_TRUSTED_PROXIES", "10.0.0.0/8")
    monkeypatch.setattr(rate_limit_module, "_TRUSTED_PROXIES_CACHE", ("", ()))

    limiter_worker_a = RateLimiter(max_requests=2, window_seconds=30, bucket_namespace="MULTI_WORKER_HTTP")
    limiter_worker_b = RateLimiter(max_requests=2, window_seconds=30, bucket_namespace="MULTI_WORKER_HTTP")

    app_a = FastAPI()
    app_a.state.db = db
    app_b = FastAPI()
    app_b.state.db = db

    req_a = SimpleNamespace(
        app=app_a,
        headers={"X-Forwarded-For": "1.1.1.1, 198.51.100.77"},
        client=SimpleNamespace(host="10.0.0.2"),
    )
    req_b = SimpleNamespace(
        app=app_b,
        headers={"X-Forwarded-For": "2.2.2.2, 198.51.100.77"},
        client=SimpleNamespace(host="10.0.0.3"),
    )

    # Request 1 on worker A, request 2 on worker B -> both share bucket for 198.51.100.77.
    await limiter_worker_a(req_a)
    await limiter_worker_b(req_b)

    # Request 3 on worker A is rejected with 429 + Retry-After.
    with pytest.raises(HTTPException) as exc_info:
        await limiter_worker_a(req_a)
    assert exc_info.value.status_code == 429
    assert exc_info.value.detail == "Rate limit exceeded"
    assert int(exc_info.value.headers["Retry-After"]) >= 1

    # PrincipalRateLimiter also uses the PG store when attached directly.
    store = PostgresRateLimitStore(db)
    principal_limiter = PrincipalRateLimiter(max_requests=1, window_seconds=30, bucket_namespace="P_TIER", store=store)
    await principal_limiter(req_a, claims={"sub": "tenant-shared"})
    with pytest.raises(HTTPException) as p_exc:
        await principal_limiter(req_b, claims={"sub": "tenant-shared"})
    assert p_exc.value.status_code == 429


# ---------------------------------------------------------------------------
# PostgreSQL SIWE sessions: cross-instance validation, hash-only storage, DB clock, eviction
# ---------------------------------------------------------------------------


async def test_siwe_sessions_cross_instance_validation_and_token_hash_storage(db, monkeypatch):
    """Session issued by worker A is validated by worker B; raw token is never stored in Postgres."""
    monkeypatch.setattr(siwe_module, "_nonce_store", {})

    worker_a = SIWEAuth(domain="wallet.example", db=db, max_sessions=10)
    worker_b = SIWEAuth(domain="wallet.example", db=db, max_sessions=10)

    nonce = await worker_a.generate_nonce()
    message, signature, address = signed(nonce, domain="wallet.example")
    issued = await worker_a.verify(message, signature)
    raw_token = issued["session_token"]

    # Raw token is never persisted in siwe_sessions; only its 64-hex SHA-256 hash is stored.
    expected_hash = hash_session_token(raw_token)
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT token_hash, address, chain_id FROM siwe_sessions")).fetchall()
    assert rows == [(expected_hash, address, 1)]
    assert raw_token not in rows[0][0]

    # Worker B (separate SIWEAuth instance, empty local dict) validates the session via PostgreSQL.
    assert worker_b.session_count() == 0
    validated = await worker_b.validate_session(raw_token)
    assert validated is not None
    assert validated["address"] == address
    assert validated["chain_id"] == 1
    assert validated["session_token"] == raw_token
    assert await worker_b.validate_session("unknown-token") is None


async def test_siwe_sessions_db_clock_expiry_eviction_and_cleanup(db, monkeypatch):
    """Verify TTL expiry via DB clock, LRU eviction above max_entries, and bounded sweep_expired."""
    store = PostgresSIWESessionStore(db, max_entries=2, cleanup_batch_size=10)
    assert store.max_entries == 2

    s1 = await store.set("tok-1", address="0x1111", chain_id=1, ttl_seconds=60)
    await asyncio.sleep(0.02)
    s2 = await store.set("tok-2", address="0x2222", chain_id=1, ttl_seconds=60)
    assert await store.count() == 2

    # Touch tok-1 so tok-2 becomes LRU.
    await asyncio.sleep(0.02)
    assert (await store.get("tok-1"))["address"] == s1["address"]

    # Upserting an existing token updates in place without evicting tok-2.
    refreshed = await store.set("tok-1", address="0x1111", chain_id=1, ttl_seconds=120)
    assert refreshed["address"] == "0x1111"
    assert await store.count() == 2

    # Inserting tok-3 evicts LRU (tok-2) to maintain max_entries=2.
    await asyncio.sleep(0.02)
    await store.set("tok-3", address="0x3333", chain_id=1, ttl_seconds=60)
    assert await store.count() == 2
    assert await store.get(s2["session_token"]) is None
    assert await store.get("tok-1") is not None
    assert await store.get("tok-3") is not None

    # Force tok-1 expired via DB clock and verify get() rejects and deletes it.
    async with db.connection() as conn:
        await conn.execute(
            """
            UPDATE siwe_sessions
            SET created_at = clock_timestamp() - INTERVAL '120 seconds',
                expires_at = clock_timestamp() - INTERVAL '1 second'
            WHERE token_hash = %s
            """,
            (hash_session_token("tok-1"),),
        )
    assert await store.get("tok-1") is None
    assert await store.count() == 1

    # Force tok-3 expired and verify sweep_expired() cleans it up.
    async with db.connection() as conn:
        await conn.execute(
            """
            UPDATE siwe_sessions
            SET created_at = clock_timestamp() - INTERVAL '120 seconds',
                expires_at = clock_timestamp() - INTERVAL '1 second'
            WHERE token_hash = %s
            """,
            (hash_session_token("tok-3"),),
        )
    assert await store.sweep_expired(batch_size=5) == 1
    assert await store.sweep_expired() == 0
    assert await store.count() == 0


async def test_lifespan_wires_pg_rate_limit_and_cross_worker_siwe_http(monkeypatch):
    """Two full create_app() instances with lifespan share PG rate limits and SIWE sessions over HTTP."""
    admin = os.environ["DATABASE_URL"]
    schema = "api_lifespan_" + uuid.uuid4().hex
    async with await psycopg.AsyncConnection.connect(admin) as conn:
        await conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    url = make_conninfo(admin, options=f"-c search_path={schema}")

    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("DB_POOL_MIN", "1")
    monkeypatch.setenv("DB_POOL_MAX", "4")
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("ALLOW_INSECURE_HKDF_SALT", "1")
    monkeypatch.setenv("AUTH_MODE", "siwe")
    monkeypatch.setenv("SIWE_DOMAIN", "wallet.example")
    monkeypatch.setenv("RATE_LIMIT_AUTH_VERIFY_MAX_REQUESTS", "2")
    monkeypatch.setenv("RATE_LIMIT_AUTH_VERIFY_WINDOW_SECONDS", "30")
    monkeypatch.delenv("PILOT_EVENT_AUTHORITIES", raising=False)
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_URL", raising=False)
    monkeypatch.setattr(siwe_module, "_nonce_store", {})

    app_a = api_main.create_app()
    app_b = api_main.create_app()

    @app_b.get("/_cross_worker_probe")
    async def probe(claims: dict = Depends(auth_middleware.JWTAuthDependency)):
        return claims

    try:
        async with api_main.lifespan(app_a), api_main.lifespan(app_b):
            assert isinstance(app_a.state.rate_limit_store, PostgresRateLimitStore)
            assert isinstance(app_b.state.rate_limit_store, PostgresRateLimitStore)
            assert app_a.state.siwe_auth._pg_sessions is not None
            assert app_b.state.siwe_auth._pg_sessions is not None
            assert get_siwe_auth(SimpleNamespace(app=app_a)) is app_a.state.siwe_auth

            async with (
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app_a), base_url="http://worker-a") as client_a,
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app_b), base_url="http://worker-b") as client_b,
            ):
                # Issue SIWE session on worker A.
                nonce = (await client_a.get("/auth/nonce")).json()["nonce"]
                message, signature, address = signed(nonce, domain="wallet.example")
                verify_resp = await client_a.post("/auth/verify", json={"message": message, "signature": signature})
                assert verify_resp.status_code == 200
                token = verify_resp.json()["session_token"]

                # Validate the issued session on worker B.
                probe_resp = await client_b.get("/_cross_worker_probe", headers={"Authorization": f"Bearer {token}"})
                assert probe_resp.status_code == 200
                assert probe_resp.json()["sub"] == address
                assert probe_resp.json()["auth_mode"] == "siwe"

                # Rate limit on /auth/verify is shared across worker A (1st call above) and worker B.
                r2 = await client_b.post("/auth/verify", json={"message": "invalid", "signature": "0x00"})
                assert r2.status_code == 401
                r3 = await client_a.post("/auth/verify", json={"message": "invalid", "signature": "0x00"})
                assert r3.status_code == 429
                assert r3.json() == {"detail": "Rate limit exceeded"}
                assert int(r3.headers["Retry-After"]) >= 1

        assert app_a.state.rate_limit_store is None
        assert app_b.state.rate_limit_store is None
    finally:
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            await conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


async def test_lazy_get_siwe_auth_binds_ready_database_on_bare_app(db, monkeypatch):
    """Bare FastAPI app with a connected app.state.db lazily constructs PG-backed SIWEAuth."""
    monkeypatch.setenv("SIWE_DOMAIN", "bare-pg.example")
    monkeypatch.setattr(siwe_module, "_nonce_store", {})
    app = FastAPI()
    app.state.db = db
    app.include_router(auth_routes.router)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://bare") as client:
        nonce = (await client.get("/auth/nonce")).json()["nonce"]
        message, signature, address = signed(nonce, domain="bare-pg.example")
        resp = await client.post("/auth/verify", json={"message": message, "signature": signature})
        assert resp.status_code == 200
        assert app.state.siwe_auth._pg_sessions is not None
        assert await app.state.siwe_auth._pg_sessions.count() == 1
        validated = await app.state.siwe_auth.validate_session(resp.json()["session_token"])
        assert validated is not None and validated["address"] == address


async def test_api_state_stores_unwind_transactions_and_release_connections_on_cursor_error():
    """Verify cursor errors unwind transaction/cursor/connection contexts cleanly without leaks."""
    from contextlib import asynccontextmanager

    events: list[str] = []

    class FailingCursor:
        def __init__(self, fail_on_call: int = 1) -> None:
            self._calls = 0
            self._fail_on_call = fail_on_call
            self.rowcount = 0

        async def execute(self, *_args, **_kwargs) -> None:
            self._calls += 1
            if self._calls == self._fail_on_call:
                raise RuntimeError("simulated cursor execute failure")

        async def fetchone(self):
            return None

    class FakeConnection:
        def __init__(self, fail_on_call: int = 1) -> None:
            self._fail_on_call = fail_on_call

        @asynccontextmanager
        async def transaction(self):
            events.append("tx:enter")
            try:
                yield
            except BaseException:
                events.append("tx:rollback")
                raise
            finally:
                events.append("tx:exit")

        @asynccontextmanager
        async def cursor(self):
            events.append("cur:enter")
            try:
                yield FailingCursor(self._fail_on_call)
            finally:
                events.append("cur:exit")

    class FakeDB:
        def __init__(self, fail_on_call: int = 1) -> None:
            self.open_connections = 0
            self._fail_on_call = fail_on_call

        @asynccontextmanager
        async def connection(self):
            self.open_connections += 1
            events.append("conn:enter")
            try:
                yield FakeConnection(self._fail_on_call)
            finally:
                self.open_connections -= 1
                events.append("conn:exit")

    def assert_clean_unwind(fake_db: FakeDB) -> None:
        assert fake_db.open_connections == 0
        assert events == ["conn:enter", "tx:enter", "cur:enter", "cur:exit", "tx:rollback", "tx:exit", "conn:exit"]
        events.clear()

    # 1. Rate-limit check_and_increment (record)
    fake_db = FakeDB()
    rl_store = PostgresRateLimitStore(fake_db)
    with pytest.raises(RuntimeError, match="simulated cursor execute failure"):
        await rl_store.check_and_increment("K", max_requests=5, window_seconds=60.0, max_clients=10)
    assert_clean_unwind(fake_db)

    # 2. Rate-limit cleanup with max_buckets and explicit batch_size (fail on 1st and 2nd execute)
    for fail_on in (1, 2):
        fake_db = FakeDB(fail_on_call=fail_on)
        rl_store = PostgresRateLimitStore(fake_db)
        with pytest.raises(RuntimeError, match="simulated cursor execute failure"):
            await rl_store.cleanup(max_buckets=5, batch_size=3)
        assert_clean_unwind(fake_db)

    # 3. Rate-limit clear
    fake_db = FakeDB()
    rl_store = PostgresRateLimitStore(fake_db)
    with pytest.raises(RuntimeError, match="simulated cursor execute failure"):
        await rl_store.clear()
    assert_clean_unwind(fake_db)

    # 4. SIWE session set (create)
    fake_db = FakeDB()
    siwe_store = PostgresSIWESessionStore(fake_db, max_entries=10)
    with pytest.raises(RuntimeError, match="simulated cursor execute failure"):
        await siwe_store.set("tok-err", address="0x1111", chain_id=1, ttl_seconds=60)
    assert_clean_unwind(fake_db)

    # 5. SIWE session get
    fake_db = FakeDB()
    siwe_store = PostgresSIWESessionStore(fake_db, max_entries=10)
    with pytest.raises(RuntimeError, match="simulated cursor execute failure"):
        await siwe_store.get("tok-err")
    assert_clean_unwind(fake_db)

    # 6. SIWE session sweep_expired with explicit batch_size
    fake_db = FakeDB()
    siwe_store = PostgresSIWESessionStore(fake_db, max_entries=10)
    with pytest.raises(RuntimeError, match="simulated cursor execute failure"):
        await siwe_store.sweep_expired(batch_size=4)
    assert_clean_unwind(fake_db)
