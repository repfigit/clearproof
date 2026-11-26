# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL-backed multi-worker rate-limit bucket store and SIWE session store.

Both stores use PostgreSQL's database clock (``clock_timestamp()``) for window
and TTL expiry so multiple workers/replicas agree on expiry regardless of host
clock skew, and both bound table growth via on-write expired-row cleanup plus
bounded LRU eviction.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.storage.database import Database

DEFAULT_RATE_LIMIT_CLEANUP_BATCH = 500
DEFAULT_SIWE_CLEANUP_BATCH = 500
DEFAULT_SIWE_NONCE_CLEANUP_BATCH = 500
DEFAULT_CLEANUP_INTERVAL_WRITES = 64


def hash_session_token(token: str) -> str:
    """Return the lowercase hex SHA-256 digest of a raw SIWE session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_nonce(nonce: str) -> str:
    """Return the lowercase hex SHA-256 digest of a raw SIWE nonce."""
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def _resolve_bucket_namespace(bucket_key: str, bucket_namespace: str | None) -> str:
    """Return explicit ``bucket_namespace`` or derive the prefix before ``:`` (else ``default``)."""
    if bucket_namespace is not None:
        return bucket_namespace
    prefix, sep, _ = bucket_key.partition(":")
    return prefix if sep and prefix else "default"


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of one atomic rate-limit check/increment."""

    allowed: bool
    count: int
    retry_after: int


class PostgresRateLimitStore:
    """Atomic PostgreSQL rate-limit bucket store safe across workers and replicas.

    Concurrency model
    -----------------
    ``check_and_increment`` executes a single atomic
    ``INSERT INTO api_rate_limit_buckets ... ON CONFLICT (bucket_key) DO UPDATE``
    statement using PostgreSQL's ``clock_timestamp()``:

    - Missing row: inserts ``request_count = 1`` with
      ``window_started_at = clock_timestamp()`` and
      ``window_expires_at = clock_timestamp() + window``.
    - Expired row (``window_expires_at <= clock_timestamp()``): resets the
      window to start at ``clock_timestamp()`` with ``request_count = 1``.
    - Active row with ``request_count <= max_requests``: increments
      ``request_count`` up to ``max_requests + 1`` (clamped at ``max_requests + 1``
      so rejected bursts never overflow ``INTEGER``).
    - Allowed iff the returned ``request_count <= max_requests``.

    PostgreSQL serializes concurrent conflicting upserts on the primary key
    (``bucket_key``), so *N* concurrent increments for the same key can never
    exceed ``max_requests``.
    """

    def __init__(
        self,
        db: Database,
        *,
        cleanup_interval_writes: int = DEFAULT_CLEANUP_INTERVAL_WRITES,
        cleanup_batch_size: int = DEFAULT_RATE_LIMIT_CLEANUP_BATCH,
    ) -> None:
        if cleanup_interval_writes <= 0:
            raise ValueError("cleanup_interval_writes must be positive")
        if cleanup_batch_size <= 0:
            raise ValueError("cleanup_batch_size must be positive")
        self._db = db
        self._cleanup_interval_writes = cleanup_interval_writes
        self._cleanup_batch_size = cleanup_batch_size
        self._write_counter = 0

    async def check_and_increment(
        self,
        bucket_key: str,
        *,
        max_requests: int,
        window_seconds: float,
        max_clients: int,
        bucket_namespace: str | None = None,
    ) -> RateLimitDecision:
        """Atomically record a request or reject if ``max_requests`` is reached."""
        namespace = _resolve_bucket_namespace(bucket_key, bucket_namespace)
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO api_rate_limit_buckets AS b (
                    bucket_key,
                    bucket_namespace,
                    window_started_at,
                    window_expires_at,
                    request_count,
                    updated_at
                )
                VALUES (
                    %(bucket_key)s,
                    %(bucket_namespace)s,
                    clock_timestamp(),
                    clock_timestamp() + make_interval(secs => %(window_seconds)s),
                    1,
                    clock_timestamp()
                )
                ON CONFLICT (bucket_key) DO UPDATE SET
                    bucket_namespace = EXCLUDED.bucket_namespace,
                    window_started_at = CASE
                        WHEN b.window_expires_at <= clock_timestamp()
                            THEN clock_timestamp()
                        ELSE b.window_started_at
                    END,
                    window_expires_at = CASE
                        WHEN b.window_expires_at <= clock_timestamp()
                            THEN clock_timestamp() + make_interval(secs => %(window_seconds)s)
                        ELSE b.window_expires_at
                    END,
                    request_count = CASE
                        WHEN b.window_expires_at <= clock_timestamp()
                            THEN 1
                        WHEN b.request_count <= %(max_requests)s
                            THEN b.request_count + 1
                        ELSE b.request_count
                    END,
                    updated_at = clock_timestamp()
                RETURNING
                    request_count,
                    EXTRACT(EPOCH FROM (window_expires_at - clock_timestamp()))
                """,
                {
                    "bucket_key": bucket_key,
                    "bucket_namespace": namespace,
                    "window_seconds": float(window_seconds),
                    "max_requests": int(max_requests),
                },
            )
            row = await cur.fetchone()
            count = int(row[0])
            remaining = float(row[1])

        self._write_counter += 1
        if self._write_counter >= self._cleanup_interval_writes:
            self._write_counter = 0
            await self.cleanup(max_buckets=max_clients, bucket_namespace=namespace)

        allowed = count <= max_requests
        retry_after = 0 if allowed else max(1, math.ceil(remaining))
        return RateLimitDecision(allowed=allowed, count=min(count, max_requests), retry_after=retry_after)

    async def cleanup(
        self,
        *,
        max_buckets: int | None = None,
        batch_size: int | None = None,
        bucket_namespace: str | None = None,
    ) -> int:
        """Delete expired buckets (bounded batch) and evict oldest rows above ``max_buckets``.

        When ``bucket_namespace`` is provided, LRU eviction above ``max_buckets``
        is scoped strictly to that namespace so traffic on one endpoint cannot
        evict rate-limit buckets belonging to another endpoint.
        """
        limit = self._cleanup_batch_size if batch_size is None else batch_size
        deleted = 0
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                DELETE FROM api_rate_limit_buckets
                WHERE bucket_key IN (
                    SELECT bucket_key
                    FROM api_rate_limit_buckets
                    WHERE window_expires_at <= clock_timestamp()
                    ORDER BY window_expires_at ASC
                    LIMIT %(limit)s
                )
                """,
                {"limit": limit},
            )
            deleted += cur.rowcount

            if max_buckets is not None:
                if bucket_namespace is not None:
                    await cur.execute(
                        """
                        DELETE FROM api_rate_limit_buckets
                        WHERE bucket_key IN (
                            SELECT bucket_key
                            FROM api_rate_limit_buckets
                            WHERE bucket_namespace = %(bucket_namespace)s
                            ORDER BY updated_at DESC, bucket_key DESC
                            OFFSET %(max_buckets)s
                            LIMIT %(limit)s
                        )
                        """,
                        {
                            "bucket_namespace": bucket_namespace,
                            "max_buckets": int(max_buckets),
                            "limit": limit,
                        },
                    )
                else:
                    await cur.execute(
                        """
                        DELETE FROM api_rate_limit_buckets
                        WHERE bucket_key IN (
                            SELECT bucket_key
                            FROM api_rate_limit_buckets
                            ORDER BY updated_at DESC, bucket_key DESC
                            OFFSET %(max_buckets)s
                            LIMIT %(limit)s
                        )
                        """,
                        {"max_buckets": int(max_buckets), "limit": limit},
                    )
                deleted += cur.rowcount
        return deleted

    async def count(self, *, bucket_namespace: str | None = None) -> int:
        """Return the number of persisted rate-limit buckets (diagnostic/test hook)."""
        async with self._db.connection() as conn, conn.cursor() as cur:
            if bucket_namespace is not None:
                await cur.execute(
                    "SELECT count(*) FROM api_rate_limit_buckets WHERE bucket_namespace = %s",
                    (bucket_namespace,),
                )
            else:
                await cur.execute("SELECT count(*) FROM api_rate_limit_buckets")
            row = await cur.fetchone()
            return int(row[0])

    async def clear(self) -> None:
        """Delete all persisted rate-limit buckets (test isolation hook)."""
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute("DELETE FROM api_rate_limit_buckets")


class PostgresSIWESessionStore:
    """PostgreSQL-backed SIWE session store keyed by SHA-256 token hash.

    Raw session tokens are never stored in PostgreSQL; only the 64-char hex
    SHA-256 digest (``token_hash``) is persisted. Expiry is evaluated against
    PostgreSQL's ``clock_timestamp()``, and table growth is bounded via
    on-write expired-row cleanup plus LRU eviction above ``max_entries``.
    """

    def __init__(
        self,
        db: Database,
        *,
        max_entries: int,
        cleanup_batch_size: int = DEFAULT_SIWE_CLEANUP_BATCH,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        if cleanup_batch_size <= 0:
            raise ValueError("cleanup_batch_size must be positive")
        self._db = db
        self._max_entries = max_entries
        self._cleanup_batch_size = cleanup_batch_size

    @property
    def max_entries(self) -> int:
        return self._max_entries

    async def set(
        self,
        token: str,
        *,
        address: str,
        chain_id: int,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        """Persist a session keyed by ``sha256(token)``, pruning expired and LRU rows."""
        token_hash = hash_session_token(token)
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                DELETE FROM siwe_sessions
                WHERE token_hash IN (
                    SELECT token_hash
                    FROM siwe_sessions
                    WHERE expires_at <= clock_timestamp()
                    ORDER BY expires_at ASC
                    LIMIT %(limit)s
                )
                """,
                {"limit": self._cleanup_batch_size},
            )
            await cur.execute(
                """
                INSERT INTO siwe_sessions (
                    token_hash,
                    address,
                    chain_id,
                    created_at,
                    expires_at,
                    last_accessed_at
                )
                VALUES (
                    %(token_hash)s,
                    %(address)s,
                    %(chain_id)s,
                    clock_timestamp(),
                    clock_timestamp() + make_interval(secs => %(ttl_seconds)s),
                    clock_timestamp()
                )
                ON CONFLICT (token_hash) DO UPDATE SET
                    address = EXCLUDED.address,
                    chain_id = EXCLUDED.chain_id,
                    created_at = EXCLUDED.created_at,
                    expires_at = EXCLUDED.expires_at,
                    last_accessed_at = EXCLUDED.last_accessed_at
                RETURNING created_at, expires_at
                """,
                {
                    "token_hash": token_hash,
                    "address": address,
                    "chain_id": int(chain_id),
                    "ttl_seconds": float(ttl_seconds),
                },
            )
            created_at, expires_at = await cur.fetchone()
            await cur.execute(
                """
                DELETE FROM siwe_sessions
                WHERE token_hash IN (
                    SELECT token_hash
                    FROM siwe_sessions
                    ORDER BY last_accessed_at DESC, token_hash DESC
                    OFFSET %(max_entries)s
                    LIMIT %(limit)s
                )
                """,
                {"max_entries": self._max_entries, "limit": self._cleanup_batch_size},
            )

        return {
            "address": address,
            "chain_id": int(chain_id),
            "session_token": token,
            "created_at": _format_utc(created_at),
            "expires_at": _format_utc(expires_at),
        }

    async def get(self, token: str) -> dict[str, Any] | None:
        """Validate ``token`` against the DB clock, refreshing ``last_accessed_at``."""
        token_hash = hash_session_token(token)
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE siwe_sessions
                SET last_accessed_at = clock_timestamp()
                WHERE token_hash = %(token_hash)s
                  AND expires_at > clock_timestamp()
                RETURNING address, chain_id, created_at, expires_at
                """,
                {"token_hash": token_hash},
            )
            row = await cur.fetchone()
            if row is None:
                await cur.execute(
                    """
                    DELETE FROM siwe_sessions
                    WHERE token_hash = %(token_hash)s
                      AND expires_at <= clock_timestamp()
                    """,
                    {"token_hash": token_hash},
                )
                return None

        address, chain_id, created_at, expires_at = row
        return {
            "address": address,
            "chain_id": int(chain_id),
            "session_token": token,
            "created_at": _format_utc(created_at),
            "expires_at": _format_utc(expires_at),
        }

    async def sweep_expired(self, *, batch_size: int | None = None) -> int:
        """Delete a bounded batch of expired sessions using the PostgreSQL clock."""
        limit = self._cleanup_batch_size if batch_size is None else batch_size
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                DELETE FROM siwe_sessions
                WHERE token_hash IN (
                    SELECT token_hash
                    FROM siwe_sessions
                    WHERE expires_at <= clock_timestamp()
                    ORDER BY expires_at ASC
                    LIMIT %(limit)s
                )
                """,
                {"limit": limit},
            )
            return cur.rowcount

    async def count(self) -> int:
        """Return the number of persisted sessions (diagnostic/test hook)."""
        async with self._db.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT count(*) FROM siwe_sessions")
            row = await cur.fetchone()
            return int(row[0])


class PostgresSIWENonceStore:
    """PostgreSQL-backed SIWE nonce store keyed by SHA-256 nonce hash.

    Raw nonces are never stored in PostgreSQL; only the 64-char hex SHA-256
    digest (``nonce_hash``) is persisted. Expiry is evaluated against
    PostgreSQL's ``clock_timestamp()``, consumption is atomic via
    ``DELETE ... RETURNING``, and table growth is bounded via on-write
    expired-row cleanup plus oldest-first eviction above ``max_entries``.
    """

    def __init__(
        self,
        db: Database,
        *,
        max_entries: int,
        cleanup_batch_size: int = DEFAULT_SIWE_NONCE_CLEANUP_BATCH,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        if cleanup_batch_size <= 0:
            raise ValueError("cleanup_batch_size must be positive")
        self._db = db
        self._max_entries = max_entries
        self._cleanup_batch_size = cleanup_batch_size

    @property
    def max_entries(self) -> int:
        return self._max_entries

    async def create(self, nonce: str, *, ttl_seconds: float) -> None:
        """Persist ``sha256(nonce)`` with DB-clock expiry, pruning expired and excess rows."""
        nonce_hash = hash_nonce(nonce)
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                DELETE FROM siwe_nonces
                WHERE nonce_hash IN (
                    SELECT nonce_hash
                    FROM siwe_nonces
                    WHERE expires_at <= clock_timestamp()
                    ORDER BY expires_at ASC
                    LIMIT %(limit)s
                )
                """,
                {"limit": self._cleanup_batch_size},
            )
            await cur.execute(
                """
                INSERT INTO siwe_nonces (
                    nonce_hash,
                    created_at,
                    expires_at
                )
                VALUES (
                    %(nonce_hash)s,
                    clock_timestamp(),
                    clock_timestamp() + make_interval(secs => %(ttl_seconds)s)
                )
                ON CONFLICT (nonce_hash) DO UPDATE SET
                    created_at = EXCLUDED.created_at,
                    expires_at = EXCLUDED.expires_at
                """,
                {
                    "nonce_hash": nonce_hash,
                    "ttl_seconds": float(ttl_seconds),
                },
            )
            await cur.execute(
                """
                DELETE FROM siwe_nonces
                WHERE nonce_hash IN (
                    SELECT nonce_hash
                    FROM siwe_nonces
                    ORDER BY created_at DESC, nonce_hash DESC
                    OFFSET %(max_entries)s
                    LIMIT %(limit)s
                )
                """,
                {"max_entries": self._max_entries, "limit": self._cleanup_batch_size},
            )

    async def consume(self, nonce: str) -> bool:
        """Atomically delete ``sha256(nonce)`` and return ``True`` iff it was unexpired."""
        nonce_hash = hash_nonce(nonce)
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                DELETE FROM siwe_nonces
                WHERE nonce_hash = %(nonce_hash)s
                RETURNING (expires_at > clock_timestamp()) AS valid
                """,
                {"nonce_hash": nonce_hash},
            )
            row = await cur.fetchone()
        return bool(row and row[0])

    async def sweep_expired(self, *, batch_size: int | None = None) -> int:
        """Delete a bounded batch of expired nonces using the PostgreSQL clock."""
        limit = self._cleanup_batch_size if batch_size is None else batch_size
        async with self._db.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.execute(
                """
                DELETE FROM siwe_nonces
                WHERE nonce_hash IN (
                    SELECT nonce_hash
                    FROM siwe_nonces
                    WHERE expires_at <= clock_timestamp()
                    ORDER BY expires_at ASC
                    LIMIT %(limit)s
                )
                """,
                {"limit": limit},
            )
            return cur.rowcount

    async def count(self) -> int:
        """Return the number of persisted nonces (diagnostic/test hook)."""
        async with self._db.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT count(*) FROM siwe_nonces")
            row = await cur.fetchone()
            return int(row[0])


def _format_utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat()
