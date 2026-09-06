from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import psycopg
from psycopg_pool import AsyncConnectionPool

from src.storage.pilot_schema import (
    AUTHORIZATION_EVIDENCE_MIGRATION,
    EVENT_INDEX_MIGRATION,
    FACT_EVIDENCE_MIGRATION,
    PILOT_SCHEMA,
    POLICY_ACTIVATION_MIGRATION,
    PROVIDER_EVIDENCE_MIGRATION,
    ROOT_SOURCE_MIGRATION,
)
from src.storage.signals import PUBLIC_SIGNALS_CONSTRAINT, migrate_public_signals

logger = logging.getLogger(__name__)

_MIGRATION_LOCK = 0x4350524F4F46

_SCHEMA_MIGRATIONS = [
    """
    CREATE TABLE IF NOT EXISTS credentials (
        credential_id   TEXT PRIMARY KEY,
        issuer_did      TEXT NOT NULL,
        subject_wallet  TEXT NOT NULL,
        jurisdiction    TEXT NOT NULL,
        kyc_tier        TEXT NOT NULL CHECK (kyc_tier IN ('retail', 'professional', 'institutional')),
        sanctions_clear BOOLEAN NOT NULL,
        issued_at       BIGINT NOT NULL,
        expires_at      BIGINT NOT NULL,
        revoked         BOOLEAN NOT NULL DEFAULT FALSE,
        commitment      TEXT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_credentials_wallet ON credentials (subject_wallet);
    CREATE INDEX IF NOT EXISTS idx_credentials_commitment ON credentials (commitment);
    CREATE INDEX IF NOT EXISTS idx_credentials_revoked ON credentials (revoked) WHERE revoked = FALSE;
    """,
    """
    CREATE TABLE IF NOT EXISTS proofs (
        proof_id        TEXT PRIMARY KEY,
        transfer_id     TEXT NOT NULL,
        groth16_proof   TEXT NOT NULL,
        public_signals  JSONB NOT NULL,
        verification_key TEXT NOT NULL,
        originator_vasp_did TEXT NOT NULL,
        beneficiary_vasp_did TEXT,
        jurisdiction    TEXT NOT NULL,
        amount_tier     SMALLINT NOT NULL CHECK (amount_tier BETWEEN 1 AND 4),
        proof_generated_at BIGINT NOT NULL,
        proof_expires_at BIGINT NOT NULL,
        is_expired      BOOLEAN NOT NULL DEFAULT FALSE,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_proofs_transfer ON proofs (transfer_id);
    CREATE INDEX IF NOT EXISTS idx_proofs_expires ON proofs (proof_expires_at) WHERE NOT is_expired;
    """,
    """
    CREATE TABLE IF NOT EXISTS nullifiers (
        nullifier_hash  TEXT PRIMARY KEY,
        credential_commitment TEXT NOT NULL,
        transfer_id     TEXT NOT NULL,
        proof_id        TEXT NOT NULL REFERENCES proofs(proof_id),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_nullifiers_commitment ON nullifiers (credential_commitment);
    """,
    """
    CREATE TABLE IF NOT EXISTS idempotency_keys (
        key             TEXT PRIMARY KEY,
        wallet_address  TEXT NOT NULL,
        result_hash     TEXT NOT NULL,
        expires_at      BIGINT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_idem_expires
        ON idempotency_keys (expires_at);
    """,
    """
    CREATE TABLE IF NOT EXISTS sanctions_roots (
        root_id         BIGSERIAL PRIMARY KEY,
        root_hash       TEXT NOT NULL,
        leaf_count      INTEGER NOT NULL,
        source          TEXT NOT NULL,
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        is_current      BOOLEAN NOT NULL DEFAULT FALSE
    );

    ALTER TABLE sanctions_roots ADD CONSTRAINT chk_leaf_count CHECK (leaf_count >= 0);

    CREATE INDEX IF NOT EXISTS idx_sanctions_current ON sanctions_roots (is_current);
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_entries (
        sequence_number BIGSERIAL PRIMARY KEY,
        timestamp       BIGINT NOT NULL,
        entry_type      TEXT NOT NULL,
        actor           TEXT NOT NULL,
        transaction_ref TEXT NOT NULL,
        data_hash       TEXT NOT NULL,
        prev_entry_hash TEXT NOT NULL,
        entry_hash      TEXT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_entries (entry_type);
    CREATE INDEX IF NOT EXISTS idx_audit_transaction ON audit_entries (transaction_ref);
    """,
    migrate_public_signals,
    PUBLIC_SIGNALS_CONSTRAINT,
    PILOT_SCHEMA,
    ROOT_SOURCE_MIGRATION,
    EVENT_INDEX_MIGRATION,
    PROVIDER_EVIDENCE_MIGRATION,
    FACT_EVIDENCE_MIGRATION,
    POLICY_ACTIVATION_MIGRATION,
    AUTHORIZATION_EVIDENCE_MIGRATION,
]


class Database:
    def __init__(self, pool_min: int = 2, pool_max: int = 10) -> None:
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: AsyncConnectionPool | None = None
        self._lifecycle_lock = asyncio.Lock()

    @property
    def is_ready(self) -> bool:
        return self._pool is not None

    async def connect(self) -> None:
        async with self._lifecycle_lock:
            if self._pool is not None:
                return
            url = os.environ.get("DATABASE_URL")
            if not url:
                raise RuntimeError("DATABASE_URL environment variable is required")
            pool = AsyncConnectionPool(conninfo=url, min_size=self._pool_min, max_size=self._pool_max, open=False)
            try:
                await pool.open(wait=True)
                await self._migrate(pool)
            except BaseException:
                await pool.close()
                raise
            self._pool = pool
            logger.info("Database connected, schema up to date")

    async def close(self) -> None:
        async with self._lifecycle_lock:
            if self._pool is not None:
                await self._pool.close()
                self._pool = None
                logger.info("Database connection pool closed")

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[psycopg.AsyncConnection]:
        if self._pool is None:
            raise RuntimeError("Database not connected")
        async with self._pool.connection() as conn:
            yield conn

    async def _migrate(self, pool: AsyncConnectionPool) -> None:
        # The pool context commits schema, data and version rows together, or
        # rolls them all back. Acquire the lock before even creating the table.
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK,))
                await cur.execute("""
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)

                await cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                versions = [row[0] for row in await cur.fetchall()]
                current_version = versions[-1] if versions else 0
                if current_version > len(_SCHEMA_MIGRATIONS) or versions != list(range(1, current_version + 1)):
                    raise RuntimeError("Unrecognized database migration history; operator review required")

                for i, migration in enumerate(_SCHEMA_MIGRATIONS, start=1):
                    if i <= current_version:
                        continue
                    if callable(migration):
                        await migration(conn)
                    else:
                        await cur.execute(migration)
                    await cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (i,))
        logger.info("Database migrations committed through version %d", len(_SCHEMA_MIGRATIONS))
