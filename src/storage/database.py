from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import psycopg

logger = logging.getLogger(__name__)

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
        ON idempotency_keys (expires_at)
        WHERE expires_at > EXTRACT(EPOCH FROM now());
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
]


class Database:
    def __init__(self, pool_min: int = 2, pool_max: int = 10) -> None:
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: psycopg.Pool | None = None

    @property
    def is_ready(self) -> bool:
        return self._pool is not None

    async def connect(self) -> None:
        if self._pool is not None:
            return

        url = os.environ.get("DATABASE_URL")
        if not url:
            raise RuntimeError("DATABASE_URL environment variable is required")

        self._pool = psycopg.Pool(
            conninfo=url,
            min_size=self._pool_min,
            max_size=self._pool_max,
        )

        await self._migrate()
        logger.info("Database connected, schema up to date")

    async def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None
            logger.info("Database connection pool closed")

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[psycopg.Connection]:
        if self._pool is None:
            raise RuntimeError("Database not connected")
        conn = self._pool.connection()
        try:
            yield conn
        finally:
            conn.close()

    async def _migrate(self) -> None:
        async with self.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)

                result = await cur.execute("SELECT MAX(version) FROM schema_migrations")
                current_version = result.fetchone()[0] or 0

                for i, migration in enumerate(_SCHEMA_MIGRATIONS, start=current_version + 1):
                    if i <= current_version:
                        continue
                    await cur.execute(migration)
                    await conn.commit()
                    await cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (i,))
                    await conn.commit()
                    logger.info("Applied migration %d", i)
