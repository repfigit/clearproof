# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL schema for multi-worker API state (rate-limit buckets, SIWE sessions, and SIWE nonces).

Appended as ordered, transactional migrations in ``src/storage/database.py``.
"""

RATE_LIMIT_BUCKETS_MIGRATION = """
CREATE TABLE api_rate_limit_buckets (
    bucket_key        TEXT PRIMARY KEY,
    window_started_at TIMESTAMPTZ NOT NULL,
    window_expires_at TIMESTAMPTZ NOT NULL,
    request_count     INTEGER NOT NULL CHECK (request_count >= 1),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (window_expires_at > window_started_at)
);

CREATE INDEX idx_api_rate_limit_buckets_expires
    ON api_rate_limit_buckets (window_expires_at);

CREATE INDEX idx_api_rate_limit_buckets_updated
    ON api_rate_limit_buckets (updated_at);
"""

SIWE_SESSIONS_MIGRATION = """
CREATE TABLE siwe_sessions (
    token_hash       TEXT PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$' AND length(token_hash) = 64),
    address          TEXT NOT NULL,
    chain_id         BIGINT NOT NULL CHECK (chain_id >= 0),
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    last_accessed_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX idx_siwe_sessions_expires
    ON siwe_sessions (expires_at);

CREATE INDEX idx_siwe_sessions_last_accessed
    ON siwe_sessions (last_accessed_at);
"""

SIWE_NONCES_MIGRATION = """
CREATE TABLE siwe_nonces (
    nonce_hash TEXT PRIMARY KEY CHECK (nonce_hash ~ '^[0-9a-f]{64}$' AND length(nonce_hash) = 64),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX idx_siwe_nonces_expires
    ON siwe_nonces (expires_at);

CREATE INDEX idx_siwe_nonces_created
    ON siwe_nonces (created_at);
"""

RATE_LIMIT_BUCKET_NAMESPACE_MIGRATION = """
ALTER TABLE api_rate_limit_buckets
    ADD COLUMN bucket_namespace TEXT NOT NULL DEFAULT 'default';

UPDATE api_rate_limit_buckets
SET bucket_namespace = CASE
    WHEN position(':' IN bucket_key) > 1
        THEN split_part(bucket_key, ':', 1)
    ELSE 'default'
END;

CREATE INDEX idx_api_rate_limit_buckets_namespace_updated
    ON api_rate_limit_buckets (bucket_namespace, updated_at DESC, bucket_key DESC);
"""
