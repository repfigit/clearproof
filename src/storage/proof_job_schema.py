"""Durable, encrypted pilot proving queue; global limits are database state."""

PROOF_JOBS_MIGRATION = """
CREATE TABLE proof_job_control (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    max_concurrent INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrent BETWEEN 1 AND 4),
    max_pending INTEGER NOT NULL DEFAULT 256 CHECK (max_pending BETWEEN 1 AND 1024),
    max_tenant_pending INTEGER NOT NULL DEFAULT 32 CHECK (max_tenant_pending BETWEEN 1 AND 64)
);
INSERT INTO proof_job_control(singleton) VALUES (true);
CREATE TABLE proof_jobs (
    tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    job_id TEXT NOT NULL CHECK (job_id ~ '^[0-9a-f]{64}$'),
    actor_id TEXT NOT NULL CHECK (actor_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    status TEXT NOT NULL CHECK (status IN ('queued','proving','cancelling','completed','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + 300),
    retain_until BIGINT NOT NULL CHECK (retain_until=created_at+86400),
    available_at BIGINT NOT NULL,
    lease_token TEXT CHECK (lease_token ~ '^[0-9a-f]{64}$'),
    lease_expires_at BIGINT,
    last_error TEXT CHECK (last_error IN ('job_expired','prover_failed','current_state_rejected',
        'configuration_changed','worker_interrupted','retry_exhausted','stored_input_rejected')),
    request_key_id TEXT NOT NULL,
    request_content_tag TEXT NOT NULL,
    request_nonce BYTEA NOT NULL CHECK (octet_length(request_nonce)=12),
    request_ciphertext BYTEA NOT NULL CHECK (octet_length(request_ciphertext) BETWEEN 16 AND 32784),
    result_key_id TEXT,
    result_content_tag TEXT,
    result_nonce BYTEA CHECK (octet_length(result_nonce)=12),
    result_ciphertext BYTEA CHECK (octet_length(result_ciphertext) BETWEEN 16 AND 16400),
    PRIMARY KEY (tenant_id,job_id),
    UNIQUE (tenant_id,idempotency_key),
    CHECK ((status IN ('proving','cancelling')) = (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((result_key_id IS NULL AND result_content_tag IS NULL AND result_nonce IS NULL AND result_ciphertext IS NULL)
        OR (result_key_id IS NOT NULL AND result_content_tag IS NOT NULL
            AND result_nonce IS NOT NULL AND result_ciphertext IS NOT NULL)),
    CHECK ((status='completed') = (result_ciphertext IS NOT NULL))
);
CREATE INDEX proof_jobs_claim ON proof_jobs (available_at,created_at,job_id) WHERE status='queued';
CREATE INDEX proof_jobs_active ON proof_jobs (tenant_id,status) WHERE status IN ('queued','proving','cancelling');
CREATE INDEX proof_jobs_retention ON proof_jobs (retain_until);
"""
