"""Additive tenant storage. Legacy unscoped rows are not assigned an owner implicitly."""

PILOT_SCHEMA = """
CREATE TABLE pilot_records (
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    key_id TEXT NOT NULL CHECK (length(key_id) = 64),
    content_tag TEXT NOT NULL CHECK (length(content_tag) = 64),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 65552),
    PRIMARY KEY (tenant_id, kind, record_id, revision),
    CHECK (tenant_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$' AND tenant_id !~ '[^a-z0-9_-]'),
    CHECK (record_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$' AND record_id !~ '[^a-z0-9_-]'),
    CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
                    'issuance-root','issuer-root','sanctions-root','idempotency'))
);
CREATE TABLE pilot_consumptions (
    tenant_id TEXT NOT NULL,
    nullifier TEXT NOT NULL CHECK (nullifier ~ '^[0-9a-f]{64}$' AND length(nullifier)=64),
    proof_kind TEXT NOT NULL DEFAULT 'proof' CHECK (proof_kind='proof'),
    proof_id TEXT NOT NULL,
    proof_revision BIGINT NOT NULL DEFAULT 1 CHECK (proof_revision=1),
    PRIMARY KEY (tenant_id, nullifier),
    FOREIGN KEY (tenant_id, proof_kind, proof_id, proof_revision)
        REFERENCES pilot_records(tenant_id, kind, record_id, revision)
);
"""

ROOT_SOURCE_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source'));
"""
