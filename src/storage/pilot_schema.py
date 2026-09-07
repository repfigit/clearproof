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


EVENT_INDEX_MIGRATION = """
CREATE TABLE pilot_event_index (
    tenant_id TEXT NOT NULL,
    record_id TEXT NOT NULL CHECK (record_id ~ '^[0-9a-f]{64}$' AND length(record_id)=64),
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$' AND length(scope_digest)=64),
    stream_digest TEXT NOT NULL CHECK (stream_digest ~ '^[0-9a-f]{64}$' AND length(stream_digest)=64),
    source_sequence BIGINT NOT NULL CHECK (source_sequence BETWEEN 1 AND 9007199254740991),
    kind TEXT NOT NULL DEFAULT 'event' CHECK (kind='event'),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision=1),
    PRIMARY KEY (tenant_id, record_id),
    UNIQUE (tenant_id, stream_digest, source_sequence),
    FOREIGN KEY (tenant_id, kind, record_id, revision)
        REFERENCES pilot_records(tenant_id, kind, record_id, revision)
);
CREATE INDEX pilot_events_by_scope ON pilot_event_index (tenant_id, scope_digest, record_id);
"""


PROVIDER_EVIDENCE_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source','provider-evidence'));
"""


FACT_EVIDENCE_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source',
               'provider-evidence','fact-evidence'));
"""


POLICY_ACTIVATION_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source',
               'provider-evidence','fact-evidence','policy-activation'));
"""

AUTHORIZATION_EVIDENCE_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source',
               'provider-evidence','fact-evidence','policy-activation','authorization-evidence'));
"""


OBSERVATION_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source',
               'provider-evidence','fact-evidence','policy-activation','authorization-evidence','observation'));
"""


PUBLICATION_JOURNAL_MIGRATION = """
CREATE TABLE pilot_publications (
    tenant_id TEXT NOT NULL,
    intent_id TEXT NOT NULL CHECK (intent_id ~ '^[0-9a-f]{64}$' AND length(intent_id)=64),
    receipt_id TEXT NOT NULL,
    receipt_kind TEXT NOT NULL DEFAULT 'receipt' CHECK (receipt_kind='receipt'),
    receipt_revision BIGINT NOT NULL DEFAULT 1 CHECK (receipt_revision=1),
    phase TEXT NOT NULL CHECK (phase IN ('publish','mirror')),
    chain_id BIGINT NOT NULL CHECK (chain_id BETWEEN 1 AND 9007199254740991),
    sender TEXT NOT NULL CHECK (sender ~ '^0x[0-9a-f]{40}$' AND length(sender)=42),
    nonce BIGINT NOT NULL CHECK (nonce BETWEEN 0 AND 9007199254740991),
    broadcast_claimed BOOLEAN NOT NULL DEFAULT false,
    key_id TEXT NOT NULL,
    content_tag TEXT NOT NULL,
    cipher_nonce BYTEA NOT NULL CHECK (octet_length(cipher_nonce)=12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 65552),
    PRIMARY KEY (tenant_id,intent_id),
    UNIQUE (chain_id,sender,nonce),
    UNIQUE (tenant_id,receipt_id,phase),
    FOREIGN KEY (tenant_id,receipt_kind,receipt_id,receipt_revision)
        REFERENCES pilot_records(tenant_id,kind,record_id,revision)
);
"""


PUBLICATION_HISTORY_MIGRATION = """
CREATE TABLE pilot_publication_observations (
    tenant_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    observation_id TEXT NOT NULL CHECK (observation_id ~ '^[0-9a-f]{64}$' AND length(observation_id)=64),
    previous_observation_id TEXT,
    key_id TEXT NOT NULL,
    content_tag TEXT NOT NULL,
    cipher_nonce BYTEA NOT NULL CHECK (octet_length(cipher_nonce)=12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 65552),
    PRIMARY KEY (tenant_id,intent_id,sequence),
    UNIQUE (tenant_id,intent_id,observation_id),
    FOREIGN KEY (tenant_id,intent_id) REFERENCES pilot_publications(tenant_id,intent_id),
    FOREIGN KEY (tenant_id,intent_id,previous_observation_id)
        REFERENCES pilot_publication_observations(tenant_id,intent_id,observation_id)
);
"""


PUBLICATION_ATTEMPTS_MIGRATION = """
ALTER TABLE pilot_publications ADD COLUMN broadcast_attempts INTEGER NOT NULL DEFAULT 0;
UPDATE pilot_publications SET broadcast_attempts=1 WHERE broadcast_claimed;
ALTER TABLE pilot_publications ADD CONSTRAINT pilot_publication_attempt_bounds
    CHECK (broadcast_attempts BETWEEN 0 AND 3 AND broadcast_claimed=(broadcast_attempts>0));
"""


WALLET_OWNERSHIP_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source',
               'provider-evidence','fact-evidence','policy-activation','authorization-evidence','observation',
               'wallet-challenge','wallet-challenge-slot','wallet-quota','wallet-attestation',
               'wallet-extension','wallet-revocation'));
"""
