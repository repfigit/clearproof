# SPDX-License-Identifier: Apache-2.0
"""Incremental Merkle tree persistence schema for pilot issuance inventories."""

ISSUANCE_MERKLE_MIGRATION = """
CREATE TABLE pilot_merkle_roots (
    tenant_id TEXT NOT NULL,
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$' AND length(scope_digest)=64),
    depth SMALLINT NOT NULL CHECK (depth BETWEEN 1 AND 32),
    root_version BIGINT NOT NULL CHECK (root_version BETWEEN 0 AND 9007199254740991),
    leaf_count BIGINT NOT NULL CHECK (leaf_count BETWEEN 0 AND 4294967296),
    root_hash TEXT NOT NULL CHECK (root_hash ~ '^(0|[1-9][0-9]{0,77})$'),
    PRIMARY KEY (tenant_id, scope_digest, depth),
    CHECK (tenant_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$' AND tenant_id !~ '[^a-z0-9_-]')
);
CREATE TABLE pilot_merkle_leaves (
    tenant_id TEXT NOT NULL,
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$' AND length(scope_digest)=64),
    depth SMALLINT NOT NULL CHECK (depth BETWEEN 1 AND 32),
    leaf_index BIGINT NOT NULL CHECK (leaf_index BETWEEN 0 AND 4294967295),
    credential_id TEXT NOT NULL CHECK (credential_id ~ '^[0-9a-f]{64}$' AND length(credential_id)=64),
    commitment TEXT NOT NULL CHECK (commitment ~ '^[1-9][0-9]{0,77}$'),
    root_version BIGINT NOT NULL CHECK (root_version BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (tenant_id, scope_digest, depth, leaf_index),
    UNIQUE (tenant_id, scope_digest, depth, credential_id),
    UNIQUE (tenant_id, scope_digest, depth, commitment),
    FOREIGN KEY (tenant_id, scope_digest, depth)
        REFERENCES pilot_merkle_roots(tenant_id, scope_digest, depth)
);
CREATE TABLE pilot_merkle_nodes (
    tenant_id TEXT NOT NULL,
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$' AND length(scope_digest)=64),
    depth SMALLINT NOT NULL CHECK (depth BETWEEN 1 AND 32),
    level SMALLINT NOT NULL CHECK (level BETWEEN 0 AND 32),
    node_index BIGINT NOT NULL CHECK (node_index BETWEEN 0 AND 4294967295),
    node_hash TEXT NOT NULL CHECK (node_hash ~ '^(0|[1-9][0-9]{0,77})$'),
    root_version BIGINT NOT NULL CHECK (root_version BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (tenant_id, scope_digest, depth, level, node_index),
    FOREIGN KEY (tenant_id, scope_digest, depth)
        REFERENCES pilot_merkle_roots(tenant_id, scope_digest, depth)
);
"""

ISSUANCE_MERKLE_DOWNGRADE = """
DROP TABLE IF EXISTS pilot_merkle_nodes;
DROP TABLE IF EXISTS pilot_merkle_leaves;
DROP TABLE IF EXISTS pilot_merkle_roots;
"""
