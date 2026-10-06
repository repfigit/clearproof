# SPDX-License-Identifier: Apache-2.0
"""Opaque audience index; private enrollment evidence remains encrypted."""

ENROLLMENT_INVENTORY_MIGRATION = """
ALTER TABLE pilot_records DROP CONSTRAINT pilot_records_kind_check;
ALTER TABLE pilot_records ADD CONSTRAINT pilot_records_kind_check
CHECK (kind IN ('credential','proof','transfer','receipt','event','policy','revocation',
               'issuance-root','issuer-root','sanctions-root','idempotency','root-source',
               'provider-evidence','fact-evidence','policy-activation','authorization-evidence','observation',
               'wallet-challenge','wallet-challenge-slot','wallet-quota','wallet-attestation',
               'wallet-extension','wallet-revocation','enrollment-inventory'));
CREATE TABLE pilot_enrollment_index (
    tenant_id TEXT NOT NULL,
    record_id TEXT NOT NULL CHECK (record_id ~ '^[0-9a-f]{64}$' AND length(record_id)=64),
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$' AND length(scope_digest)=64),
    kind TEXT NOT NULL DEFAULT 'credential' CHECK (kind='credential'),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision=1),
    PRIMARY KEY (tenant_id, record_id),
    FOREIGN KEY (tenant_id, kind, record_id, revision)
        REFERENCES pilot_records(tenant_id, kind, record_id, revision)
);
CREATE INDEX pilot_enrollments_by_scope ON pilot_enrollment_index (tenant_id, scope_digest, record_id);
"""
