# Proof storage upgrade (CP-001)

The storage layer accepts JSON arrays of 1–128 canonical decimal strings. Each
value must be in the BN254 scalar field (`0 <= value < r`). Numbers, booleans,
negative values, hexadecimal, leading zeros, expressions and nested containers
are rejected. This checks storage representation; the selected proof version
must separately validate signal count, statement and cryptographic validity.

Migration 7 converts legacy JSONB strings containing JSON arrays or the former
Python list representation into JSONB arrays. Only quoted decimal elements,
commas, brackets and whitespace are recognized in the legacy list grammar. No
Python evaluation or execution is involved. Input is limited to 16 KiB per row,
and records are processed in pages of 100. Migration 8 adds a database constraint
that also protects writes made outside Python.

Before upgrading an existing service, stop older writers and take a database
backup under the deployment's normal access controls. Start the new application
with the existing `DATABASE_URL`. Startup serializes migrations with a PostgreSQL
transaction advisory lock. All pending schema changes, data normalization and
version records commit together. A failed or cancelled startup does not expose a
ready pool; reconnect does not replay previously committed migrations.

Malformed or oversized stored values abort the upgrade and leave records and
migration versions unchanged. Do not delete or replace records just to make an
upgrade pass. Investigate the source under authorized access, recover a verified
record from a backup where available, and retain the incident evidence. Migration
histories with gaps or unknown versions also require investigation: the earlier
runner could assign incorrect version numbers during a failed reconnect.

For rollback before a successful upgrade, stop the failed process; its migration
transaction has already rolled back. After a successful upgrade, do not restart
the old writer against the new schema: it cannot serialize valid JSON arrays.
Use a compatible application build, or restore the pre-upgrade backup into a
separate controlled database after accounting for any writes since the backup.

Verification uses an isolated PostgreSQL instance. The integration fixture
creates a separate schema per test and drops only that schema:

```bash
DATABASE_URL='postgresql://localhost/clearproof_test' uv run python -m pytest \
  tests/integration/test_proof_storage.py tests/unit/test_stored_signals.py -q
```

Checks cover actual JSONB round trips, restart, concurrent startup, legacy
normalization, multi-page rollback, rejected expressions, direct SQL constraint
bypass attempts, and concurrent nullifier insertion. Missing proof references or
database failures propagate; only a real duplicate nullifier returns `False`.

Tenant isolation, durable credential issuance, atomic authorization consumption
and complete evidence retention are subsequent pilot requirements. These storage
checks do not establish those properties.
