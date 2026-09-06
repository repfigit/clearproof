# Pilot tenant storage

`PilotStore` is the encrypted persistence boundary for the adoption pilot. It is
not yet connected to legacy issuance/proving routes. Migration 9 adds tables;
legacy unscoped rows are left untouched because their ownership cannot be inferred.

Construct a store from an authenticated `Principal`, a connected `Database` and a
`RecordCipher` containing the current and retained storage keys. Never construct
the principal from caller-supplied tenant IDs. Each SQL lookup includes the bound
tenant. Roles are explicit: admin does not implicitly grant decryption or proof
consumption. This is application tenant isolation, not PostgreSQL row-level security.

Records use the bounded canonical JSON profile in `specs/transfer-evidence-v1.md`.
The profile supports ASCII strings; arbitrary personal information must be encoded
inside its defined encrypted envelope, not passed as unrestricted JSON. Routing
IDs must be opaque identifiers, never names, email addresses or wallet addresses.
Tenant, kind, record ID, revision, key fingerprint and keyed content tag are visible
metadata. Payloads and cached operation results are encrypted with AES-256-GCM.
HKDF separates tenant encryption and content-tag keys. Ciphertext authentication
binds routing metadata and revision. Content tags reveal equality within a tenant;
they are keyed to resist guessing low-entropy plaintext from a database copy.

Use `transaction()` for short database operations. It takes a transaction-scoped
advisory lock per tenant with a 30-second total deadline. Do not nest store
transactions, perform network calls or generate proofs while holding this lock.
Failure or cancellation rolls back the entire transaction. Separate tenants can
write concurrently. Transactions cannot be reused after leaving their context.

Credentials, proofs, transfers, events, receipts, policies and revocations are
immutable. Root records accept an explicit expected revision and append a new
revision. `read(..., revision=N)` retrieves historical revisions; `read()` returns
the current revision and value. `get()` returns the current value only.

`run_idempotent()` commits the callback's writes and encrypted response together.
Retries with the same tenant, actor, operation, key and canonical request retrieve
the committed response. A changed actor or request conflicts. A unique tenant and
nullifier constraint prevents double consumption, and a composite foreign key
requires a proof in the same tenant. These are storage guarantees: the service
must authenticate credentials, verify proofs and enforce current policy before
calling `consume()`. `is_consumed()` only inspects state.

Key IDs fingerprint key material rather than environment version labels. Retain
old keys explicitly to read old records after rotation; removing a required key
fails closed. This does not implement a retention policy or automated re-encryption.
Database administrators can delete rows or restore an older database. AEAD detects
substitution and tampering, but cannot prove completeness or detect wholesale
rollback. Historical evidence still requires independently trusted snapshots and
verification anchors under the remaining pilot milestones.

Validation uses isolated real PostgreSQL schemas in
`tests/integration/test_pilot_storage.py`, plus tampering tests in
`tests/unit/test_pilot_cipher.py`. Test proof payloads are synthetic storage records,
not cryptographic proofs. Restart coverage closes/recreates the database connection
pool and constructs new store objects; it does not claim a PostgreSQL server crash
or full API-process recovery test.
