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
verification anchors; see [historical verification](../internal/PILOT_HISTORY_INSPECTION.md).

Validation uses isolated real PostgreSQL schemas in
`tests/integration/test_pilot_storage.py`, plus tampering tests in
`tests/unit/test_pilot_cipher.py`. Storage-only cases use synthetic records. The explicitly enabled real-artifact
authorization cases also generate/verify actual development proofs and exercise
encrypted export, reconnect and API/CLI paths. Connection-pool reconnect is
distinct from the separate event-worker process-death test; neither establishes
recovery from a PostgreSQL server crash or arbitrary host failure.

### Shared enrollment eligibility checks

`load_unrevoked_enrollment` requires the caller's expected chain and registry
alongside its tenant transaction and verification time. It verifies the retained
wallet signature, record identity/commitment and original acceptance interval
before checking present credential validity and revocation. Issuance-tree building
uses this same boundary. Malformed acceptance evidence or an invalid signature
fails the build rather than being treated as an expired credential to omit.

Consent expiry limits when enrollment may be accepted; it does not shorten an
already accepted credential's lifetime. Callers must still independently establish
issuer/root authority, policy, valuation, transfer binding and proof validity.
The loader neither authorizes a transfer nor consumes its nullifier. Current
verification must run these checks in the same tenant transaction as consumption
to prevent a revocation racing that decision. `ProofAuthorizationService` runs
these checks through `_inspect_transaction` before recording the encrypted proof,
receipt and nullifier in the same idempotent tenant transaction. Exact retries
return the historical receipt; they are not a fresh current-policy decision.
