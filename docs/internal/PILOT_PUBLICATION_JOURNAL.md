# Development publication journal

`PublicationJournal` retains encrypted signed transaction bytes before an operator
attempts publication. It is a persistence and broadcast boundary, not a source
approval service or a finality verifier. PostgreSQL remains the authorization
consumption authority; a journal entry or RPC response never creates a second
transfer authorization.

## Reservation

The caller constructs a `PublicationBinding` from an independently authenticated
mirror preparation and approved transaction builder. It binds the consumed receipt,
statement, publish/mirror phase, chain, registry, sender, exact calldata SHA-256,
semantic plan digest, approved runtime SHA-256 and expiry. The builder must verify
that the calldata implements that phase and statement. The journal does not decode
contract calls or independently approve the supplied plan/runtime pins.

`reserve` requires tenant-admin, evidence-decryption and proof-inspection roles.
It accepts bounded signed EIP-1559 type-2 transactions, recovers the actual sender,
and compares chain, destination, zero transferred value and exact calldata digest.
The transaction hash is computed from the signed bytes. The receipt must exist in
the tenant's encrypted store, have its exact canonical identity and ALLOW outcome,
and match the authoritative nullifier-to-proof consumption. Intent expiry cannot
exceed the retained receipt expiry. Current source approval is separately required
before broadcasting.

Migration 17 adds `pilot_publications`. Signed bytes are split into bounded hex
chunks within the existing 64 KiB canonical/encrypted record envelope. Public
operational metadata reserves `(chain_id, sender, nonce)` across tenants and one
phase per tenant/receipt. Exact reservation retries return the same identity;
a different transaction for that phase or an already reserved account nonce fails.
The sender is an operator transaction account, not a customer wallet selector.
Nonce coordination is limited to this database: the operator must separately
control use of the account by other applications and databases.

## Broadcast and uncertain outcomes

`broadcast_once` loads the retained intent, calls the writer's independent source
and chain revalidation callback, and commits a broadcast claim under the tenant
lock before invoking `send_raw`. The callback must raise on failed validation and
must check the current clock, source evidence, destination/runtime, epochs and
revisions. No transaction is sent if revalidation fails.

Only the first claimant invokes the sender. A crash before send, timeout after
send, cancellation, incorrect returned hash or successful RPC response leaves the
claim set. The journal never clears it or automatically allocates another nonce,
bumps fees or resends. This intentionally leaves a pre-send crash unresolved until
an operator/worker reconciles it; a claim does not prove that the node received the
transaction.

`inspect` works after reconnect and expiry and returns the binding, exact retained
transaction hash and claim state. Its chain outcome is always `not-established`.
The writer must query that hash on the independently pinned chain, verify block
inclusion/canonicality/finality and exact registry state, and distinguish pending,
failed, replaced, orphaned and successfully mirrored outcomes. These reconciliation
and replacement state transitions remain unimplemented; a journal row alone is
insufficient evidence for any of them. Database reservation and chain state are
not atomic, and the journal does not schedule source invalidation.

## Validation and accounting

The PostgreSQL tests cover encrypted reservation, exact retry, expiry, reconnect,
foreign-tenant reads, global nonce conflicts, phase conflicts, competing claims,
failed revalidation, lost responses and incorrect RPC hashes. The joined real EVM
gate signs its publish and mirror transactions with public local Hardhat test keys.
Publication is accepted by the node but its response is deliberately lost; after
reconnecting PostgreSQL the gate finds the transaction by its retained hash,
checks successful inclusion and registry state, and confirms no second send occurs.
This demonstrates local recovery evidence, not a durable production worker or
production finality policy.

The existing `/pilot/usage` inventory counts `pilot_records` and authoritative
consumptions. It does not include journal rows or their ciphertext in its retained
record/byte counters. Publication accounting and retention are separate follow-up
work; these counts are not invoices.
