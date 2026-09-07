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
The read-only reconciler below queries that hash against independent chain policy
and distinguishes pending, included, noncanonical and confirmed execution. A
journal row alone is insufficient evidence for any chain outcome. Durable worker
transitions and replacement identification remain unimplemented. Database reservation and chain state are
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

## Read-only chain reconciliation

`PublicationReconciler` consumes the retained journal identity and a separately
configured `PublicationChainPolicy`. That policy pins the chain ID, registry
address, runtime SHA-256, observation tag, minimum confirmations and maximum block
age. A pin copied from an untrusted RPC is not an independent approval. The local
EVM fixture captures its pin from its own newly deployed test contract; production
operators must use independently reviewed deployment evidence.

The reconciler checks both the policy and retained binding, recovers the journal's
account nonce, and compares the observed transaction's hash, sender, destination,
chain, nonce, zero value and calldata digest. A receipt must bind the same transaction
and inclusion block. Its block hash must match the provider's canonical block and
contain the exact transaction at the receipt's index. Runtime is checked at the
observation anchor and inclusion block. Before returning an included outcome, both
headers and the receipt are read again to reject a changing observation.

A successful transaction also requires exactly one matching registry event and
matching registry state at inclusion. Publication binds the tenant and statement
ID; mirroring binds the tenant, statement, receipt and retained nullifier. Event
presence alone cannot prove the state lookup, and a successful EVM receipt alone
cannot prove the intended registry operation occurred.

| Status | Meaning at this provider observation |
| --- | --- |
| `not-found` | The retained hash was not found; this does not establish that it was never sent or that its nonce is reusable. |
| `pending` | The exact transaction is known without inclusion or a receipt. |
| `noncanonical` | Reported inclusion disagrees with the canonical block at that height. |
| `awaiting-confirmations` | Inclusion and execution were observed, but the selected confirmation policy is not met. |
| `confirmed-success` | Matching successful execution, event and registry state meet the selected confirmation policy. |
| `confirmed-failure` | Matching reverted execution meets the selected confirmation policy. |

The default tag is `finalized`. Unsupported tags fail; there is no automatic
fallback. With `latest`, confirmations are depth observations, not consensus
finality. With `safe` or `finalized`, depth is measured relative to that selected
anchor. Reports retain the tag and block hashes so those assurances remain distinct.
The RPC/provider remains trusted for chain data; this is not a consensus light client.

Every report sets `current_authorization=not-evaluated` and
`resubmission=not-authorized`. Registry effects describe inclusion-time state,
not fresh source eligibility or continued current-head approval. Reconciliation
neither clears a broadcast claim nor writes journal state, sends a transaction,
allocates another nonce or authorizes a transfer. Identifying replacement hashes,
resolving a crash before send and controlled replacement remain worker tasks.

The joined EVM gate exercises not-found, one-block awaiting-confirmations and
two-block confirmed-success for both actual publication and mirroring. Unit tests
cover pending, reverted and noncanonical observations, missing/wrong events, scope
and calldata substitutions, missing state, stale blocks and reorg during read-back.
