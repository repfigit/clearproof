# Operational usage inventory

`GET /pilot/usage` returns a `clearproof-usage-inventory-v1` snapshot for the JWT's
tenant. It requires the dedicated `usage:read` role; policy-read or decryption
permission does not implicitly grant it. The endpoint reads metadata only and
does not require a decryption role. Tenant query selectors reject. Database
unavailability returns 503; missing authentication/permission returns 401/403.

The response includes `tenant_id`, operator-clock `sampled_at`,
`scope: retained-tenant-records`, `billing_status: not-an-invoice` and these integer
counters. One SQL statement reads a consistent database snapshot across records
and consumptions. No records, secrets, encryption-key IDs or source payloads are
returned, and reading the endpoint writes nothing. Publication journal and
publication-history rows are outside this inventory.

| Counter | Exact unit |
| --- | --- |
| `encrypted_records` | Retained rows in pilot_records, including historical revisions, chunks and idempotency results |
| `ciphertext_bytes` | Sum of stored ciphertext byte lengths, including encryption tags; excludes nonce/metadata, indexes, database overhead and backups |
| `retained_observations` | Rows with observation kind, including both v1 and v2 |
| `retained_events` | Rows with event kind; not delivery attempts or verified external notifications |
| `retained_proofs` | Rows with proof kind; not a count of independently valid proofs or executions |
| `retained_receipts` | Rows with receipt kind; not settled transfers |
| `retained_policy_versions` | Rows with policy kind; not policy activations |
| `consumed_nullifiers` | Tenant entries in pilot_consumptions; not payment/settlement confirmations |

## Retry and deduplication semantics

An exact observation retry returns the original idempotency result and adds no
rows. A fresh logical observation key can add an observation and its cached result,
even for the same transfer; it is not a distinct-transfer or user count. A changed
request under the same key conflicts. Event delivery deduplication likewise
preserves the retained event rather than counting each retry as another event.
Proof/receipt creation and source-evidence retention can add multiple rows, so
`encrypted_records` must not be presented as transfer volume. Nullifier consumption
is unique within a tenant. Reads, cohort reports and read-only exports do not
increment these counters.

These are current retained inventories, not append-only time-window billing events.
Administrative retention/deletion or restoration can reduce/change the snapshot.
Subtracting snapshots is not a reliable activity or invoice calculation when those
operations occur. Old policy/root revisions and content-addressed evidence chunks
have different units from logical observations. Provider evidence chunks must not
be charged as separate provider messages.

Use this inventory to understand operational footprint.
It does not compute charges, grant free tiers, enforce quotas, create invoices or
integrate a payment processor. Any later variable-price contract needs a separate
agreed billable event definition, period boundary, durable ledger, correction and
reconciliation process. Outcome labels do not alter a chargeable unit.

Real PostgreSQL/API checks cover zero inventory, concurrent deduplicated event
retention, changed-request conflict, foreign-tenant data, reconnect, metadata-only
permission, rejected query selection and unchanged counts after reading. The
underlying storage/authorization tests cover unique consumption and observation
retry behavior. This inventory does not establish customer adoption or revenue.
