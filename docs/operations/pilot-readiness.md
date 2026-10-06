# Scoped pilot configuration readiness

`GET /pilot/readiness/{capability}/{target_id}` requires an authenticated principal
with `usage:read`. Capability is `inspection` or `proving`; target ID must identify
an independently operator-configured target in that principal's tenant. The
request accepts no query selectors, alternate tenant, trust material or proof.
Unknown, wrongly typed and cross-tenant targets produce a failed configuration
check without exposing another tenant's inventory. Admin does not imply this role.

Use a protected authentication-header file, not a token in command arguments:

```bash
curl --fail-with-body --silent --show-error \
  --header @/absolute/protected-auth-header \
  http://127.0.0.1:8000/pilot/readiness/inspection/operator-target
```

Select your actual API origin and configured target. Keep the header file private
(0600); it contains the appropriate bearer or API-key header. API-key pilot access
also needs operator-provided tenant, actor and role settings on the server.

## Meaning of the report

The report uses `clearproof-pilot-readiness-v1` and scope
`configured-target-preflight`. HTTP 200 means every reported check passed; HTTP
503 means one or more failed. Both responses have `Cache-Control: no-store`.
They contain only the capability, clock and fixed booleans, not target IDs,
tenants, paths, addresses, keys, record contents or exception details.

| Check | What is actually checked |
| --- | --- |
| `database` | A real `SELECT 1` through the configured pool |
| `migration_history` | Exactly the migration sequence expected by this software; at most expected versions plus one row are read |
| `storage_key` | The active keyring can seal and open a tiny synthetic value in memory under this tenant; no record is read or written |
| `target_configuration` | Loaded target type and tenant, manifest/profile binding, verifier executable availability, transfer freshness, configured policy, signed valuation and signed root approvals under operator-selected pins |

Proving targets additionally need the configured sanctions tree to match the
approval, supported JavaScript/native backend types, and WASM/proving-key files
of their declared sizes. Native executable existence and execute permission are
checked. These are file metadata checks, not fresh content-hash verification or
proof execution. Configuration mappings are bounded to 256 entries, with direct
lookup of the requested tenant/target.

Database acquisition and work have a two-second application timeout; the
transaction is read-only with a 1.5-second PostgreSQL statement timeout.
Readiness never connects a new pool, runs migrations, creates or repairs tables,
changes policies/roots, decrypts retained customer records, queues jobs or writes
nullifiers. Failures are redacted into the fixed flags. Cancellation propagates;
ordinary timeout/query failures report not ready and release the connection.

## Limits and response to failure

The report always says `current_state_checked: false`,
`authorization_consumed: false` and `production_eligible: false`. It does not
compare configured roots/policy against retained current heads, inspect a holder's
enrollment/revocation, confirm live chain/provider state or worker heartbeat,
measure capacity, pair a proof or establish production artifact assurance. The
API and worker may still differ in configuration or availability.

For DB or migration failure, restore the intended connection/schema and follow
the reviewed migration procedure. The readiness request does not repair it.
For key failure, restore authorized retained key material; generating a new key
does not recover old ciphertext. A passing active-key probe says nothing about
decryptability of retained records under older keys.

For target failure, review the operator target, profile, executable permissions,
artifact bundle, current signed approvals and clocks. Do not replace trust or
disable freshness checks to make it green. Missing and foreign targets share the
same minimized result; check the caller's intended tenant locally.

Combine this preflight with the artifact doctor, an authorized retained-record
read and `POST /pilot/proof/inspect` for the read-only current-state/proof path.
Keep the required decryption/inspection roles separate from `usage:read`.
Authorization consumption is never a readiness probe. Public `/health` remains
process liveness and can return 200 while scoped readiness returns 503.
