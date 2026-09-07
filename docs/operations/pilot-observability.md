# Pilot observability and operator runbook

Use authenticated, scoped reports to assess the pilot. A successful HTTP response
is meaningful only within that endpoint's scope; it does not imply current
compliance, counterparty acceptance, settlement or production readiness.

## What can be observed now

| Surface | Meaning and access | Operational limit |
| --- | --- | --- |
| `GET /health` | Public process-liveness response, software version and server clock | No database, key, artifact, trust, chain or provider readiness checks. HTTP 200 alone is not readiness. |
| `GET /metrics` | Legacy configured SIWE/JWT/API-key-protected process-local debug counters and uptime | Counters reset on restart and are not wired to the pilot services. Zero is not evidence that no pilot operations occurred. No Prometheus/OTEL exporter is configured here. |
| `GET /pilot/usage` | `usage:read`; one tenant-scoped database snapshot of encrypted records, bytes, observations, events, proofs, receipts, policy versions and consumed nullifiers | No decryption; a successful response checks this database path only. Excludes publication journal/history tables. Not a billing ledger, HTTP request count or adoption metric. |
| Observation discovery/read/cohort report | Policy-read/decryption roles; durable scoped observations, four outcomes, coverage, disagreement and latency | Evaluation timing excludes end-to-end onboarding/transport/settlement. Missing and old v1 timings remain unknown. See [observation semantics](../internal/PILOT_OBSERVATION_MODE.md). |
| Investigation timeline/queue | Evidence-read/decryption roles; independent states, aged findings, owners, next actions and scoped provider links | Queue pages are separate observations, not one frozen snapshot. Exhausted page budgets are partial; follow the continuation cursor. No findings does not authorize a transfer. |
| Artifact doctor | Read-only pin/profile/size/hash diagnostics with explicit development assurance | Does not check current sources, source truth or production eligibility. Matching files are not a trusted setup. |
| Publication journal/recovery service | Authenticated retained intent, pinned chain observation and encrypted reconciliation history | Inclusion-time effects are not current authorization. The journal is not included in `/pilot/usage`; consult its own service/runbook. |
| Offline historical report | Separately configured reviewer trust, exact encrypted export and declared review time | Supported/contradicted/indeterminate applies to recorded local evidence. It never authorizes replay or establishes live provider status. |

There is no single aggregate readiness endpoint. For an operator's configured
pilot, combine process liveness with authenticated database access, an authorized
encrypted-record read, artifact inspection and the read-only current inspection
path. Each must use independently supplied tenant, deployment and trust inputs.
Do not use authorization consumption as a health probe. The disposable
[acceptance run](local-pilot-acceptance.md) exercises the complete synthetic path;
it does not validate production/customer configuration.

## Investigation workflow

1. Select the tenant and authorized transfer scope; keep bearer tokens and private input on the documented private input channels. Run `investigation timeline` or `investigation queue` with the operator-selected API origin.
2. Record the report's clock, source clocks, independent states and evidence references. Do not infer chain finality from custody completion, or execution from an ALLOW observation.
3. Follow the finding's owner/next-action fields. Select queue age thresholds as operational policy, not as an inferred legal grace period. Follow all required continuation pages and record whether traversal was partial.
4. Use scoped provider links only for navigation to independently approved provider sites. The API/CLI do not fetch them; their presence does not authenticate remote evidence.
5. Compare a later report with the retained evidence. Source ordering, duplicate delivery and a change in observed canonical block have explicit semantics; preserve earlier observations instead of overwriting them.

See [reconciliation and permissions](../internal/PILOT_RECONCILIATION.md) and
[Fireblocks intake](../internal/PILOT_FIREBLOCKS_ADAPTER.md) for source authority,
exact-byte signatures, transfer binding and bounded retention.

## Failures and response

| Signal | Operator action |
| --- | --- |
| Startup rejects storage key or keyring | Restore the independently configured valid key material. Do not generate a replacement key and assume it decrypts existing rows. Keep key values out of diagnostics. |
| HTTP 401/403 | Check the intended authentication mode, tenant, actor and required roles. Admin does not implicitly grant decryption/consumption. Do not work around rejection by changing the request tenant. |
| Pilot HTTP 503 | Inspect the endpoint-specific minimized reason and authorized server configuration: database connection/migrations, key availability, configured verifier/targets/authorities or provider-link catalogue. `/health` may still return 200. |
| HTTP 404 or unknown/missing evidence | Check the caller's scope and retained reference. Absence is not permission to accept, reconstruct another tenant's record or invent source status. |
| HTTP 409/idempotency or consumption conflict | Compare actor, operation, key and exact normalized request. Retrieve an authorized historical receipt where appropriate. Do not create new keys merely to bypass a consumed authorization or clear retained nullifiers. |
| HTTP 422/current trust rejection | Review version/profile, exact context/amount units, source freshness, enrollment/revocation, policy and artifact pins through authorized diagnostics. Do not substitute caller-provided expected values or disable a check to obtain ALLOW. |
| Missing/late/failed counterparty or custody result | Keep the independent state unresolved and follow the queue's owner/next action. A timeout or unsupported version does not permit an information/encryption downgrade. |
| Uncertain publication send or noncanonical chain observation | Retain the original intent/hash and use the [publication runbook](../internal/PILOT_PUBLICATION_JOURNAL.md). Observation alone cannot authorize resend. Explicit same-byte recovery has fresh checks and a three-attempt total cap; fee/nonce replacement is unsupported. |
| Export/history rejection | Check exact binding, retained keys, manifest/runtime pins, source/status/timing evidence and selected review clock. Keep contradicted and indeterminate distinct; never convert decryption success into historical support. |

## Measurements and privacy

Predeclare cohort membership and baseline labels. Keep observed/missing counts,
comparable labels, agreement/disagreement and measured/unmeasured latency in the
same scoped report; do not silently remove hard cases from denominators. Report
actual evaluation duration with its scope. Record onboarding/diagnosis time and
repeat operator use through the [measurement worksheet](../commercial/measurement-worksheet.md),
with the method and missing measurements explicit. These are inputs to a pilot
experiment, not demonstrated willingness to pay or an SLA.

Retain only authorized encrypted exports and minimized reports. Never log bearer
or private keys, raw person information, decrypted payloads, raw signed-provider
bodies or request bodies to debug failures. Avoid high-cardinality customer IDs
in shared metric labels. The local runner's `private/` and PostgreSQL data/logs
are not shareable report artifacts. Use the explicit report-only inventory and
protected file permissions documented in the setup guide.

Local clock age, source assertions, server-supplied durations and trusted chain
provider observations have their documented limits. No alert threshold or metric
in this guide establishes legal compliance or production assurance. Managed
telemetry/retention, live provider access and customer acceptance remain governed
by the explicit follow-on gates, not inferred from these local reports.
