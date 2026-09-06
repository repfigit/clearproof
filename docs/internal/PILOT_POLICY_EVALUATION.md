# Read-only policy evaluation

`src.policy.evaluator.evaluate_policy(policy, transfer, context, facts, now=...)`
replays a bounded rule set over supplied evidence. It performs no network,
storage, signing, payment, settlement or authorization-consumption operation.
The caller must authenticate the tenant, policy, quote and evidence snapshot.
Evidence hashes identify inputs; their presence does not prove source truth.

Rules are part of the immutable `PilotPolicy` digest. Up to 64 unique rules use
boolean predicates or exact unsigned USD-cent comparisons (`below`, `at_least`).
Each rule references reviewed sources already present in the policy. No eval,
expressions, arbitrary code or unbounded recursion is supported. Unknown boolean
predicates are retained as unsupported, not silently evaluated as false.

The pilot requires fresh evidence for applicability resolution, credential
validity, sanctions clearance, counterparty trust, required-information
completeness and valuation authentication before ALLOW is possible. This is a
minimum data-completeness profile, not a claim to enumerate all legal duties.
A low amount never bypasses these checks. Amount comparisons also require an
authenticated-valuation fact. The pairing result is a separate decision; proof
validity is an optional explicit policy predicate, not inferred here.

Scope mismatch or conflicting duplicate facts rejects the input. An expired or
not-yet-effective policy/transfer/source/context yields INDETERMINATE. Under an
active policy, a definite matching DENY rule takes precedence; otherwise missing,
stale/future or unsupported facts and unresolved applicability yield
INDETERMINATE. Next come matching REVIEW rules or incomplete required checks,
then a matching ALLOW rule. No decisive rule produces INDETERMINATE. Conflicting
matched effects are recorded even when precedence resolves the outcome.

Outputs contain policy/transfer digests, evaluation time, outcome, sorted matched
rule IDs, missing and unsupported predicates, reason codes and a conflict flag.
They omit raw wallets, amounts and fact values. Keep these operational reports
inside the authenticated tenant boundary: rule IDs and decisions can themselves
reveal sensitive information. They are not public proof signals or SAR notices.
ZK coverage is explicitly `not-established`; business rules are not automatically
asserted to be enforced by the circuit.

Counterfactual replay may evaluate a candidate policy digest against the original
transfer snapshot without editing that transfer's historical policy reference.
It still checks tenant, deployment, jurisdiction, catalog and context consistency.
Policy comparison uses this replay while preserving the original record. Replay is
not current policy activation or transfer authorization; `PolicyTrustStore`
performs independent current-version selection for the proof-input path.

Tests cover reproducible replay without input mutation, smallest-unit boundaries,
missing facts below a threshold, deny/allow conflict, review for incomplete
information, unsupported predicates, invalid timing, empty policies and foreign
or conflicting evidence. Durable fact authentication remains integration work;
the retained policy review service is described below.

## Counterfactual comparison API and CLI

`src.policy.diff.compare_policies` accepts `PolicyDiffRequest` with `before` and
`after` policies and 1–64 cases. Each case supplies `case_id`, `transfer`,
`context`, `facts` and `evaluated_at`. Policies must share tenant, deployment,
jurisdiction and asset catalog. Duplicate case IDs or tenant/transfer business
identities reject the entire batch, even if nonces differ. Cases are sorted by
case ID so input ordering cannot change the report.

Run `python -m src.policy.diff` with comparison JSON on stdin. It emits a
`clearproof-policy-diff-v1` JSON report on stdout; rejected input emits a generic
error and exits 1. Feed confidential input from an authorized encrypted source
through a pipe; do not put customer data in command arguments or plaintext files.

`POST /pilot/policy/diff` accepts the same JSON through the authenticated API.
The verified principal requires both `policy:read` and `evidence:decrypt`; all
policy and case tenants must match that principal. Uploads are limited to 1 MiB
and ten seconds, and both interfaces reject duplicate JSON keys. HTTP errors
omit submitted values. The endpoint performs no persistence or external calls.
The report remains tenant-private, including its case IDs and diagnostic rules.

Reports include before/after decisions, missing and unsupported predicates,
explicit `not-established` ZK coverage, cases entering/leaving review, review
counts and delta, indeterminate counts and changed decision/explanation flags.
`changed_rule_ids` identifies edited definitions and changed matched-rule IDs;
it is a candidate explanation, not a minimal causal attribution. Both matched
rule lists remain available. Editing a matched rule under the same ID changes
the explanation flag even if its final decision is unchanged.

This is a supplied-case simulation, not a workload forecast. It does not prove
snapshot authenticity, activate policies, consume transfer authorization or
alter original evidence. The service below retains reviewed expected outcomes
and approvals. Source-document retention, activation history and a packaged
TypeScript CLI command remain open CP-011 integration.
Tests exercise real stdin subprocesses and signed JWT requests, tenant and role
rejection, bounded/malformed input, deterministic ordering, business-identity
deduplication, reverse review counts and same-ID rule edits.

## Retained policy reviews

`src.services.policy_review.PolicyReviewService.approve` stores an immutable
approval through the encrypted tenant store. Its operator-authenticated
principal needs `policy:approve` and `evidence:decrypt`. The service records the
principal's actor ID and the supplied server clock; API callers must never
choose either identity or approval time. The authenticated route below supplies
them from the token and server clock.

Each request contains one policy and 1–16 reviewed cases with independently
specified expected outcomes. Evaluation must match every expectation before
anything is written. Unique case/business-transfer IDs prevent duplicate review
counts; future case observations and currently inactive policies reject.
Case snapshots are retained separately under domain-separated digests, and the
approval retains their digests, expectations and actual evaluation reports.
All records, including source references inside the policy, are encrypted.
The complete approval must fit the existing bounded canonical storage profile.

A successor requires an already retained approval for its exact predecessor,
with matching policy identity/scope, consecutive revision and nondecreasing
approval time. Case records, approval and idempotency result share one tenant
transaction. Retries return the original approval timestamp; another actor or
changed request cannot reuse the same idempotency key. One immutable approval
is retained per policy digest. This permits draft branches and does not choose
which branch is current: independent activation and historical activation
receipts remain separate work.

The review attests the authenticated reviewer's action, not external source
truth or independent legal assessment. Actual source documents, authenticated
fact acquisition, independent activation and offline historical approval
verification remain open. PostgreSQL tests
exercise reconnect persistence, encrypted rows, tenant isolation, predecessor
links, immutable approval conflicts and rejected expected outcomes.

## Authenticated retained-record endpoints

`POST /pilot/policy/approve` accepts `{ "review": { "policy": ..., "cases":
[{ "case": ..., "expected": "ALLOW" }] }, "idempotency_key": "opaque-key" }`.
It requires `policy:approve` and `evidence:decrypt`. Actor/time fields in the
request are rejected. The service uses the configured database and encryption
keyring; missing dependencies return 503. Conflicts return 409; invalid reviews
return generic 422 errors without submitted values. Approval is not activation.

`POST /pilot/policy/diff/stored` accepts `before_digest`, `after_digest` and
`case_digests` (1–64 unique digests). It requires `policy:read` and
`evidence:decrypt`. It loads encrypted approvals and cases in a tenant
transaction, validates their schema markers and recomputed content digests,
then runs the same counterfactual comparison as `/diff`. Missing records and
records belonging to another tenant both return 404. Duplicate cases reject.
This operation writes no records and consumes no authorization. Historical
case evaluation times are preserved; the result is not current authorization.

Both endpoints enforce the same 1 MiB/ten-second input bounds as supplied-case
comparison and reject duplicate JSON keys. Reports still omit wallets and raw
amounts. Cases come from authenticated retained review actions, whose source
truth remains the reviewer's responsibility. Retained source documents and
independent historical trust verification remain separate work.
