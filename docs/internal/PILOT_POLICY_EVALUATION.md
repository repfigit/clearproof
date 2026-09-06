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
This enables later policy diff while preserving the original record. Replay is
not current policy activation or transfer authorization; `PolicyTrustStore`
performs independent current-version selection for the proof-input path.

Tests cover reproducible replay without input mutation, smallest-unit boundaries,
missing facts below a threshold, deny/allow conflict, review for incomplete
information, unsupported predicates, invalid timing, empty policies and foreign
or conflicting evidence. Durable fact authentication, rule-approval history,
API/CLI reports and the policy-diff workflow remain integration work.
