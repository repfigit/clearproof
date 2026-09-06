# Current pilot proof inspection API

The source API exposes `POST /pilot/proof/inspect`. This is read-only current
statement inspection, using the same `ProofInspectionService` as internal callers.
It checks real pairing against independently pinned artifacts and reconstructs
expected signals from server-selected transfer/context, valuation, policy and
signed roots. The tenant transaction also checks durable enrollment, revocation,
active policy selection and retained root heads. Inspection writes no records and
consumes no authorization.

An operator provisions `app.state.pilot_inspection_targets` as a dictionary keyed
by `(tenant_id, target_id)`, with `InspectionTarget(configuration, verifier)` values.
The configuration is `CurrentStatementConfiguration`; the verifier is loaded by
`PilotPairingVerifier.load` using inspected artifact and runtime digests. Targets
are explicit transfer configurations, not caller-provided trust inventories.
The default app has no targets and returns 503 until provisioned. Reinstall this
operator configuration on process restart; durable enrollment/root/policy records
remain in PostgreSQL. A serialized provisioning loader is still onboarding work.

The authenticated JWT needs both `proof:inspect` and `evidence:decrypt`. Static
API-key development mode retains the existing fixed operator-assigned tenant and
roles. Unknown targets are looked up only within that authenticated tenant.

The bounded JSON request contains exactly:

- `target_id`: opaque server target selector.
- `credential_id`: opaque enrolled credential identifier.
- `proof_json`: JSON string holding the Groth16 proof (at most 8192 bytes after encoding).
- `public_signals`: eight canonical decimal field strings for pilot-transfer-v2.

The total upload limit is 16 KiB. Duplicate JSON keys, extra fields, legacy signal
vectors and malformed proofs reject with generic diagnostics. The request cannot
set verifier time, executable paths, roots or trust keys. The server samples its
clock for each inspection.

A successful inspection returns `clearproof-current-inspection-v1`, scope
`current-statement-inspection`, `cryptographic_valid`, `proof_profile`,
`manifest_digest`, manifest `assurance`, and `authorization_consumed: false`.
A well-formed proof with failed pairing returns HTTP 200 and
`cryptographic_valid: false`; current trust/context rejection returns 422.
Missing roles return 403, unknown scoped target/enrollment 404, absent server
configuration/database 503, oversized uploads 413. Error bodies omit submitted
proof contents and private records.

A positive pairing result is not a business policy ALLOW, counterparty acceptance,
legal conclusion or settlement evidence. This endpoint does not expose the
state-changing authorization service. Development manifest assurance is retained
in the response. SDK/CLI current inspection and contract parity, durable
observation reports and complete local onboarding remain separate work.
