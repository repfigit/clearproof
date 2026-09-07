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
remain in PostgreSQL. The local acceptance runner supplies synthetic configuration;
a serialized operator provisioning loader is not supplied by this pilot.

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
in the response. SDK/CLI inspection is described below;
[observation](PILOT_OBSERVATION_MODE.md),
[authorization](PILOT_AUTHORIZATION.md) and
[contract mirroring](PILOT_CURRENT_REGISTRY.md) have separate implemented boundaries.

## Source SDK and CLI

Build the source workspaces first; these additions are not part of public npm
0.3.0:

```bash
npm run build --workspace=@clearproof/proof
npm run build --workspace=@clearproof/cli
node packages/cli/dist/index.js inspect-current --api-url http://127.0.0.1:8000
```

Provide the request JSON described above through stdin and the bearer token via
`CLEARPROOF_API_TOKEN` in the process environment. The command prints only the
validated report to stdout. Exit 0 means the API reported successful current
pairing, 1 means failed pairing, and 2 means the request or response could not be
accepted. None of these exit codes conveys an authorization or policy ALLOW.
Failures use a generic stderr message without request/response bodies or tokens.

SDK callers can use the same thin remote inspection adapter:

```typescript
import { inspectCurrentProof, type CurrentInspectionRequest } from '@clearproof/proof';

// request has target_id, credential_id, proof_json and eight public_signals.
const request: CurrentInspectionRequest = preparedRequest;
const report = await inspectCurrentProof(
  operatorApiOrigin,
  bearerToken,
  Buffer.from(JSON.stringify(request)),
);
```

`inspectCurrentProof` also accepts exact `Uint8Array` JSON bytes, preserving
ambiguous/duplicate keys for the server to reject. It bounds the upload to 16 KiB,
uses the shared bounded authenticated transport, refuses redirects and requires
HTTPS except for explicitly selected loopback HTTP. API origin selection belongs
to the operator; this transport is not a general-purpose untrusted URL fetcher.
Responses must match the exact current inspection schema, eight-signal v2 profile
and development assurance; additional/private fields and unexpected assurance
claims reject. Future profiles require an explicit client update.

The SDK delegates current acceptance to the selected API. It does not independently
verify API claims or reproduce Python business rules. The real PostgreSQL gate
with `CLEARPROOF_POLICY_CLI_TEST=1` exercises built Node CLI → SDK → HTTP → JWT →
current service/pairing, covering success, failed pairing, tenant/role rejection
and input-error redaction. The isolated development-artifact CI job enables this
gate. The [acceptance audit](../plans/adoption-pilot-acceptance-audit.md) records
the evidence for current authorization, contract parity and observation separately.

## Read-only current policy evaluation

`POST /pilot/proof/evaluate` uses the same target, proof parser and current-state
service. It additionally requires `policy:read` and an operator-configured
`InspectionTarget.fact_trust` (`FactTrustStore`). An absent fact authority returns
503; requests cannot provide or override that authority.

The request extends the inspection body with required `fact_ids`, an array of at
most 64 distinct retained fact-evidence digests. An empty array is allowed and
lets the policy report explain missing facts. References are loaded only in the
authenticated tenant; each signature, transfer/context binding, source authority,
validity interval and known compromise is checked under the configured trust.
Malformed, duplicate, unavailable or untrusted references return 422. Facts are
not accepted as request-body assertions.

The response is `clearproof-current-evaluation-v1`, scope
`current-policy-evaluation`, with `authorization_consumed: false`, manifest
`assurance`, nested `inspection` and nullable `policy`. Successful pairing enables
the normal minimized policy report: ALLOW, DENY, REVIEW or INDETERMINATE, with
policy/transfer digests, server evaluation time, matched rules, missing predicates
and reasons. `zk_coverage: not-established` preserves the distinction between the
circuit statement and Python policy evaluation. Failed pairing returns
`policy: null`; it must not be interpreted as ALLOW or as missing-fact evaluation.

This evaluates the selected retained evidence at the server clock. It does not
assert that those references exhaust all source observations or discover newer
external facts. The caller can compare eligible retained fact sets, but cannot
change their signatures or the operator's authorities. The synthetic integration
scenario uses explicitly signed alternative fact sets to exercise all four
outcomes; it does not validate external data truth or regulatory sufficiency.

Neither endpoint writes an observation record, signs a decision receipt, consumes
a nullifier, sends a Travel Rule payload or executes a transfer. Durable observation
mode and authorization use the separate services linked above. The
current source SDK/CLI adapter described above exposes inspection only; evaluation
client support is not implied by this API addition.
