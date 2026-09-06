# Durable local proof observation

`ProofObservationService.observe` evaluates a current pilot-transfer-v2 proof and
selected retained signed facts using the same tenant-transactional service as
current policy evaluation. It atomically retains an encrypted observation and
its encrypted idempotency result. This source service is a building block for
observation onboarding; it is not yet a complete onboarding command or report UI.

Observation requires `observations:write`, `proof:inspect`, `policy:read` and
`evidence:decrypt`. It does not require or grant `proof:generate` or `proof:consume`.
The operator supplies the same trusted statement/verifier configuration and fact
authority as current inspection. The input contains credential ID, exact proof
bytes, eight signals, retained fact IDs, idempotency key and operator clock.

New immutable `clearproof-proof-observation-v2` records contain:

- Fixed `mode: observation`, `authorization_consumed: false`, and
  `execution: not-requested`.
- Development assurance, actor/tenant scope, observation time and a request digest.
- Integer `evaluation_duration_ns` with `latency_scope: current-evaluation-only`.
- Credential reference, proof/signal digests, transfer/context/policy/artifact
  digests, proof profile and sorted distinct retained fact references.
- Pairing result and the minimized nullable policy evaluation. Successful pairing
  can yield ALLOW, DENY, REVIEW or INDETERMINATE; failed pairing has no policy result.

Record IDs bind the complete stored record. Raw proof bytes, wallets, transfer
amounts, source fact values and raw PII are not added to observation records.
Records and cached responses use the existing tenant record cipher. These are
local encrypted reports, not independently signed historical evidence bundles or
trusted timestamps. Their source references and operator clock do not establish
external truth, latest-source completeness or legal sufficiency.

## Retry and enforcement semantics

Concurrent exact requests with the same actor, operation and idempotency key
produce one observation and one cached result. Fact-reference order is normalized.
A changed proof, context, credential, fact set or actor with the same key conflicts.
A new key creates a new observation even for otherwise identical inputs. These
are logical operation counts, not counts of HTTP deliveries or pairing attempts.

An exact retry after expiry or trust changes returns the original observation
with its original time. It does not rerun acceptance or imply a current ALLOW.
Use a new key for a fresh evaluation, which must pass current checks. Missing
trusted inputs or context rejection writes nothing; a completed failed pairing
can be retained with `policy: null`. Transaction failure rolls back both record
and idempotency result.

Observation never creates a retained authorization proof/receipt or consumes a
nullifier. Its storage kind is separate from `proof`, so the consumption table's
proof foreign key cannot reference an observation, even for a caller with
consumption permission. A stored ALLOW is not an instruction to send a Travel Rule
message or execute a transfer.

`read_observation(db, cipher, principal, observation_id)` requires policy-read and
decryption roles, validates record identity and scope, and returns the original
report or no record within that tenant. It does not select a current policy or
re-evaluate an expired proof.

## Storage and validation

Additive migration 16 allows the immutable `observation` kind. Existing encrypted
records, root revisions, receipts and consumption constraints are preserved.
Deploy readers/writers that understand this version together. A pre-migration-16
binary cannot run against a newer schema; use a forward compatibility fix for
rollback, retaining encrypted observations and the migration history. Do not drop
observation records or relabel them as authorization proofs to roll back code.

The real PostgreSQL gate exercises four synthetic outcomes, completed failed
pairing, concurrent deduplication, explicit fresh observation, changed-request and
actor conflicts, missing write permission, immutable records, consumption foreign
key rejection, transaction rollback, scope isolation, encrypted rows and exact
retrieval after restart/expiry/authority replacement. Development proving keys
remain outside the source package.

Deterministic counterparty scenarios,
integrated clean setup and paid-pilot usage
reporting remain CP-016–018 work. This service alone does not close those gates.

## Authenticated API

The source API now exposes `POST /pilot/proof/observe`. Its private JSON body
extends `/pilot/proof/evaluate` with `idempotency_key`. The same 16 KiB upload
limit, exact proof parsing, eight-signal profile, tenant-scoped operator target
and server-selected fact trust apply. Roles are `observations:write`,
`proof:inspect`, `policy:read` and `evidence:decrypt`; neither proof generation nor
consumption permission is needed. Caller-supplied mode, clock, consumption flag or
trust configuration rejects. The response is the retained observation report.

Concurrent exact requests return the same report. A changed request or actor
under the same key returns 409. Missing current configuration returns 503,
unknown tenant target/enrollment 404, missing roles 403, and malformed input or
current trust rejection 422. Observation does not activate enforcement.

`POST /pilot/proof/observations/read` accepts only `observation_id` in a bounded
1 KiB JSON body and requires `policy:read` plus `evidence:decrypt`. References stay
in the private body rather than a URL path. It returns the retained report or a
scoped 404, with generic input/configuration/integrity errors. This read endpoint
requires storage and encryption configuration but no current inspection target,
root configuration or available proving runtime. Reads after restart therefore
remain possible even when the current target is removed.

The real-proof JWT/PostgreSQL gate covers four HTTP policy outcomes, concurrent
idempotent creation, changed-request conflict, role/tenant isolation, rejected
mode/clock/trust overrides, minimized errors, bounded reads and retrieval in a
replacement app without current targets. Exactly four logical HTTP observations
add eight encrypted observation/idempotency records and zero consumptions.
Observation pagination and the complete onboarding
scenario remain open; these API routes do not close CP-016–018 by themselves.

## Source SDK and CLI clients

Build the source proof and CLI workspaces before using these commands. They are
not included in published npm 0.3.0.

```bash
npm run build --workspace=@clearproof/proof
npm run build --workspace=@clearproof/cli
node packages/cli/dist/index.js observation create --api-url http://127.0.0.1:8000
node packages/cli/dist/index.js observation read --api-url http://127.0.0.1:8000
```

Supply the corresponding private JSON body on stdin and the bearer token through
`CLEARPROOF_API_TOKEN`. `create` accepts the observation API request; `read` accepts
only an observation ID. Successful operations print one validated JSON report and
exit 0 regardless of ALLOW/DENY/REVIEW/INDETERMINATE or failed pairing. Exit 2 and a
generic stderr diagnostic mean the request or returned report was rejected.
These exit codes describe storage/retrieval success, never authorization.

The source SDK exports `createObservation(origin, token, requestBytes)` and
`readObservation(origin, token, requestBytes)`, plus `ObservationRequest`,
`ObservationReport` and `ObservedPolicy` types. Input bytes are preserved for the
server to validate. Both use the shared bounded, non-redirecting authenticated
transport with operator-selected HTTPS or explicit loopback HTTP.

The clients require the exact observation profile, non-enforcement flags and
development assurance. They check policy/transfer/time consistency, sorted unique
references, the relationship between pairing and nullable policy, and the
canonical full-record digest. A read response must match the requested ID.
Unexpected or private extra fields reject. These checks detect record inconsistency;
they do not authenticate an independent historical authority or prove API claims.
The configured API remains the trust boundary.

The real PostgreSQL gate exercises built CLI creation of a fresh DENY observation,
exact retries, reads across all four outcomes, request/role/tenant rejection and
redacted errors. The SDK recomputes Python-generated observation digests. Creating
a DENY observation successfully returns exit 0 and leaves consumption empty.
Pagination, counterparties and clean onboarding remain open.

## Selected-cohort reporting

`POST /pilot/proof/observations/report` requires `policy:read` and
`evidence:decrypt`, accepts at most 16 KiB, and reads immutable records under the
authenticated tenant transaction. It needs no current targets or proving runtime.
The body contains `cohort_id` and 1–64 `cases`, each with:

- `case_id`: an opaque case label, unique in the cohort.
- `observation_id`: a retained digest, or explicit null for a not-yet-observed case.
- Optional `baseline_outcome`: ALLOW, DENY, REVIEW, INDETERMINATE or null.

Duplicate non-null observation IDs reject so one record cannot be counted twice.
Different logical observations of the same transfer may be selected deliberately;
the report exposes distinct observed transfers separately. Unknown or foreign
references are identically unavailable. Malformed/duplicate input returns a
generic 422, oversized input 413, missing roles 403, and storage/configuration
failure 503. A requested reference that cannot be read does not become a policy
outcome.

The deterministic `clearproof-observation-cohort-report-v2` response binds the
normalized selected cohort with `cohort_digest` and sorts case results by case ID.
It reports case, observed, missing, failed-pairing, policy, determinate and
per-outcome counts. `determinate_count` includes ALLOW/DENY/REVIEW; observed
INDETERMINATE is counted as a policy result but not a determinate result. Failed
pairing is an observation with no policy result. Explicitly unobserved and
unavailable records remain distinct per-case statuses.

Baseline labels are marked `caller-supplied-unverified`. Label count includes
labels on missing cases; comparable count includes only labels paired with an
actual policy result. Agreements and disagreements use that comparable subset.
A missing or failed-pairing result is not automatically a disagreement, a DENY or
an ALLOW. These counts compare selected operator labels, not independently verified
customer decisions or legal truth. They do not establish unexplained disagreement
causes, representative population coverage or commercial value.

For example, four selected observations with one of each policy outcome and two
missing cases produce six cases, four observations, four policy results and three
determinate results. If only three observed results have baseline labels, only
those three enter the agreement/disagreement denominator. Multiple observations
of one transfer still count as one distinct observed transfer.

No record or consumption is written. Raw proof bytes, wallets, fact values and
observation source references are omitted from the returned case summaries.
Broader cohort discovery/pagination and integrated
onboarding remain open.


## Versioned evaluation duration

New observations use record v2 and digest domain `clearproof/proof-observation/v2`.
They measure `time.monotonic_ns()` immediately before and after current evaluation
inside the tenant transaction. The interval includes retained-fact checks, current
statement/pairing and policy evaluation. It excludes upload/authentication, request preflight, waiting
for the tenant lock, observation/idempotency writes, response transfer and external
custody or counterparty latency. The explicit scope is `current-evaluation-only`.
Durations are integer nanoseconds from 0 to 60 billion; an out-of-profile result
rejects retention. Existing transaction/runtime deadlines still apply.

The timer runs only on a new logical observation. Exact retries return the retained
duration and are not added as fast zero-duration samples. Completed failed pairing
can have a duration without a policy result. Requests rejected before retention
have no observation duration and are outside this measurement sample.

Existing v1 records retain their original bytes, IDs and lack of duration. Version
routing reads both v1 and v2; cached v1 results remain v1 when returned by the new
writer, including after expiry. No migration or rewrite of encrypted records is
needed. The updated SDK/CLI validates both versions and their respective digest
domains. Older v1-only clients reject new v2 records, so update clients with writers.
The observation record version is separate from the unchanged pilot-transfer-v2
circuit profile and proving artifacts.

Cohort report v2 adds a `latency` object with scope, measured count, unmeasured
observed count, unmeasured case count, and integer total/minimum/maximum duration.
The mean, when measured count is nonzero, is the total divided by that count.
`latency_status` is complete only when every selected case is measured, partial
when some are measured, and not-recorded when none are measured. Empty sample
aggregates are null, not zero; old records and missing cases never enter timing
aggregates. The maximum cohort and duration bounds keep totals within JavaScript's
safe-integer range.

Tests combine v1 and v2 records, preserve legacy cached results, validate measured
real-proof records through the built CLI, and check exact cohort duration sums.
These local development measurements describe the selected completed evaluations;
they are not production performance claims, independent time attestations or an
end-to-end service-level objective.

## Cohort report clients

The source SDK exports `reportObservationCohort(origin, token, requestBytes)` and
typed `ObservationCohortRequest` / `ObservationCohortReport` models. The CLI exposes:

```bash
node packages/cli/dist/index.js observation report --api-url http://127.0.0.1:8000
```

Supply the cohort JSON described above on stdin and `CLEARPROOF_API_TOKEN` in the
environment. Only policy-read and decryption roles are needed. Exit 0 means the
report request succeeded, including a report with disagreements or no available
observations. Request/response rejection uses exit 2 and generic stderr, with no
private body or bearer token echoed.

Clients normalize the cohort for digest comparison while sending the original
JSON bytes to the API. Duplicate cases/references, unsupported labels and oversized
inputs reject. Returned cohort ID/digest, case identities, baseline labels and
case order must match the normalized request. Exact profile/field checks reject
unexpected claims or private extra fields. Clients verify count arithmetic,
missing/failed-pairing semantics, baseline denominators, timing coverage and
bounded integer duration aggregates. Null measurements cannot silently become
zero values. Distinct-transfer counts and timing totals remain server-supplied
facts; the client checks their consistency/bounds, not independent source truth.

The built-command PostgreSQL gate compares CLI output with the actual API report,
including measured records, missing cases, baseline disagreements and foreign-tenant
unavailability. Reporting leaves encrypted record counts and consumption unchanged.
Cohort discovery/pagination, deterministic bilateral scenarios, complete onboarding
and commercial preparation remain open.
