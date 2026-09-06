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

Each immutable `clearproof-proof-observation-v1` record contains:

- Fixed `mode: observation`, `authorization_consumed: false`, and
  `execution: not-requested`.
- Development assurance, actor/tenant scope, observation time and a request digest.
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

Observation API/CLI orchestration, deterministic counterparty scenarios,
coverage/disagreement/latency reports, integrated clean setup and paid-pilot usage
reporting remain CP-016–018 work. This service alone does not close those gates.
