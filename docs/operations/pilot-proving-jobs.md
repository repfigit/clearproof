# Durable pilot proving jobs

`POST /pilot/proof/jobs` queues current `pilot-transfer-v3` proving work in
PostgreSQL and returns `202 Accepted` with an opaque `job_id`. A separately
supervised Linux worker reconstructs a witness from retained enrollment and
registrar inventories, generates and pairs a proof, and retains its result in
encrypted storage. The API process does not start proving subprocesses.

These jobs are development pilot evidence, not regulatory assurance or transfer
authorization. Generating a proof does not consume a nullifier. Current policy
evaluation and authorization remain separate operations. The legacy
`POST /proof/generate` keeps its existing synchronous behavior; its 16-signal
profile is not interchangeable with these eight-signal jobs.

## Configure both services

The API and every worker need the same PostgreSQL database, stable PII keyring,
and operator-owned target configuration. Set `PILOT_PROVING_FACTORY` to an
installed Python callable, for example `operator_pilot:configure`. This is
trusted deployment code, never a module, executable or path supplied by a user.
The callable accepts `(Database, RecordCipher)` and returns a mapping from
`(tenant_id, target_id)` to `src.services.proof_jobs.ProvingTarget`, synchronously
or asynchronously. Configure between 1 and 256 targets.

A target contains `CurrentStatementConfiguration`, a `PilotProver` loaded with
independently pinned artifact and JavaScript runtime digests, and the exact
approved `PilotSanctionsTree`. Load private business records from encrypted
tenant storage; do not create plaintext configuration files containing transfer
facts. Trust, current root approvals, valuation approval, policy and deployment
context are operator inputs. Request bodies cannot replace them. Factory loading
rejects tenant mismatches, artifact-context mismatches and a sanctions root that
differs from its configured approval.

Start the API normally, then run a separately supervised worker:

```bash
uv run python -m src.prover.proof_job_worker
```

Both services fail startup if a configured factory cannot load. A worker also
requires at least one configured target. Without the factory the API's proving
routes have no available targets. PostgreSQL migrations add `proof_job_control`
and `proof_jobs`; no Redis service is required.

Workers handle one job at a time. PostgreSQL persists the shared admission and
concurrency limits, including across replicas. Defaults are one concurrent job,
256 pending jobs globally and 32 per tenant. Configure them with the trusted
operator operation `ProofJobQueue.configure(max_concurrent=..., max_pending=...,
max_tenant_pending=...)` before running workers. Allowed bounds are 1–4,
1–1024 and 1–64 respectively. Reconfiguration refuses active workers. Measure
host capacity and queue wait time before increasing these values; the default
pending limit does not promise that every admitted job will finish before expiry.

## Request and retrieve

Every operation requires freshly authenticated `proof:generate`, `policy:read`
and `evidence:decrypt` roles. There is no implicit administrator override. The
tenant and actor come from verified authentication, not the request body.

Send a bounded private JSON body to `POST /pilot/proof/jobs`:

```json
{
  "target_id": "synthetic-target",
  "credential_id": "synthetic-enrollment-id",
  "holder_secret": "123456",
  "idempotency_key": "synthetic-job-001"
}
```

Those example values are synthetic; the credential must exist in the tenant's
retained enrollment inventory. Holder secrets are nonzero canonical BN254 scalar
strings. Use opaque identifiers without personal data. Uploads are bounded to
2 KiB and ten seconds; duplicate JSON keys, extra fields and query overrides are
rejected without echoing private input. TLS and deployment access controls are
operator responsibilities.

The admission response includes job metadata and a `Location` header. Poll
`GET /pilot/proof/jobs/{job_id}`. Status is `queued`, `proving`, `cancelling`,
`completed`, `failed` or `cancelled`. A different tenant or actor receives `404`.
A full global or tenant queue returns `429` with `Retry-After: 5`, rather than
pretending the request was admitted. Job responses use `Cache-Control: no-store`.

On successful fresh retrieval, `result_available` is true and `result` contains
`proof_json`, exactly eight `public_signals`, and the artifact manifest's
`assurance`. Retrieval rechecks current enrollment/revocation, approved root
heads, policy activation, valuation, context and time. An expired or stale
completed job remains retained evidence, but returns `result_available: false`
with a stable `result_error` and no proof bytes. Never treat `completed` alone as
permission to transfer funds or consume authorization.

The encrypted request pins the selected transfer, context, approvals, artifact
manifest and runtime. Replacing a target under the same ID cannot silently
retarget a queued proof. The worker checks current business state before proving,
then rechecks under the tenant transaction before committing a result. No long
tenant transaction is held during expensive proving.

## Cancellation, retry and recovery

`POST /pilot/proof/jobs/{job_id}/cancel` and
`POST /pilot/proof/jobs/{job_id}/retry` accept an empty body or literal `{}`.
They do not accept replacement inputs, deadlines or attempt resets. Completed
jobs cannot be cancelled or retried (`409`). A queued cancellation is immediate.
A running cancellation returns `202` with `cancelling`; its global slot remains
occupied until the worker has killed and reaped its subprocess and acknowledged
cleanup, or the fenced lease expires after a worker failure.

Jobs keep their original exclusive deadline: at most five minutes after the
verification context, bounded by transfer and root approval expiry. Proof and
credential lifetimes may impose an earlier effective cutoff. Retrying never
extends this deadline. There are at most three claims per job, with exponential
backoff for transient prover/worker failures. Invalid current state and changed
configuration fail without automatic retry; a manual retry still requires fresh
roles, remaining attempts, a live original deadline and queue capacity.

Workers heartbeat a 30-second database-clock lease every two seconds, with a
five-second database observation timeout. Losing the lease, storage connectivity,
cancellation or deadline cancels the owned operation before acknowledging a
failure. A fencing token prevents old workers from publishing after recovery.
SIGTERM/SIGINT wait for cleanup. Linux parent-death protection kills Node if its
worker is killed without running Python cleanup. Expired leases are recovered
on the next claim/admission operation; there is no separate scheduler dependency.
An uncertain completion write is never blindly repeated.

## Private data and resource limits

Requests, principals, holder secrets and results use the versioned `RecordCipher`
with tenant/job/purpose binding. Only opaque IDs, status, lease and deadline
metadata are plaintext. Private witnesses are reconstructed in memory; proving
inputs travel through stdin. The worker does not write plaintext input, witness
or proof files. Temporary runtime files contain only public pinned source.
Subprocess arguments and environments do not contain holder inputs. Runtime
stderr and private exception details are not returned or logged.

The Node heap bound defaults to 1536 MiB and is configurable from 256–4096 MiB
when the operator loads `PilotProver`. This is not an RSS bound. Set independent
container/cgroup memory limits, disable swapping sensitive memory, and disable
core dumps for the API and worker parents as well as the proving child. The
launcher sets the child's core limit to zero. Do not claim production throughput
or memory capacity from a single development proof.

Database leases bound admitted logical work. Arbitrarily frozen or partitioned
hosts require independent supervision and fencing; SQL leases alone cannot
guarantee a physical subprocess cap under every host failure. Keep replica and
host resource limits within measured capacity. Configure database backups and
PII key retention as encrypted evidence storage requires. Job rows retain
evidence for 24 hours and are purged by subsequent queue maintenance operations;
backup retention is a separate operator policy.

## Verify locally

Use owned synthetic PostgreSQL and an explicit unapproved development artifact
bundle; never use real customer records or commit development proving keys.

```bash
uv run python -m pytest tests/unit/test_pilot_prover.py \
  tests/unit/test_proving_configuration.py tests/unit/test_proof_job_worker_command.py -q
uv run python -m pytest tests/integration/test_proof_job_queue.py \
  tests/integration/test_proof_job_worker.py tests/integration/test_proof_job_api.py -q
uv run python -m pytest tests/integration/test_pilot_proving.py \
  tests/integration/test_proof_job_acceptance.py -q
```

Integration suites require `DATABASE_URL`; real proving also requires
`CLEARPROOF_PILOT_TEST_ARTIFACTS`. The fresh development circuit pipeline runs the
memory-only proving acceptance, and CI's full PostgreSQL/artifact suite runs the
job acceptance. Ordinary transport tests explicitly use synthetic backend
descriptors and are not evidence of valid cryptographic proofs.
