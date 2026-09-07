# Retain a local pilot acceptance run

This command runs the real PostgreSQL/development-EVM acceptance suite and retains
its synthetic outputs. It is a source-checkout workflow, not a production service
or proof of clean-environment onboarding. The suite creates and drops isolated
PostgreSQL schemas and starts/stops its own loopback Hardhat node. Use a dedicated
test database whose role can create schemas.

Prerequisites are the installed Python development environment, built Node
workspaces/contracts, and inspected unapproved development artifacts. Follow
[development artifact setup](../internal/PILOT_DEVELOPMENT_ARTIFACTS.md) to generate
both profiles in a new directory. Set `DATABASE_URL` through your local environment;
keep database credentials out of reports and shell history.

```bash
.venv/bin/python scripts/test_pilot_mirror.py \
  /absolute/development-artifacts/pilot \
  --output /absolute/new-pilot-run
```

The output directory must not exist. It is created with mode 0700; captured files
use mode 0600. Ordinary invocations without `--output` retain no extra files. An
inherited capture environment variable is ignored by the runner. If a test fails,
partial files may remain for diagnosis, but no successful `run.json` is written.
Use a new directory for the next attempt.

A successful run includes:

| File under `reports/` | Evidence |
| --- | --- |
| `policy-comparison.json` | Authenticated stored policy comparison and review-queue change |
| `observations.json` | Real-proof observation results for ALLOW, DENY, REVIEW and INDETERMINATE |
| `observation-cohort.json` | Coverage, disagreement and measured/missing latency counts |
| `counterparty-scenarios.json` | Built CLI dispositions and rejected inputs, including timeout, version and key rotation |
| `investigation.json` | Durable counterparty/custody timeline after duplicate and reordered deliveries |
| `history.encrypted.json` | Recipient-encrypted historical evidence export |
| `reviewer-trust.json` | Separately configured public synthetic reviewer authorities and exact bindings |
| `history-clock.json` | Explicit clock for reproducing this historical review |
| `history-report.json` | Successful review from the process that disabled socket connections |

`run.json` inventories report byte sizes and SHA-256 digests, pins the development
artifact manifest, and identifies this as a local acceptance suite. These are
local integrity references, not a signed attestation or production approval.
Reports come from the suite's scoped synthetic fixtures; the policy comparison
uses its own reviewed cases. Do not infer that all report files describe a single
customer transfer. The scope/receipt/context references in each report govern it.

`private/reviewer-key.json` contains only the generated synthetic export-recipient
private key. Keep this directory private; never upload it with reports. The CI
artifact configuration selects `reports/` and `run.json` explicitly. No signing
keys, plaintext person information, database credentials or recipient private
keys for the bilateral message are captured in reports.

## Install from the lockfiles and let the command own the database

From a fresh checkout, install dependencies from the committed lockfiles:

```bash
npm exec --yes --package=npm@11.9.0 -- npm ci
uv sync --frozen --extra dev --python 3.12
npm run build
```

The npm lockfile uses the public npm registry; the Python lockfile uses PyPI.
Frozen installs preserve the resolved dependency graph. They do not certify that
all dependencies are free of security issues. Node, Python, uv, Circom and
PostgreSQL executables are still explicit host prerequisites. CI installs Circom
2.2.2 with a pinned binary digest; the local setup requires that compiler too.

Generate fresh unapproved development artifacts outside the checkout, then run
with a new owned PostgreSQL 18 cluster:

```bash
.venv/bin/python scripts/test_development_circuits.py /absolute/new-development-artifacts
.venv/bin/python scripts/test_pilot_local.py \
  /absolute/new-development-artifacts/pilot \
  /absolute/new-owned-pilot-run \
  --postgres-bin /usr/lib/postgresql/18/bin
```

The PostgreSQL binary directory is explicit and version-checked. Run as a normal
user permitted to start a local PostgreSQL process. `TMPDIR` may be set to a short,
writable path when the system temporary directory is constrained. The wrapper
creates a private temporary Unix socket, enables local trust only within that
private directory, disables TCP listening and overrides `DATABASE_URL` with its
owned test database. The test suite owns the EVM. The wrapper stops its PostgreSQL
cluster on success or failure; it retains private database files and logs for
diagnosis. It does not start or stop any pre-existing database.

Outputs are under `new-owned-pilot-run/pilot/`. Share only its `reports/` and
`run.json` as appropriate for synthetic acceptance evidence. The outer run
contains PostgreSQL data/logs, and `pilot/private/` contains the export key; do not
publish those directories. As with the existing command, successful acceptance
is not itself a claim that the host prerequisites were provisioned from scratch.

## Reproduce the retained offline review

The following uses the private key only through subprocess stdin. Run from this
checkout with the same independently pinned artifacts and snarkjs runtime. Replace
the two absolute directory placeholders. No database is required; the child
process disables socket connections before loading the historical verifier.

```python
import json
import pathlib
import shutil
import subprocess
import sys

run = pathlib.Path('/absolute/new-pilot-run')
artifacts = pathlib.Path('/absolute/development-artifacts/pilot')
clock = json.loads((run / 'reports/history-clock.json').read_text())
key = json.loads((run / 'private/reviewer-key.json').read_text())['key']
command = [
    sys.executable, '-c',
    "import runpy,socket; "
    "socket.socket.connect=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('network forbidden')); "
    "runpy.run_module('src.prover.history_cli',run_name='__main__')",
    '--bundle', str(run / 'reports/history.encrypted.json'),
    '--trust', str(run / 'reports/reviewer-trust.json'),
    '--artifacts', str(artifacts),
    '--runtime', str(pathlib.Path('node_modules/snarkjs/build/snarkjs.min.js').resolve()),
    '--node', shutil.which('node'), '--verified-at', str(clock['verified_at']),
]
result = subprocess.run(command, input=key + '\n', text=True, capture_output=True, timeout=30)
assert result.returncode == 0, 'Retained historical review failed'
report = json.loads(result.stdout)
assert report == json.loads((run / 'reports/history-report.json').read_text())
print(json.dumps(report))
```

This establishes reproducibility under the supplied synthetic trust and selected
review clock. A copied trust file is not an independently approved production
trust configuration. Changing the clock asks a different historical trust question.
See [offline verification](../internal/PILOT_VERIFY_HISTORY_CLI.md) for outcome
semantics and CLI usage.

The complete requirement-by-requirement M0–M5 acceptance audit remains open. Live provider access, customer validation and production
assurance remain F1–F5 follow-ons.


## Workspace test behavior

`npm run test:ts` executes test tasks every time. Test-result caching is disabled
because untracked external artifact files and live test services are outside the
usual source cache. The task explicitly passes pilot/legacy artifact directories,
the selected test Python executable and the temporary directory to its children.
Build results can still be cached. For the complete contract gate, set
`CLEARPROOF_PILOT_TEST_ARTIFACTS`, `CLEARPROOF_LEGACY_TEST_ARTIFACTS` and
`CLEARPROOF_TEST_PYTHON` to the generated profiles and installed Python environment
before running the command. Without the artifact inputs, the separately marked
real-artifact cases remain pending; that is not the full contract acceptance gate.

The owned database command also runs the proof-storage parsing, migration and
reconnect suite before the durable authorization/publication tests. All run in
isolated schemas of the newly created cluster.


## Verified clean-checkout checkpoint — September 6, 2026

An independent clone with its own Python environment and dependency installation
completed frozen installs, the full workspace build, fresh phase-two development
setup and both proof-profile round trips. The Circom 2.2.2 binary matched the CI
SHA-256 pin. The owned-service command then passed 76 PostgreSQL/EVM tests with
these new artifacts and retained the nine expected report files. After the test
process and owned PostgreSQL cluster exited, the documented offline example
reproduced the exact historical report, with socket connections disabled.
Inventory hashes, file permissions and reviewer-key/person-name exclusion checks
also passed.

The final Python run passed 963 tests with 90 service/optional tests skipped; the
separate 76-test owned-service gate exercised the relevant database cases. The
uncached workspace tests passed 159 SDK, 12 CLI, 2 content, 2 artifact-metadata and
83 contract tests, including the artifact-dependent contract cases. SDK/contract
noEmit checks passed. These were local results, not a claim of remote CI success.

The host supplied Node 26.5.1, Python 3.12.13, uv 0.12.9, Circom 2.2.2 and
PostgreSQL 18; npm 11.9.0 was used for the frozen Node install. This checkpoint
validates the documented workflow with those host prerequisites. It is not a
claim of bit-identical keys, production assurance or compatibility with every
host/version. The run manifest itself still leaves clean-environment status
unestablished because test success alone cannot prove the preceding setup steps.

For version selection and upgrades, use the [compatibility matrix](pilot-compatibility.md).
For endpoint meanings, report interpretation and failure handling, use the
[observability and operator runbook](pilot-observability.md).
