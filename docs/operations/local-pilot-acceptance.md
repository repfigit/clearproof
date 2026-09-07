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

Fresh-checkout service automation and the complete M0–M5 acceptance audit remain
separate completion work. Live provider access, customer validation and production
assurance remain F1–F5 follow-ons.
