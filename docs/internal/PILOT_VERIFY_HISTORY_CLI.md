# Offline `verify-history` command

The unreleased source CLI reviews an encrypted history export without database,
API, TSA or chain access. Install the Python environment with `uv sync --extra dev`
and build the Node CLI with `npm run build --workspace=@clearproof/cli` after its
workspace dependencies. Use the independently inspected development artifact
bundle and snarkjs runtime matching the recorded proof.

```bash
node packages/cli/dist/index.js verify-history \
  --python "$PWD/.venv/bin/python" \
  --bundle /secure/history.encrypted.json \
  --trust /secure/reviewer-trust.json \
  --artifacts /approved/pilot-artifacts \
  --runtime "$PWD/node_modules/snarkjs/build/snarkjs.min.js" \
  --node "$(command -v node)" \
  < /secure/reviewer-key.hex
```

The key input is exactly 64 lowercase hexadecimal characters, optionally followed
by one newline. Keep its source protected. No key argument, environment variable
or plaintext evidence output is needed. The command never writes decrypted
payloads, witnesses or evidence files. Its Node wrapper delegates directly to the
selected Python executable without a shell, and inherits stdin for key input.
Run from the source checkout or a Python environment where Clearproof's `src`
package is importable.

The same implementation is available directly:

```bash
.venv/bin/python -m src.prover.history_cli \
  --bundle /secure/history.encrypted.json \
  --trust /secure/reviewer-trust.json \
  --artifacts /approved/pilot-artifacts \
  --runtime node_modules/snarkjs/build/snarkjs.min.js \
  --node "$(command -v node)" \
  < /secure/reviewer-key.hex
```

`--verified-at EPOCH` is an explicit reviewer-clock override for reproducible
review; the default is current UTC epoch seconds. The report always records the
review time for completed inspections. Changing it changes the compromise/time
question being asked; it is not a mechanism for proving when review happened.

## Independent reviewer configuration

The versioned [JSON schema](../../specs/history-reviewer-v1.schema.json) describes
`clearproof-history-reviewer-v1`. The trust file is approved reviewer input, never
an authority selected by the evidence bundle. It is bounded to 256 KiB and rejects
duplicate JSON keys, unknown fields and incomplete structured trust blocks.

| Field | Meaning |
| --- | --- |
| `binding` | Independently expected tenant, receipt digest, reviewer ID, recipient key fingerprint and export time |
| `artifact_manifest_digest` | Approved manifest digest for the local artifact directory |
| `runtime_sha256` | Approved SHA-256 of the local snarkjs JavaScript runtime |
| `statement` | Policy inventory/pins, historical root pins, scoped root and valuation authorities |
| `facts` | Independently approved external-fact authorities |
| `decisions` | Approved decision-signing authorities |
| `statuses` | Separate issuer/registry status delegations |
| `information` | Approved information-source authorities |
| `timing` | Base64 DER TSA leaf/root certificates, policy OID, approval interval, accuracy/delay limits and known compromise |

Statement and authority blocks are optional to permit partial inspection. Their
absence leaves corresponding checks unverified and prevents `supported`. The
binding and cryptographic artifact/runtime pins are always required. Retained
keys must be reviewed independently; copying an untrusted export's keys into this
file does not establish their authority. Certificate bytes are public trust
configuration, not TSA private keys.

## Output and exit status

The command emits one `clearproof-history-report-v1` JSON object. Completed reports
include `scope: recorded-local-policy-decision`, artifact assurance, receipt
reference, individual check results, reviewer time, reasons and any authenticated
timestamp interval. They contain no decrypted source records or private key.

- `0`: supported recorded local decision under the configured authorities.
- `1`: the reviewed artifact's claim is contradicted.
- `2`: indeterminate, including missing trust, wrong decryption key, malformed or
  unavailable input/runtime. Input errors use a generic code without echoing data.

[Historical inspection](PILOT_HISTORY_INSPECTION.md) defines the outcome's limits.
Support does not certify source truth, legal compliance, global status, delivery
or settlement. Development artifacts and the local synthetic TSA remain
unapproved for production.

Tests run the real Python and built Node entry points against a PostgreSQL export
with actual development proofs, after closing the database. The direct Python
command also disables socket connections. Tests cover support, omitted authority,
wrong key and an encrypted-but-altered receipt, and check exit codes and minimized
output. This command is part of the source pilot; it is not in npm version 0.3.0.
