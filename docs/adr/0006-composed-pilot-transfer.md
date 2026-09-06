# ADR 0006: Composed development transfer proof

Status: implemented witness composition; end-to-end authorization remains incomplete.

The separate `pilot-transfer-v1` circuit composes the authenticated credential
membership construction, private transfer projection, exact integer valuation,
and sanctions gaps for both participant wallets. The originator credential binds
the tenant, wallet and jurisdiction and requires knowledge of its holder secret.
This does not claim beneficiary credential verification.

The eight public inputs, in order, are `projection_commitment`,
`authorized_issuer_root`, `sanctions_root`, `authorization_nullifier`,
`evaluated_at`, `proof_expires_at`, `domain_chain_id`, `domain_registry`.
There are no public outputs, amount tiers or SAR flags. Nullifiers use domain 203
and the stable authorization scope from ADR 0005. Expiry is after evaluation,
at most 300 seconds later, and no later than transfer or credential expiry.

Each tree is depth eight. The new sanctions profile sorts raw 160-bit address
integers, hashes leaves with Poseidon domain 301 and includes sentinel keys zero
and 2^160. It supports at most 254 sanctioned addresses for local pilot fixtures.
Membership paths constrain both neighbor leaves and their adjacent positions.
The circuit takes each query wallet directly from the transfer projection.
This profile is incompatible with the legacy sorted-hash sanctions tree and
must not be published through an existing production sanctions feed or relay.
A larger, versioned profile is required for full screening datasets.

`compliance_witness` is an encoder, not an authorization verifier. Authentic
policy thresholds and quotes, expected transfer/context commitments, authorized
and fresh roots, wallet enrollment, current revocation and transactional
nullifier consumption remain external requirements. In particular, accepting a
prover-supplied projection commitment cannot authenticate its private records.
The trusted verifier must recompute that commitment or validate an explicitly
trusted attestation of the binding. See ADRs 0003 and 0005.

The legacy sixteen-signal verifier ABI is unchanged. This profile must not be
routed to it, nor treated as supported by the current API/SDK/contracts until
artifact manifests, acceptance parity and adversarial integration checks exist.
All newly compiled artifacts and development keys remain local. Neither circuit
compilation nor successful development proofs constitute an audit or approved
production trusted setup.

## Local development reproduction

Requires the installed Python development environment, Node/snarkjs and Circom.
The phase-one file below is an existing **unapproved development input**, not
an audited ceremony. All generated files stay in a new temporary directory.
The example imports a synthetic test fixture; never replace it with customer data.

```bash
PILOT_DEV_DIR=$(mktemp -d)
export PILOT_DEV_DIR
circom circuits/pilot_compliance.circom --wasm --r1cs --sym -o "$PILOT_DEV_DIR"
.venv/bin/python - <<'PY'
import json, os, runpy
from pathlib import Path
fixture = runpy.run_path('tests/unit/test_pilot_compliance.py')
data = fixture['witness'].__wrapped__()
output = Path(os.environ['PILOT_DEV_DIR'])
(output / 'synthetic.json').write_text(json.dumps(data))
(output / 'expected-public.json').write_text(json.dumps([data[k] for k in fixture['PUBLIC_SIGNALS']]))
PY
node "$PILOT_DEV_DIR/pilot_compliance_js/generate_witness.js" "$PILOT_DEV_DIR/pilot_compliance_js/pilot_compliance.wasm" "$PILOT_DEV_DIR/synthetic.json" "$PILOT_DEV_DIR/synthetic.wtns"
node node_modules/snarkjs/build/cli.cjs groth16 setup "$PILOT_DEV_DIR/pilot_compliance.r1cs" artifacts/pot18_final.ptau "$PILOT_DEV_DIR/UNAPPROVED-development.zkey"
node node_modules/snarkjs/build/cli.cjs zkey export verificationkey "$PILOT_DEV_DIR/UNAPPROVED-development.zkey" "$PILOT_DEV_DIR/verification-key.json"
node node_modules/snarkjs/build/cli.cjs groth16 prove "$PILOT_DEV_DIR/UNAPPROVED-development.zkey" "$PILOT_DEV_DIR/synthetic.wtns" "$PILOT_DEV_DIR/proof.json" "$PILOT_DEV_DIR/public.json"
node node_modules/snarkjs/build/cli.cjs groth16 verify "$PILOT_DEV_DIR/verification-key.json" "$PILOT_DEV_DIR/public.json" "$PILOT_DEV_DIR/proof.json"
.venv/bin/python - <<'PY'
import json, os
from pathlib import Path
output = Path(os.environ['PILOT_DEV_DIR'])
assert json.loads((output / 'public.json').read_text()) == json.loads((output / 'expected-public.json').read_text())
PY
```

Observed locally on September 5, 2026: Circom 2.2.2 produced 28,598 nonlinear
and 22,394 linear constraints, eight public inputs and zero outputs. Nineteen
focused tests passed. A real Groth16 proof verified, its public signal order
matched Python, and altering the projection commitment rejected the same proof.
No key contribution or production ceremony assurance is implied by this setup.

For a complete isolated development build with a newly generated local phase-one
transcript, use `scripts/test_development_circuits.py NEW_OUTPUT_DIRECTORY`.
It exercises both circuit profiles and creates the development manifest and
files needed by the opt-in pairing integration test. See the CI development
setup section in `docs/internal/PILOT_ARTIFACT_DOCTOR.md`. The script does not
approve its self-generated trust pins for any production or customer workflow.

ADR 0007 adds scoped signed valuation approvals to the Python witness builder.
The approval is checked outside the circuit at the evaluation time. Current
verifiers still must authenticate the quote with their own tenant/clock and
recompute the expected projection; a prover bypassing Python does not thereby
receive authority to choose its own price.

ADR 0008 replaces the composed encoder's free threshold tuple with current policy
selection from independent operator pins. Approved thresholds and policy digest
now feed the same private projection. Current authorization must repeat that
selection independently; the amount tier does not itself encode a business or
legal ALLOW decision.
