# Operational test inventory

This inventory complements application coverage. The ten Python files in
`scripts/` contain 1045 executable statements and 238 branches at checkpoint 136.
The four JavaScript helpers and three shell scripts need separate acceptance and
coverage evidence; Python coverage cannot measure them. No scripts are silently
removed from the Python denominator.

| Script | Current evidence | Remaining verification |
| --- | --- | --- |
| `build_sanctions_tree.py` | Synthetic normalization/tree unit tests | Offline source parsing, failures, reproducibility and output lifecycle; remaining measured branches |
| `generate_poseidon_constants.py` | 77/77 statements, 20/20 branches; actual complete output parity, matrix redraws, non-mutating verification failures | Retain coverage in final aggregate |
| `hpke_keygen.py` | 15/15 statements, 2/2 branches; actual foreign-directory CLI; X25519 derivation and HPKE round trip | Retain coverage in final aggregate |
| `l2_cost_model.py` | 229/229 statements, 56/56 branches; FastLZ, fee boundaries, both report formats, measured inputs and actual CLI | Retain coverage in final aggregate |
| `make_bls_input.py` | 87/87 statements, 14/14 branches; full vector parity, fresh CLI, corrupt references and cross-field path inconsistency | Retain coverage in final aggregate; benchmark remains non-standard BLS Poseidon |
| `pilot_contract_fixture.py` | Invoked by real current-registry contract tests | Instrument script and exercise input/error paths |
| `test_checkpoint_evm.py` | Owned-EVM acceptance runner previously completed | Instrument runner itself; failure/cleanup paths |
| `test_development_circuits.py` | Actual development proof runner plus subprocess lifecycle tests | Remaining setup, validation and cleanup branches |
| `test_pilot_local.py` | Outside current focused execution | Local orchestration and failure/cleanup paths |
| `test_pilot_mirror.py` | Actual durable authorization/EVM acceptance runner completed | Instrument runner itself; failure/cleanup/report paths |
| `poseidon_hash.js` | 12 actual subprocess tests: large decimal input parity, both JSON forms, malformed shapes/values/arity | JavaScript instrumentation and remaining source audit |
| `generate_verifier.mjs` | Used for fresh development proofs and real contract tests | Input-validation/output/error inventory and instrumentation |
| `generate_verifier_bls.mjs` | Outside current focused execution | Input-validation/output/error inventory and instrumentation |
| `check_eip2537.mjs` | Outside current focused execution | Controlled local precompile probe, unavailable RPC and error reporting |
| `compile_circuits.sh` | Development artifacts exercised through isolated runner | Shell entry/options/failure audit in an isolated checkout |
| `circuit_lint.sh` | Existing CI static-analysis job | Local command/error-path evidence and remote run verification |
| `regen_protobufs.sh` | Existing CI freshness job | Verify exact output/freshness/failure behavior and remote run |

Run the current focused operational job from the repository root:

```bash
uv run python -m pytest \
  tests/unit/test_l2_cost_model.py tests/unit/test_poseidon.py \
  tests/unit/test_deterministic_tree.py tests/unit/test_development_runner.py \
  tests/unit/test_hpke_keygen_script.py tests/unit/test_poseidon_script.py \
  tests/unit/test_poseidon_generator.py \
  tests/unit/test_bls_input_script.py \
  --cov=scripts --cov-branch --cov-report=json:operational-coverage.json \
  --cov-report=term-missing -q
```

Node dependencies must be installed. CI retains this report separately from
`src` coverage. The completed HPKE, L2 model, parameter generator and BLS input
converter scripts have a 100% regression
gate; the all-script aggregate stays visibly partial until the remaining behavior
is exercised. Synthetic sanctions fixtures do not update deployed roots;
development proving material and ephemeral private keys are never committed.
