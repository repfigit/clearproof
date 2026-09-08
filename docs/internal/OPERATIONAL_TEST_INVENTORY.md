# Operational test inventory

This inventory complements application coverage. The ten Python files in
`scripts/` contain 1045 executable statements and 238 branches at checkpoint 136.
All 1045 statements and 238 branches are covered in the local incremental
aggregate at checkpoint 145. The four JavaScript helpers and three shell scripts need separate acceptance and
coverage evidence; Python coverage cannot measure them. No scripts are silently
removed from the Python denominator.

| Script | Current evidence | Remaining verification |
| --- | --- | --- |
| `build_sanctions_tree.py` | 293/293 statements, 70/70 branches; synthetic source HTTP/parsing failures, isolated outputs, leaf-vector verification and deterministic roots | Retain aggregate; `--verify` checks leaf vectors, not a fetched-source or full stored-tree audit |
| `generate_poseidon_constants.py` | 77/77 statements, 20/20 branches; actual complete output parity, matrix redraws, non-mutating verification failures | Retain coverage in final aggregate |
| `hpke_keygen.py` | 15/15 statements, 2/2 branches; actual foreign-directory CLI; X25519 derivation and HPKE round trip | Retain coverage in final aggregate |
| `l2_cost_model.py` | 229/229 statements, 56/56 branches; FastLZ, fee boundaries, both report formats, measured inputs and actual CLI | Retain coverage in final aggregate |
| `make_bls_input.py` | 87/87 statements, 14/14 branches; full vector parity, fresh CLI, corrupt references and cross-field path inconsistency | Retain coverage in final aggregate; benchmark remains non-standard BLS Poseidon |
| `pilot_contract_fixture.py` | 48/48 statements, 8/8 branches; actual proof generation, altered-nullifier rejection, prover timeout/exit and temporary cleanup | Retain coverage in final aggregate; separate artifact-backed CI gate |
| `test_checkpoint_evm.py` | 44/44 statements, 6/6 branches; startup/retry/deadline/child-failure and cleanup tests, separate owned-EVM integration | Retain coverage and real execution in final aggregate |
| `test_development_circuits.py` | 104/104 statements, 16/16 branches; current real compile/prove/contract workflow plus preconditions, both phase-one paths and process lifecycle | Retain real and unit coverage in final aggregate |
| `test_pilot_local.py` | 43/43 statements, 8/8 branches; setup/failure/cleanup tests plus 223 passing tests through real owned-cluster/EVM acceptance | Retain aggregate and real execution evidence |
| `test_pilot_mirror.py` | 105/105 statements, 38/38 branches; doctor/report checks, process startup/readiness/cleanup failures and actual 223-test acceptance run | Retain aggregate and real execution evidence |
| `poseidon_hash.js` | 19/19 statements, 4/4 branches, 19/19 lines, 2/2 functions; streamed-input V8 tests plus 12 actual subprocess tests | Retain coverage and subprocess parity in final verification |
| `generate_verifier.mjs` | 28/28 statements, 10/10 branches, 26/26 lines, 4/4 functions; exact committed output, real CLI and rejected inputs | Retain coverage and contract parity evidence |
| `generate_verifier_bls.mjs` | 41/41 statements, 12/12 branches, 35/35 lines, 4/4 functions; exact benchmark output, real CLI and rejected inputs | Retain coverage; benchmark is not a production migration |
| `check_eip2537.mjs` | 32/32 statements, 16/16 branches, 28/28 lines, 1/1 functions; response/fallback/timeout tests and actual local EVM pairing vector | Retain coverage; tests do not establish current public-chain availability |
| `compile_circuits.sh` | 26 actual shell control-flow tests with synthetic tools; isolated real compile/setup/verifier build and CLI proof verification | Retain behavior evidence; real download/local phase-one branches use synthetic boundary tests, not live ceremonies |
| `circuit_lint.sh` | Ten isolated Bash acceptance tests; actual Circomspect passes with five documented findings; seven real SARIF reports validated | Retain shell behavior evidence and verify remote run; no line/branch percentage claimed |
| `regen_protobufs.sh` | 17 shell acceptance tests: real pinned-compiler output parity and all four stale/missing checks; postprocessor variants/failures and compiler failure | Retain behavior evidence; remote run verification pending |

Run the current focused operational job from the repository root:

```bash
uv run python -m pytest \
  tests/unit/test_l2_cost_model.py tests/unit/test_poseidon.py \
  tests/unit/test_deterministic_tree.py tests/unit/test_development_runner.py \
  tests/unit/test_hpke_keygen_script.py tests/unit/test_poseidon_script.py \
  tests/unit/test_poseidon_generator.py \
  tests/unit/test_bls_input_script.py \
  tests/unit/test_sanctions_sources.py \
  tests/unit/test_checkpoint_runner.py \
  tests/unit/test_pilot_local_runner.py \
  tests/unit/test_pilot_mirror_reports.py \
  tests/unit/test_pilot_mirror_runner.py \
  tests/unit/test_development_setup.py \
  tests/unit/test_circuit_lint_script.py \
  tests/unit/test_regen_protobufs_script.py \
  tests/unit/test_compile_circuits_script.py \
  --cov=scripts --cov-branch --cov-report=json:operational-coverage.json \
  --cov-report=term-missing -q
```

Node dependencies must be installed. CI retains this report separately from
`src` coverage. The completed HPKE, L2 model, parameter generator, BLS input
converter, sanctions builder, checkpoint, local-pilot and mirror runner scripts
have a 100% regression gate. This focused report remains partial because artifact
workflows run separately. The circuit job combines its
real development workflow and failure-path tests for a 100% development-runner
gate; the contract fixture also has an artifact-backed gate. Local aggregation
covers all ten Python scripts. Checkpoint 152 adds a cross-job aggregate gate
combining application, operational, development and contract-fixture data; its
exact command passes locally across 153 files. Remote execution remains pending.
Synthetic sanctions fixtures do not update deployed roots;
development proving material and ephemeral private keys are never committed.

JavaScript measurement is separate:

```bash
npm run test:scripts:coverage
```

The root Vitest configuration inventories all four JavaScript scripts, including
unimported files. At checkpoint 148 all four scripts pass per-file 100% gates;
the aggregate is 120/120 statements, 42/42 branches, 108/108 lines and 11/11 functions.
Poseidon tests exercise actual circomlib hashing with controlled process streams;
12 separate real subprocess tests verify the CLI against native Python hashes. CI retains
the JSON/LCOV reports. Probe tests replace fetch locally; the successful pairing
vector was also checked on a local Hardhat EVM. Its 384-byte infinity-pair input
and exact boolean output follow [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#abi-for-pairing).

Circuit lint shell acceptance (checkpoint 149) covers both output modes, all
seven analyzer invocations, all five allowlist patterns, unexpected warnings and
errors, missing executable, silent/non-diagnostic exits, fatal exits containing
an otherwise allowed warning, and temporary-file cleanup. Four failing tests
exposed swallowed analyzer failures; the runner now accepts exit 1 only when a
diagnostic was emitted, then applies its finding filter. Other nonzero statuses
become unexpected errors. Real Circomspect passes in both modes; seven SARIF 2.1.0
reports were checked in an isolated external tree. These are behavioral acceptance
checks, not a claim of measured Bash line or branch coverage.

At checkpoint 152, the current operational CI command passes all 234 selected
tests in 210.90 seconds. Its standalone report intentionally remains partial
(artifact-backed branches run in the circuit job). CI retains raw data as well
as JSON. The final `python-aggregate-coverage` job depends on both contributing
jobs and combines four explicitly named data files. Local validation with the
same command covers 9377/9377 statements and 2306/2306 branches across 143
application files and ten scripts. Omitting contract-fixture evidence fails the
gate. Application and development inputs are earlier unchanged-source evidence;
this aggregate is not a fresh full-suite or remote-CI completion claim.

The deployment audit at checkpoint 153 found twelve additional authored
TypeScript files under `packages/contracts/scripts/`. Solidity instrumentation
does not measure them. `npm run test:contract-scripts:coverage` now inventories
all twelve, including unimported files, in a separate V8 report. Network-selection
and legacy verifier-preparation helpers pass 100% per-file gates; the other ten
files are included at zero measured coverage until their paths are exercised.
The initial aggregate is 16/643 statements, 11/180 branches, 14/632 lines and
4/49 functions. Existing real deployment acceptance is complementary evidence,
not a substitute for this missing TypeScript measurement.

| Contract script | V8 coverage at checkpoint 153 | Remaining work |
| --- | --- | --- |
| `networks.ts` | 100% all metrics | Retain selection/override tests; no public RPC availability claim |
| `legacy-verifier.ts` | 100% all metrics | Retain actual deployment/timelock checks |
| `deploy.ts` | 100% all metrics | Retain threshold/record/failure tests and actual local deployment acceptance |
| `deploy-multichain.ts` | 100% all metrics | Retain balance, threshold, relay-role and explorer tests plus local acceptance |
| `deploy-relay.ts` | 100% all metrics | Retain real local deployment, oracle-role and record checks |
| `deploy-verifier-bls.ts` | 0% | Isolated benchmark deployment/error paths |
| `redeploy-verifier.ts` | 0% | Isolated replacement/error paths |
| `relay-sanctions-root.ts` | 0% | Controlled relayer lifecycle and errors |
| `update-sanctions-root.ts` | 0% | Synthetic update/consistency failures |
| `check-transfer.ts` | 100% all metrics | Retain controlled read responses/errors |
| `verify-onchain.ts` | 100% all metrics | Retain proof formatting/submission and failure tests |
| `gas-bench.ts` | 100% all metrics | Retain actual ephemeral-Hardhat benchmark and failure tests |

Checkpoint 154 covers three more contract scripts: transfer lookup (26 statements,
12 branches, 26 lines, four functions), proof submission (44 statements, 34
branches, 44 lines, six functions), and gas benchmarking (32 statements, two
branches, 31 lines, two functions), all fully gated. The 44-test suite now covers
118/643 statements, 59/180 branches, 115/632 lines and 16/49 functions overall.
Seven contract scripts remain unmeasured. Registry tool tests use controlled RPC,
file and transaction responses; the gas benchmark also passes on a real ephemeral
Hardhat network. No public transactions or sanctions updates are performed.

Checkpoint 155 adds eleven relay deployment tests and a real ephemeral-Hardhat
entry-point test. Relay tooling reaches 45/45 statements, 10/10 branches, 45/45
lines and 2/2 functions. Its tests cover missing deployment/oracle metadata,
role presence/grant confirmation, metadata preservation, explorer verification
variants, and deployment/role/receipt/write failures. Six contract scripts now
have full per-file gates; the remaining six stay in the denominator at zero.
The complete contract-tooling report remains partial at 163/643 statements,
69/180 branches, 160/632 lines and 18/49 functions.

Checkpoint 156 adds 29 measured tests for the single-network and multi-chain
deployment entrypoints. They cover lower-case jurisdiction encoding, exact
constructor/override thresholds, receipt-before-record ordering, pending
activation metadata, configured/default output paths, empty override tables,
invalid jurisdiction keys, failed deployment/seeding/confirmation/persistence,
local-network explorer suppression, both configured explorer-key paths, optional
error messages and the empty-balance refusal. Both source files reach 100% on
all metrics and gain per-file gates. Overall: 313/643 statements, 90/180 branches,
308/632 lines and 26/49 functions across all twelve files. Four scripts remain
unmeasured. Existing actual local deployment acceptance remains complementary
evidence; these new tests control network and file operations.
