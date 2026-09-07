# Contract development validation and legacy deployment preparation

The pilot eight-signal verifier and legacy sixteen-signal registry flow use
separate artifacts. Select complete, matching bundles explicitly:

```bash
CLEARPROOF_PILOT_TEST_ARTIFACTS=/absolute/path/to/development/pilot \
CLEARPROOF_LEGACY_TEST_ARTIFACTS=/absolute/path/to/development/legacy \
npm test --workspace=@clearproof/contracts -- --network hardhat
npm run typecheck --workspace=@clearproof/contracts
```

Use `scripts/test_development_circuits.py <new-output-directory>` to generate
isolated unapproved development bundles. The builder runs the Python pilot proof
check, the EVM pilot pairing check and the legacy prove/submit/read-back check
against its fresh output. That end-to-end legacy test generates an Apache-2.0
verifier from the selected verification key, compiles it with Solidity 0.8.24 and
optimizer runs 200, and deploys it only in the test network. Temporary source is
removed, and the checked-in legacy verifier/key is not replaced. This proves local
cryptographic and registry integration; it does not approve a setup for production.

An explicitly selected incomplete bundle fails. Without a legacy selector, the
old root `artifacts/` location remains the compatibility default; absent files
retain the existing optional-test behavior. A present incompatible bundle fails,
and should be investigated or replaced through a documented development build.
Do not hide it by skipping assertions. In the September 6 local check, the root
WASM expected 124 inputs while the legacy fixture supplied 123; the explicitly
selected current development bundle passes. The old root files were not modified.

Typechecking now includes generated TypeChain bindings and the shared snarkjs
module declaration. The package command regenerates bindings from compiled ABIs
before checking all scripts and tests. Run compilation/tests first on a clean
checkout. CI runs typechecking after the Hardhat tests, and the fresh development
builder runs both artifact-dependent EVM tests.

## PostgreSQL authorization to local EVM

After installing dependencies, building the SDK/CLI and compiling contracts, run:

```bash
npm run build --workspace=@clearproof/proof
npm run build --workspace=@clearproof/cli
npm run compile --workspace=@clearproof/contracts
# DATABASE_URL must already identify a dedicated test PostgreSQL database.
.venv/bin/python scripts/test_pilot_mirror.py /absolute/path/to/development/pilot
```

The runner requires a complete inspected development bundle; it does not generate
or approve new keys. It starts an owned Hardhat node on a dynamically selected
loopback port, checks chain ID 31337 and runs all durable pilot storage and publication-journal tests.
Each test uses a unique database schema that is dropped afterward. The node and
test process groups are cleaned up on success, failure or interruption, and node
logs containing public development keys are kept in an ephemeral private file.
Missing dependencies/artifacts, node startup errors and test failures fail the run.

The authorization fixture deploys the matching verifier and registry before
producing its real proof. After atomic PostgreSQL authorization it authenticates a
fresh mirror plan, publishes its actual heads and statement, verifies and mirrors
the receipt, and confirms the database consumption was not repeated. The
publication journal is exercised with a lost response after node acceptance,
database reconnect and hash-based inclusion lookup without a second send. It exercises
wrong receipt/caller, replay and checkpoint invalidation, then continues the
existing restart, API/CLI and offline historical verification checks. This local
integration uses synthetic credentials and source approvals. It is not a deployed
publisher service, live source relay or production finality demonstration.

CI invokes this command with the fresh pilot artifacts created by the isolated
builder. The ordinary suite keeps EVM integration optional when no explicit
`CLEARPROOF_MIRROR_TEST_RPC` is configured; use the runner to require this gate.

## Legacy deployment registration and activation

`deploy.ts` and `deploy-multichain.ts` use the shared `prepareLegacyVerifier`
helper. It deploys the legacy verifier and its router, registers selector
`keccak256("groth16-bn254-v1")`, and preserves the default 24-hour activation
timelock. Registry construction uses the router address, selector, VASP registry,
sanctions oracle and all three default thresholds. Explorer verification receives
the same constructor arguments.

Deployment records default to `packages/contracts/deployments/`; set
`CLEARPROOF_DEPLOYMENTS_DIR` to an explicit directory for isolated local runs.
Records use the actual selected Hardhat network name. Explorer publication is
skipped on `hardhat` and `localhost`.

Deployment records include `VerifierRouter` and `verifierActivation`, whose
`status` is `pending-timelock`, with the selector, registered name and chain
`activateAfter` timestamp. Deployment is not readiness to accept proofs. After
that timestamp, an authorized router administrator can call
`activateVerifier(selector, name)` using the recorded values. Confirm the router's
current pending registration and timelock on-chain before activation, and verify
the resulting active verifier matches the approved deployment. This preparation
does not perform automatic activation or bypass a timelock.

`deploy-multichain.ts` operates on the single explicitly selected Hardhat network;
repeat it per network. It does not implement a `DEPLOY_NETWORKS` loop. Any sanctions
root publication must still follow the project's relay procedure. The gas benchmark
is restricted to the ephemeral `hardhat` network and uses real contract dependencies
and the current constructor. It makes no production gas or deployment assurance
claim. Development validation must not be taken as authorization to deploy remotely.
