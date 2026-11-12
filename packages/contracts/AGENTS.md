# PACKAGES/CONTRACTS AGENTS.md

**Scope:** Solidity sources and Hardhat tooling. The current profile is the
`pilot-transfer-v3` pilot (eight public signals, `specs/pilot-transfer-v3.md`).
A separate 16-signal legacy demo path is kept for parity; it is marked below and
in each legacy source header. Nothing here is audited. No pilot deployment exists
or is recorded; `scripts/deploy-pilot.ts` is the testnet-only deploy path (below).

## PILOT CONTRACTS (current)

| Contract | Role |
|----------|------|
| `PilotGroth16Verifier.sol` | Eight-signal Groth16/BN254 pairing check. Key and artifact-manifest digest are fixed at construction; reports `proofProfile = pilot-transfer-v3`, `assurance = development-unapproved`. Does not reconstruct statements or consume nullifiers. |
| `PilotCurrentRegistry.sol` | Tenant checkpoints (eight `Kind` heads: Issuance, Issuers, Sanctions, Credential, Policy, Valuation, Participants, Authorization), publisher-attested statements, read-only `inspect` and receipt `mirror`. PostgreSQL owns authorization; the registry only mirrors consumed receipts. See `docs/internal/PILOT_CURRENT_REGISTRY.md`. |
| `PilotRootCheckpoint.sol` | Independent current root-approval checkpoints (signed snapshot digest, root, approval revision, validity). Read by `src/chain/pilot_checkpoint.py`. See `docs/operations/pilot-root-checkpoint.md`. |
| `Pairing.sol` | MIT-licensed alt_bn128 pairing library shared by both verifiers (REUSE override in `REUSE.toml`). |
| `PairingHarness.sol` | Test harness exposing `Pairing` internals. |
| `test/MockPilotVerifier.sol` | **Test only.** ABI-compatible pilot verifier stub (configurable result, no pairing) so registry logic runs without circuit artifacts. Never deploy. |

### Pilot invariants (do not weaken)

- **Signal order** is fixed by the spec; `PilotCurrentRegistry._inspect` checks
  indices 0–7 against the statement and pins. Never pick a profile by signal count.
- **Domain binding lives here, not in the circuit:** `signals[6] == block.chainid`
  and `signals[7] == uint160(address(this))`. Removing either enables replay.
- **Verifier code-hash pin:** the registry records the verifier's `codehash` at
  construction and fails closed if it changes.
- **Publisher epochs:** every `setPublisher` call (including the same address or
  zero) increments the tenant epoch. Heads/statements from older epochs are not
  current. Both pilot registries record the epoch on each head; readers must check
  `head.publisherEpoch == publisherEpochs(tenant)` and a nonzero publisher
  (`PilotRootCheckpoint.isCurrent`, and the Python observer, do this).
- **Administration:** both use OpenZeppelin `AccessControlDefaultAdminRules`
  (two-step admin transfer, `INITIAL_ADMIN_DELAY = 2 days`, changeable through the
  OZ delay-change flow). `grantRole(DEFAULT_ADMIN_ROLE, …)` is rejected by design.
  A zero admin reverts with `AccessControlInvalidDefaultAdmin`.
- **Pause:** `PAUSER_ROLE` (granted to the initial admin) can `pause()`; only the
  default admin can `unpause()`. Paused: `publishHead`, `publishStatement`,
  `publishBatch`, `mirror` (registry) and `publish` (checkpoint) revert with
  `EnforcedPause`. Views, including `inspect`, stay available, and `setPublisher`
  is deliberately unpausable so a compromised publisher can be cut off. After an
  admin transfer, review and revoke `PAUSER_ROLE` holders explicitly.
- **Events** (consumed by `src/chain/publication_reconciliation.py`; regenerate
  decoders if you change them):
  - `PublisherChanged(tenant indexed, publisher indexed, epoch)` (both contracts)
  - `HeadPublished(tenant, kind, scope indexed; revision, digest, value, validFrom, validUntil, enabled, publisherEpoch)`
  - `StatementPublished(tenant, statementId indexed; contextDigest, consumer, projectionCommitment)`
  - `AuthorizationMirrored(tenant, receiptId, nullifier indexed; statementId)`
  - `RootCheckpointPublished(tenantHash, rootScope, snapshotDigest indexed; root, revision, validFrom, validUntil, publisherEpoch)`
- **Runtime pins:** `PilotRootCheckpoint` has no immutables, so its pin can be the
  build artifact's `deployedBytecode`. `PilotCurrentRegistry` embeds immutables
  (verifier, code hash, manifest), so pin the reviewed deployment's runtime code.

### Pilot sanctions root

`scripts/build_pilot_sanctions_tree.py` builds `artifacts/pilot_sanctions_tree.json`
(depth 20, key-sorted raw addresses) from the legacy builder's normalized output.
`scripts/publish_pilot_sanctions_head.py` authenticates a signed `sanctions-root`
approval against that rebuilt tree and, after typed confirmation, publishes a
`Kind.Sanctions` head (`--target registry`, default) or a `PilotRootCheckpoint`
approval (`--target checkpoint`). The circuit checks gap adjacency only; the
publisher is trusted for sortedness (see the spec's sanctions section).

### Pilot deployment (testnets and local networks only)

`scripts/deploy-pilot.ts` (`make deploy-pilot NETWORK=<x>`) deploys
`PilotGroth16Verifier`, `PilotCurrentRegistry` and `PilotRootCheckpoint`. The logic
is in `scripts/pilot-deployment.ts`, with the network, signer, environment and
paths passed in, so `test/PilotDeployment.test.ts` and
`tests/contract-scripts/pilot-deployment.test.ts` can run it.

- **No mainnet path.** It accepts `hardhat`/`localhost` on chain 31337 and
  `testnet: true` entries of `scripts/networks.ts` on their listed chain ID. Every
  other network is refused and there is no override flag: the verifier reports
  `assurance = "development-unapproved"`. Do not add an override.
- **Explicit admins.** `PILOT_REGISTRY_ADMIN` and `PILOT_CHECKPOINT_ADMIN` (or
  `registryAdmin`/`checkpointAdmin` in the JSON file named by `PILOT_DEPLOY_CONFIG`)
  are the only privileged constructor arguments; each admin also receives
  `PAUSER_ROLE`. The deployer is used only with `PILOT_ALLOW_DEPLOYER_ADMIN=1`,
  which is rejected off the local networks. Publishers are not constructor
  arguments: each admin calls `setPublisher(tenant, publisher)` afterwards.
- **Pinned key.** `PILOT_ARTIFACTS_DIR` names a bundle with `manifest.json` and its
  verification key; `PILOT_MANIFEST_DIGEST` is the operator-reviewed manifest digest.
  The script recomputes `PilotArtifactManifest.digest` (`src/prover/pilot_artifacts.py`)
  and checks the key file's SHA-256 and size. If that Python schema changes, update
  `artifactManifestDigest` and its known-answer test together.
- **Confirmation.** The operator types `deploy` before any transaction;
  `SKIP_CONFIRM=1` skips the prompt.
- **Manifest.** `deployments/<network>-pilot.json` records network, chain ID,
  deployer, admins, per-contract address, constructor arguments, deployment tx hash,
  block number, `runtimeCodeHash` (keccak256, the value the registry pins as
  `verifierCodeHash`) and `runtimeSha256` (the `--runtime-sha256` pin of
  `scripts/publish_pilot_sanctions_head.py`), plus profile, assurance, manifest
  digest, verification-key SHA-256 and commitment, and the git commit.
- **Restartable.** Each deployment transaction is written to the manifest before it
  is awaited. A rerun finalizes a recorded transaction, deploys only missing
  contracts (same deployer and commit required), compares recorded code hashes with
  the chain, and re-reads the verifier/registry/checkpoint views. A manifest for
  different admins, key or chain, or one that does not match on-chain code, is
  refused and left untouched. The script does not run explorer verification.
  The in-process `hardhat` network starts empty on every run, so a
  `hardhat-pilot.json` from an earlier run is refused; point
  `CLEARPROOF_DEPLOYMENTS_DIR` at a scratch directory for such trials and do not
  commit local manifests.

## LEGACY CONTRACTS (16-signal `compliance.circom` demo/parity path)

Never accept legacy proofs, roots or records as current pilot authorization.

| Contract | Role |
|----------|------|
| `Groth16Verifier.sol` | Generated 16-signal verifier (`scripts/generate_verifier.mjs`, written by `scripts/compile_circuits.sh`). Do not hand-edit; regenerate with its test vectors. |
| `VerifierRouter.sol` | Timelocked router over 16-signal `IGroth16Verifier` implementations (legacy interface only). |
| `ComplianceRegistry.sol` | Legacy proof submission, thresholds, nullifiers; checks `domain_chain_id`/`domain_contract_hash`. |
| `VASPRegistry.sol` | Legacy VASP identity and keys. |
| `SanctionsOracle.sol` | Legacy sorted-hash sanctions root with 1h cooldown and 50% leaf-count floor. |
| `SanctionsRootRelay.sol`, `ISanctionsRootReceiver.sol` | Legacy cross-chain root relay. |
| `MockVerifier.sol` | Test-only 16-signal stub. |
| `bench/Groth16VerifierBLS.sol` | ADR 0002 BLS12-381 benchmark (Prague precompiles). |

Legacy sources stay at `contracts/` (not `contracts/legacy/`) because the published
`@clearproof/contracts` package exposes `artifacts/contracts/<Name>.sol/<Name>.json`
and `scripts/compile_circuits.sh` writes `Groth16Verifier.sol` in place; moving them
would break those paths. Legacy scripts: `deploy.ts`, `deploy-multichain.ts`,
`deploy-relay.ts`, `deploy-verifier-bls.ts`, `update-sanctions-root.ts`,
`relay-sanctions-root.ts`, `legacy-verifier.ts`, `redeploy-verifier.ts`,
`check-transfer.ts`, `verify-onchain.ts`, `gas-bench.ts`.

## LAYOUT

```
packages/contracts/
├── contracts/            # Solidity sources (pilot + legacy, see tables), test/ mocks, bench/
├── scripts/              # Hardhat scripts: deploy-pilot.ts + pilot-deployment.ts (pilot), legacy deploy/relay
├── test/                 # Hardhat suites; helpers/ builds development verifiers
├── deployments/          # Legacy records (sepolia.json), benchmarks; <network>-pilot.json once a pilot deploy is run
└── typechain-types/      # Generated bindings, committed — regenerate with `npx hardhat compile`
```

## TESTS

- `npx hardhat test` runs everything that needs no circuit artifacts, including
  `PilotRootCheckpoint.test.ts` and `PilotCurrentRegistryLogic.test.ts` (mock
  verifier: pause, admin rules, epochs, events, domain binding, mirroring), and
  `PilotDeployment.test.ts` (the deploy script on the in-process network with a
  synthetic generator-point key: manifest, resume, refusals).
- `npm run test:contract-scripts:coverage` (repository root) holds every
  `scripts/*.ts` file, including both pilot deployment files, to 100% V8 coverage.
- `PilotCurrentRegistry.test.ts` and other real-proof suites require explicit
  `CLEARPROOF_PILOT_TEST_ARTIFACTS` bundles. Legacy `E2E.test.ts` requires
  `CLEARPROOF_LEGACY_TEST_ARTIFACTS`; it skips when absent and fails if a supplied
  bundle is empty or incomplete. Ambient root `artifacts/` are never E2E inputs.
  The CI `circuits` job supplies development bundles.
- `uv run python scripts/test_checkpoint_evm.py` runs the Python observer and the
  pilot sanctions publication script against an owned loopback node.

## CONVENTIONS

- Solidity 0.8.24, optimizer runs=200, Hardhat `prague` hardfork; OpenZeppelin 5.x.
- Never edit `typechain-types/` by hand; commit regenerated bindings with sources.
- Never commit `.env` or private keys. Deploy only with `DEPLOYER_PRIVATE_KEY`.
- Commit a `deployments/<network>-pilot.json` only for a deployment that was
  actually made and reviewed; never hand-write one.

## ANTI-PATTERNS

- NEVER remove the registry's chain-ID/address checks or the verifier code-hash pin.
- NEVER add a mainnet override to `deploy-pilot.ts`, or default a pilot admin to the deployer.
- NEVER treat a passing `inspect` or a mirror as a new authorization.
- NEVER rebuild a sanctions tree without publishing it: legacy needs
  `make relay-sanctions`; the pilot needs a `Kind.Sanctions` head per deployment.
- NEVER use ENS names for sanctions — raw hex addresses only.

## COMMANDS

```bash
cd packages/contracts
npx hardhat compile
npx hardhat test
npx hardhat test test/PilotRootCheckpoint.test.ts test/PilotCurrentRegistryLogic.test.ts

# Pilot contracts (testnet or local only; see "Pilot deployment")
npx hardhat run scripts/deploy-pilot.ts --network sepolia

# Legacy oracle path
npx hardhat run scripts/update-sanctions-root.ts --network sepolia
npx ts-node scripts/relay-sanctions-root.ts
```
