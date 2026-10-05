# PACKAGES/CONTRACTS AGENTS.md

**Scope:** Solidity sources and Hardhat tooling. The current profile is the
`pilot-transfer-v3` pilot (eight public signals, `specs/pilot-transfer-v3.md`).
A separate 16-signal legacy demo path is kept for parity; it is marked below and
in each legacy source header. Nothing here is audited or deployed for the pilot.

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
would break those paths. Legacy scripts: `deploy*.ts`, `update-sanctions-root.ts`,
`relay-sanctions-root.ts`, `legacy-verifier.ts`, `redeploy-verifier.ts`,
`check-transfer.ts`, `verify-onchain.ts`, `gas-bench.ts`.

## LAYOUT

```
packages/contracts/
├── contracts/            # Solidity sources (pilot + legacy, see tables), test/ mocks, bench/
├── scripts/              # Hardhat deploy/relay scripts (legacy oracle path)
├── test/                 # Hardhat suites; helpers/ builds development verifiers
├── deployments/          # Legacy deployment records (sepolia.json)
└── typechain-types/      # Generated bindings, committed — regenerate with `npx hardhat compile`
```

## TESTS

- `npx hardhat test` runs everything that needs no circuit artifacts, including
  `PilotRootCheckpoint.test.ts` and `PilotCurrentRegistryLogic.test.ts` (mock
  verifier: pause, admin rules, epochs, events, domain binding, mirroring).
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

## ANTI-PATTERNS

- NEVER remove the registry's chain-ID/address checks or the verifier code-hash pin.
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

# Legacy oracle path
npx hardhat run scripts/update-sanctions-root.ts --network sepolia
npx ts-node scripts/relay-sanctions-root.ts
```
