# Roadmap

clearproof's contracts are EVM-compatible and deploy to any EVM chain. The domain binding in the circuit (`chain_id` + `contract_hash`) ensures each deployment is replay-safe.

## Phase 1: Operator Relayer

Direct wallet-based relaying. The operator calls `updateRoot()` on each chain.

**Status: Implemented**

- [x] Network config for 10 chains (5 testnets, 5 mainnets)
- [x] `SanctionsRootRelay` adapter contract — separates transport from oracle
- [x] Multi-chain deploy script
- [x] Multi-chain relayer script
- [x] GitHub Actions workflow for automated relay

**Supported networks:**

| Testnet | Mainnet |
| --- | --- |
| Sepolia | Ethereum |
| Base Sepolia | Base |
| Arbitrum Sepolia | Arbitrum |
| Polygon Amoy | Polygon |
| Optimism Sepolia | Optimism |

## Phase 2: Deterministic Sanctions Tree

Make the sanctions tree construction fully reproducible and independently verifiable.

**Status: Implemented**

- [x] Canonical address normalization (lowercase hex, 0x prefix, 40 chars)
- [x] Poseidon domain tag 1 for leaf hashing
- [x] Source manifest with SHA-256 hashes of all source files
- [x] Versioned build script with published hash
- [x] Test vectors for independent verification
- [x] `--verify` mode to validate existing tree against test vectors

## Phase 3: Plug-and-Play VASP Discovery

Self-service onboarding for new VASPs — no manual configuration required.

**Status: Implemented**

- [x] `VASPRegistry` extended with `discoveryEndpoint` field
- [x] `/.well-known/clearproof.json` specification
- [x] SDK discovery resolver with caching

New VASPs publish one file and send one transaction to become discoverable by the entire network.

## Phase 4: Verification Fees

Per-verification fee to cover operating costs.

**Status: Planned (mainnet)**

- [ ] Fee collection in the `ComplianceRegistry` contract
- [ ] Fee waiver mechanism for early adopters

## Phase 5: Batch Verification

Submit multiple proofs in a single transaction for high-volume VASPs.

**Status: Planned (mainnet)**

- [ ] `verifyAndRecordBatch()` with soft failures
- [ ] Per-proof events for success/failure tracking
- [ ] Batch size cap to stay within block gas limits

## Phase 6: Cross-Chain Messaging

Replace the operator relayer with automated cross-chain root propagation.

**Status: Planned**

- [ ] Evaluate LayerZero v2 and Chainlink CCIP
- [ ] Deploy bridge contracts on canonical chain
- [ ] Automated root fan-out to all destination chains

## Phase 7: Sanctions Oracle Trust

Multi-party validation of the sanctions Merkle root.

**Status: Planned**

- [ ] Multi-operator attestation (N-of-M threshold)
- [ ] Disagreement alerting and halt mechanism
- [ ] Decentralized oracle network (long-term)

## Phase 8: Non-EVM Chains

Extend to Solana and Stellar for USDC/USDT corridors.

**Status: Not started (waiting for demand)**

- [ ] Native Groth16 verifier implementations
- [ ] Cross-VM proof format standardization

---

## Adding a New Chain

To add a new EVM chain:

1. Add the network to `packages/contracts/scripts/networks.ts`
2. Add the network to `packages/contracts/hardhat.config.ts`
3. Add RPC URL env var to `.env.example`
4. Deploy: `make deploy NETWORK=<name>`
5. Add to `RELAY_NETWORKS` in GitHub Actions variables
6. Verify contracts on the block explorer
