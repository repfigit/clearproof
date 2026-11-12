---
title: Verify a Proof On-Chain
prereqs:
  - contracts-deployed
  - proof-generated
  - sepolia-rpc
estimated-time: 3 min
---

# Verify a Proof On-Chain

Submit a compliance proof to a ComplianceRegistry deployed from the current source. `packages/contracts/deployments/sepolia.json` is the July 20, 2026 historical record and does not match this script. The contract performs 14 checks including Groth16 verification, sanctions root validation, and nullifier uniqueness.

> **Legacy demo path.** `ComplianceRegistry` and `scripts/verify-onchain.ts` accept the 16-signal legacy profile only. A `pilot-transfer-v3` proof is not submitted this way: PostgreSQL owns pilot authorization, and `PilotCurrentRegistry` only mirrors receipts that were already consumed.

Run the steps from the repository root. `PROOF_PATH` must name a JSON file that holds a legacy proof and its 16 public signals, such as the file written by `clearproof prove --output artifacts/latest_proof.json` or a saved `/proof/generate` response. Nothing creates that file automatically.

## 1. Set environment variables

```bash:run
export SEPOLIA_RPC_URL="https://rpc.sepolia.org"
export DEPLOYER_PRIVATE_KEY="YOUR_VASP_WALLET_PRIVATE_KEY"
export COMPLIANCE_REGISTRY="YOUR_COMPLIANCE_REGISTRY_ADDRESS" # a registry deployed from current source; do not use the July 20 historical record
export PROOF_PATH="$PWD/artifacts/latest_proof.json"
export TRANSFER_ID="recipe-transfer-001"
export VASP_DID="did:web:vasp.example.com"
```

Expected: No output (variables set)

## 2. Submit proof to ComplianceRegistry

```bash:run
(cd packages/contracts && npx hardhat run scripts/verify-onchain.ts --network sepolia)
```

Expected: Transaction hash and `ProofVerified` event emitted with the blinded nullifier

## 3. Confirm the transfer is recorded

```bash:run
(cd packages/contracts && npx hardhat run scripts/check-transfer.ts --network sepolia)
```

Expected: `isVerified` returns `true` for the transfer ID
