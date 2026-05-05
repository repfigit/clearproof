---
title: Verify a Proof On-Chain
prereqs:
  - contracts-deployed
  - proof-generated
  - sepolia-rpc
estimated-time: 3 min
---

# Verify a Proof On-Chain

Submit a compliance proof to the ComplianceRegistry contract on Sepolia testnet. The contract performs 14 checks including Groth16 verification, sanctions root validation, and nullifier uniqueness.

## 1. Set environment variables

```bash:run
export SEPOLIA_RPC_URL="https://rpc.sepolia.org"
export DEPLOYER_PRIVATE_KEY="YOUR_VASP_WALLET_PRIVATE_KEY"
export COMPLIANCE_REGISTRY="YOUR_COMPLIANCE_REGISTRY_ADDRESS" # optional if deployments/sepolia.json exists
export PROOF_PATH="$PWD/../../artifacts/latest_proof.json"
export TRANSFER_ID="recipe-transfer-001"
export VASP_DID="did:web:vasp.example.com"
```

Expected: No output (variables set)

## 2. Submit proof to ComplianceRegistry

```bash:run
cd packages/contracts && npx hardhat run scripts/verify-onchain.ts --network sepolia
```

Expected: Transaction hash and `ProofVerified` event emitted with the blinded nullifier

## 3. Confirm the transfer is recorded

```bash:run
cd packages/contracts && npx hardhat run scripts/check-transfer.ts --network sepolia
```

Expected: `isVerified` returns `true` for the transfer ID
