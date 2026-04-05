---
title: Deploy Contracts to Sepolia
prereqs:
  - sepolia-rpc
  - funded-deployer
estimated-time: 5 min
---

# Deploy Contracts to Sepolia

Deploy the full contract suite (Groth16Verifier, SanctionsOracle, VASPRegistry, ComplianceRegistry, SanctionsRootRelay) to Sepolia testnet and verify on Etherscan.

## 1. Set environment variables

```bash:run
export SEPOLIA_RPC_URL="https://rpc.sepolia.org"
export PRIVATE_KEY="YOUR_DEPLOYER_PRIVATE_KEY"
export ETHERSCAN_API_KEY="YOUR_ETHERSCAN_API_KEY"
```

Expected: No output (variables set)

## 2. Compile contracts

```bash:run
cd packages/contracts && npx hardhat compile
```

Expected: `Compiled N Solidity files successfully`

## 3. Deploy all contracts

```bash:run
cd packages/contracts && npx hardhat run scripts/deploy.ts --network sepolia
```

Expected: Five contract addresses printed, deployment artifacts written to `deployments/sepolia/`

## 4. Verify on Etherscan

```bash:run
cd packages/contracts && npx hardhat run scripts/verify-etherscan.ts --network sepolia
```

Expected: All five contracts verified on Sepolia Etherscan with green checkmarks
