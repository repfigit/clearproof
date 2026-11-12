---
title: Deploy the Legacy Contracts to Sepolia
prereqs:
  - sepolia-rpc
  - funded-deployer
estimated-time: 5 min
---

# Deploy the Legacy Contracts to Sepolia

> **Legacy demo path.** `scripts/deploy.ts` deploys the legacy 16-signal contracts: VerifierRouter, Groth16Verifier, VASPRegistry, SanctionsOracle and ComplianceRegistry. It does not deploy the `pilot-transfer-v3` contracts (`PilotGroth16Verifier`, `PilotCurrentRegistry`, `PilotRootCheckpoint`), which have no committed deployment and no deployment recipe. The committed verifier embeds a development key; nothing here is audited.

Run the steps from the repository root, with testnet funds only.

## 1. Set environment variables

```bash:run
export SEPOLIA_RPC_URL="https://rpc.sepolia.org"
export DEPLOYER_PRIVATE_KEY="YOUR_DEPLOYER_PRIVATE_KEY"
export ETHERSCAN_API_KEY="YOUR_ETHERSCAN_API_KEY"
export CLEARPROOF_DEPLOYMENTS_DIR="$HOME/clearproof-deployments"
```

Expected: No output (variables set)

Hardhat reads the signer from `DEPLOYER_PRIVATE_KEY`. `CLEARPROOF_DEPLOYMENTS_DIR` is where the deploy script writes its address record. Without it the script overwrites `packages/contracts/deployments/sepolia.json`, the committed July 20, 2026 historical record.

## 2. Compile contracts

```bash:run
(cd packages/contracts && npx hardhat compile)
```

Expected: `Compiled N Solidity files successfully`, or `Nothing to compile` when the build is current

## 3. Deploy the contracts

This step is not run by `clearproof recipes --run`: it sends several transactions and usually takes longer than the 60-second step limit. Run it yourself in the same shell as step 1.

```bash
(cd packages/contracts && npx hardhat run scripts/deploy.ts --network sepolia)
```

Expected: five contract addresses printed and written to `$CLEARPROOF_DEPLOYMENTS_DIR/sepolia.json`. The verifier is registered behind the router's 24-hour timelock, so the script reports `Verifier registration pending until chain timestamp: ...`. The deploy script does not activate it: after that time the router admin must call `activateVerifier(selector, name)`, and the registry cannot verify proofs until then.

## 4. Block explorer verification

There is no separate verification script. When `ETHERSCAN_API_KEY` is set, `scripts/deploy.ts` submits the five contracts for verification at the end of step 3 and prints `All contracts verified!` or `Verification failed (can retry later): ...`. A verification failure does not undo the deployment.

To use the new deployment with the `verify-onchain` recipe, set `COMPLIANCE_REGISTRY` to the ComplianceRegistry address from the record.
