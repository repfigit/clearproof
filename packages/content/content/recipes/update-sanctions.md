---
title: Update Sanctions Tree
prereqs:
  - contracts-deployed
estimated-time: 2 min
---

# Update Sanctions Tree

> **Legacy demo path.** This recipe updates the legacy 16-signal tree and its `SanctionsOracle`. The current `pilot-transfer-v3` profile uses a separate tree (`scripts/build_pilot_sanctions_tree.py`) and a signed head published with `scripts/publish_pilot_sanctions_head.py`; this recipe does not update it.

Rebuild the legacy sanctions Merkle tree and submit the new root to a `SanctionsOracle` you deployed. Run the steps from the repository root.

## 1. Build the sanctions tree

```bash:run
python scripts/build_sanctions_tree.py --offline
```

Expected: Tree built with leaf count printed, root hash displayed, `artifacts/sanctions_tree.json` written. `--offline` skips the HTTP fetches and uses only the addresses hardcoded in the script; omit it to fetch the OFAC and EU lists.

## 2. Submit the new root to SanctionsOracle

This step is not run by `clearproof recipes --run`: the script shows the current and proposed roots and waits for you to type a confirmation, and `--run` gives steps no terminal input. Run it yourself. It needs `SEPOLIA_RPC_URL`, `DEPLOYER_PRIVATE_KEY` (the oracle's operator wallet) and the oracle address in `packages/contracts/deployments/sepolia.json`.

```bash
make update-sanctions-oracle NETWORK=sepolia
```

Expected: the current on-chain root, leaf count, last update time and `Stale:` state, then the proposed update. After you confirm, a transaction hash and `Sanctions oracle root updated successfully`. The oracle enforces a one-hour cooldown between updates and rejects a tree with fewer than half the current leaves.

To submit the same root to every network that has a deployment file, use `make relay-sanctions`.

## 3. Confirm the oracle state

Run the command from step 2 again. It reads the oracle before proposing anything. When the on-chain root equals the tree root it prints `On-chain root already matches tree. Nothing to do.` and exits without sending a transaction. Check that `Stale:` is `false`.
