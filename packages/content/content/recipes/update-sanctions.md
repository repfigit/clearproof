---
title: Update Sanctions Tree
prereqs:
  - api-running
  - contracts-deployed
estimated-time: 2 min
---

# Update Sanctions Tree

Rebuild the sanctions Merkle tree from OFAC/UN/EU lists and relay the new root to the on-chain SanctionsOracle.

## 1. Build the sanctions tree

```bash:run
python scripts/build_sanctions_tree.py --offline
```

Expected: Tree built with leaf count printed, root hash displayed. The `--offline` flag uses cached list data; omit it to fetch fresh lists from OFAC/UN/EU sources.

## 2. Relay the new root to SanctionsOracle

```bash:run
python scripts/relay_sanctions_root.py --network sepolia
```

Expected: Transaction hash printed, `RootUpdated` event emitted on SanctionsOracle with new root and leaf count

## 3. Verify the oracle is not stale

```bash:run
cd packages/contracts && npx hardhat run scripts/check-oracle-staleness.ts --network sepolia
```

Expected: `isStale` returns `false`, `lastUpdated` is recent
