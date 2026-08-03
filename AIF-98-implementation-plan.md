# AIF-98 Implementation Plan

## Problem Summary
The issue is that `jurisdiction_code` (public signal 6) in compliance proofs is not verified against the VASP's registered jurisdiction in the VASPRegistry contract. This means a prover can claim any jurisdiction to get looser thresholds, potentially bypassing SAR review requirements.

## Key Files to Modify

1. `/home/agent/code/clearproof/packages/contracts/contracts/ComplianceRegistry.sol` - Add jurisdiction verification
2. `/home/agent/code/clearproof/src/api/routes/proof.py` - Add jurisdiction verification in off-chain verification
3. `/home/agent/code/clearproof/packages/proof/src/thresholds.ts` - Add helper function for jurisdiction matching
4. `/home/agent/code/clearproof/src/prover/tier_mapping.py` - Add helper function for jurisdiction matching

## Implementation Steps

### Step 1: Update ComplianceRegistry.sol
Add a new event `JurisdictionMismatch` and modify `verifyAndRecord` to check jurisdiction.

### Step 2: Update proof.py
Add jurisdiction matching check in `/proof/verify` endpoint and include `jurisdiction_matches_vasp` in response.

### Step 3: Update TypeScript helper
Add jurisdiction matching function to `thresholds.ts`.

### Step 4: Update Python helper
Add jurisdiction matching function to `tier_mapping.py`.