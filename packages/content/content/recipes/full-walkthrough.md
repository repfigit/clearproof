---
title: Full End-to-End Walkthrough
prereqs:
  - api-running
  - circuits-compiled
  - contracts-deployed
  - sepolia-rpc
estimated-time: 10 min
---

# Full End-to-End Walkthrough

Complete compliance flow: issue a credential, generate a proof, verify off-chain, and record on-chain.

## 1. Build the sanctions tree

```bash:run
python scripts/build_sanctions_tree.py --offline
```

Expected: Sanctions tree built with root hash and leaf count displayed

## 2. Issue a zkKYC credential

```bash:run
curl -s -X POST http://localhost:8000/credential/issue \
  -H "Content-Type: application/json" \
  -d '{"issuer_did":"did:web:vasp.example.com","subject_wallet":"0x1234abcd5678ef901234abcd5678ef9012345678","jurisdiction":"US","kyc_tier":"retail"}'
```

Expected: 200 with `credential_id` and `commitment`

## 3. Generate a compliance proof

```bash:run
curl -s -X POST http://localhost:8000/proof/generate \
  -H "Content-Type: application/json" \
  -d '{"credential_id":"CRED_ID_FROM_STEP_2","wallet_address":"0x1234abcd5678ef901234abcd5678ef9012345678","amount_usd":500,"asset":"USDC","destination_wallet":"0xabcd1234abcd1234abcd1234abcd1234abcd1234","jurisdiction":"US","idempotency_key":"recipe-full-001"}'
```

Expected: 200 with `compliance_proof` (Groth16 proof + 16 public signals) and `encrypted_pii`

## 4. Verify the proof off-chain

```bash:run
curl -s -X POST http://localhost:8000/proof/verify \
  -H "Content-Type: application/json" \
  -d '{"proof_id":"PROOF_ID_FROM_STEP_3","groth16_proof":{"pi_a":["..."],"pi_b":["..."],"pi_c":["..."]},"public_signals":["1","0","..."],"expected_amount_tier":1,"originator_vasp_did":"did:web:vasp.example.com","transfer_timestamp":1711929600}'
```

Expected: 200 with `valid: true` and `is_compliant: true`

## 5. Record the proof on-chain

```bash:run
cd packages/contracts && npx hardhat run scripts/verify-onchain.ts --network sepolia
```

Expected: Transaction hash and `ProofVerified` event emitted on ComplianceRegistry

## 6. Confirm on-chain recording

```bash:run
cd packages/contracts && npx hardhat run scripts/check-transfer.ts --network sepolia
```

Expected: `isVerified` returns `true` for the transfer ID
