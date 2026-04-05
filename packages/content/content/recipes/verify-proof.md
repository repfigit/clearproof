---
title: Verify a Proof Off-Chain
prereqs:
  - api-running
  - proof-generated
estimated-time: 1 min
---

# Verify a Proof Off-Chain

Take an existing compliance proof and verify it locally using the API server. This does not interact with any blockchain.

## 1. Verify the proof

```bash:run
curl -s -X POST http://localhost:8000/proof/verify \
  -H "Content-Type: application/json" \
  -d '{"proof_id":"PROOF_ID_FROM_GENERATE","groth16_proof":{"pi_a":["..."],"pi_b":["..."],"pi_c":["..."]},"public_signals":["1","0","..."],"expected_amount_tier":2,"originator_vasp_did":"did:web:vasp.example.com","transfer_timestamp":1711929600}'
```

Expected: 200 with `valid: true` and `compliance_attestations` showing `is_compliant: true`

The verification checks:
- Groth16 proof is cryptographically valid against the verification key
- `is_compliant` signal equals 1
- Amount tier matches the expected tier
- Transfer timestamp is reasonable
