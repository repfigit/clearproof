---
title: Generate a Compliance Proof
prereqs:
  - api-running
  - circuits-compiled
estimated-time: 2 min
---

# Generate a Compliance Proof

Issue a zkKYC credential and then generate a Groth16 compliance proof against it.

## 1. Issue a credential

```bash:run
curl -s -X POST http://localhost:8000/credential/issue \
  -H "Content-Type: application/json" \
  -d '{"issuer_did":"did:web:vasp.example.com","subject_wallet":"0x1234abcd5678ef901234abcd5678ef9012345678","jurisdiction":"US","kyc_tier":"retail"}'
```

Expected: 200 with `credential_id` and `commitment`

## 2. Generate proof

```bash:run
curl -s -X POST http://localhost:8000/proof/generate \
  -H "Content-Type: application/json" \
  -d '{"credential_id":"CRED_ID_FROM_STEP_1","wallet_address":"0x1234abcd5678ef901234abcd5678ef9012345678","amount_usd":500,"asset":"USDC","destination_wallet":"0xabcd1234abcd1234abcd1234abcd1234abcd1234","jurisdiction":"US","idempotency_key":"recipe-generate-001"}'
```

Expected: 200 with `compliance_proof` containing Groth16 proof, 16 public signals, and `encrypted_pii`
