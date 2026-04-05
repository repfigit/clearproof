---
title: API Reference
category: reference
order: 5
cli-topic: api
---

# API Reference

The clearproof API server is a Python FastAPI application.

```bash
PII_MASTER_KEY=$(openssl rand -hex 32) uv run uvicorn src.api.main:app --reload --port 8000
```

Interactive docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## Authentication

All endpoints except `/health` and `/auth/*` require a JWT bearer token obtained via SIWE (Sign-In With Ethereum).

### GET `/auth/nonce`

Returns a one-time nonce for SIWE signature. Rate limit: 60/min per IP.

### POST `/auth/verify`

Verifies a SIWE signature and returns a JWT.

```json
{
  "message": "clearproof.world wants you to sign in...",
  "signature": "0x..."
}
```

## Proof generation

### POST `/proof/generate`

Generates a Groth16 compliance proof and hybrid payload. Rate limit: 30/min per IP.

**Request body:**

```json
{
  "credential_id": "cred-xyz",
  "wallet_address": "0x1234...",
  "amount_usd": 15000.00,
  "asset": "USDC",
  "destination_wallet": "0x5678...",
  "destination_vasp_did": "did:web:counterparty.example",
  "jurisdiction": "US",
  "idempotency_key": "tx-abc-123",
  "originator_name": "Jane Doe",
  "originator_address": "123 Main St",
  "originator_account": "acct-456"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `credential_id` | string | Yes | zkKYC credential ID |
| `wallet_address` | string | Yes | Originator wallet address |
| `amount_usd` | float | Yes | Transfer amount in USD |
| `asset` | string | Yes | Asset symbol (e.g., USDC, ETH) |
| `destination_wallet` | string | Yes | Beneficiary wallet address |
| `destination_vasp_did` | string | No | Beneficiary VASP DID |
| `jurisdiction` | string | Yes | ISO 3166-1 alpha-2 (e.g., "US", "SG") |
| `idempotency_key` | string | Yes | Client-supplied key for retries |
| `originator_name` | string | No | Required for tier 3+ transfers (IVMS101) |
| `originator_address` | string | No | Originator physical address |
| `originator_account` | string | No | Originator account number |

**Response:** Returns a `HybridPayload` containing the `ComplianceProof` (proof, 16 public signals, verification key, metadata) and encrypted PII (AES-256-GCM ciphertext, nonce, associated data).

### POST `/proof/verify`

Verifies a proof locally (off-chain). Rate limit: 30/min per IP.

**Request body:**

```json
{
  "proof_id": "uuid-here",
  "groth16_proof": { "pi_a": ["..."], "pi_b": ["..."], "pi_c": ["..."] },
  "public_signals": ["1", "0", "..."],
  "expected_amount_tier": 2,
  "originator_vasp_did": "did:web:originator.example",
  "transfer_timestamp": 1711929600
}
```

**Response:**

```json
{
  "valid": true,
  "proof_id": "uuid-here",
  "compliance_attestations": {
    "is_compliant": true,
    "sar_review_flag": false,
    "amount_tier": 2,
    "jurisdiction": "US"
  },
  "verified_at": 1711929605
}
```

## Credentials

### POST `/credential/issue`

Issues a new zkKYC credential.

### POST `/credential/revoke`

Revokes a credential by ID.

### GET `/credential/{credential_id}`

Returns credential status (`active`, `revoked`, `expired`).

## Health

### GET `/health`

Liveness probe. Returns `{"status": "ok"}`.

### GET `/metrics`

Operational metrics. Requires JWT authentication (same as other authenticated endpoints).

## Startup requirements

The server validates at startup:

1. **PII_MASTER_KEY entropy** -- must be >= 32 bytes
2. **Verification key** -- `verification_key.json` must exist in the artifacts directory
3. **CORS configuration** -- warns if `CORS_ALLOWED_ORIGINS` is `*` with credentials
