---
title: API Reference
category: reference
order: 5
cli-topic: api
---

# API reference

The Python API is a development component. These routes reflect the 0.4.0 checkout as reviewed September 5, 2026; the published npm package versions are separate.

Use the running application's [local OpenAPI UI](http://localhost:8000/docs) for exact request and response schemas. The API's displayed internal version may differ from the repository package version.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /health` | Process health |
| `GET /metrics` | Operational counters |
| `GET /auth/nonce` | SIWE challenge |
| `POST /auth/verify` | SIWE signature verification |
| `POST /credential/issue` | Development credential issuance |
| `POST /credential/revoke` | Credential revocation request |
| `POST /proof/generate` | Proof generation and payload assembly |
| `POST /proof/verify` | Current off-chain verification path |
| `GET /.well-known/clearproof.json` | Self-declared discovery metadata |

Protected routes require the configured authentication mode. API-key mode uses `X-API-Key`; JWT/SIWE integrations use the corresponding authentication flow. Do not embed keys in published examples.

## Generation prerequisites

The current generation request includes credential ID, originator and destination wallets, amount, asset, jurisdiction and an idempotency key. Runtime state must include matching credential/issuer information, sanctions witnesses and compatible proving artifacts. Sensitive optional identity fields belong in authorized encrypted workflows.

The current amount request uses a floating-point USD field and asset symbol. Exact asset/amount identity and authenticated transfer binding are planned improvements; this interface is not a production accounting contract.

## Verification limits

The response includes `valid`, `proof_id`, `compliance_attestations`, `verified_at` and `rejection_reasons`. A successful response does not establish equivalence with every on-chain registry check. Do not infer fund-movement authorization or legal compliance from the response alone.

Durable tenant state, credential authenticity, witness consistency and verifier parity remain active work. See [status](/docs/status) and [security](/docs/security).


## Wallet ownership extension (source checkout)

A five-minute EOA signing challenge produces a 24-hour revocable attestation for
one enrolled credential in the authenticated tenant. Routes are
`/wallet/ownership/challenge`, `/wallet/ownership/verify`,
`/wallet/ownership/attestations/{id}`, `/wallet/ownership/revoke` and
`/wallet/ownership/credential`. The optional extension has a separate commitment;
existing credential/proof formats are unchanged. Its circuit is staged and is
not accepted by deployed verifiers. See the
[wallet ownership guide](https://github.com/repfigit/clearproof/blob/main/docs/internal/WALLET_OWNERSHIP.md)
for the full flow, signing helper and trust boundaries.
