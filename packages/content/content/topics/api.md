---
title: API Reference
category: reference
order: 5
cli-topic: api
---

# API reference

The Python API (FastAPI) is a development component in the source checkout, reviewed September 25, 2026. It is not part of the published npm packages. Use the running application's [local OpenAPI UI](http://localhost:8000/docs) for exact request and response schemas.

Protected routes require the configured authentication. Pilot routes also require an authenticated tenant principal with explicit roles and issuer scope; there is no implicit administrator override. PostgreSQL, storage keys and tenant trust configuration are required for the pilot routes. See [deployment](/docs/deployment).

## Pilot routes

| Route | Purpose |
| --- | --- |
| `POST /pilot/credential/enroll` | Enroll a credential with the holder wallet's signed consent |
| `POST /pilot/credential/revoke` | Revoke an enrolled credential permanently |
| `POST /pilot/policy/approve` | Approve a reviewed policy version (activation is a separate step) |
| `POST /pilot/policy/diff` | Compare a proposed policy against supplied cases |
| `POST /pilot/policy/diff/stored` | Compare a proposed policy against retained evidence |
| `POST /pilot/proof/inspect` | Read-only inspection of a current proof against current state; never consumes |
| `POST /pilot/proof/evaluate` | Explained policy evaluation of a current proof |
| `POST /pilot/proof/authorize` | Consume one authorization after an `ALLOW`, sealing information to the recipient |
| `POST /pilot/proof/observe` | Record a non-authorizing observation |
| `POST /pilot/proof/observations/read`, `/list`, `/report` | Read observations and cohort reports |
| `POST /pilot/events/ingest` | Ingest signed custody, counterparty or chain events |
| `POST /pilot/events/investigate` | Transfer investigation timeline |
| `POST /pilot/events/queue` | Paginated investigation queue |
| `POST /pilot/fireblocks/{integration_id}` | Verify and retain a signed Fireblocks notification from a tenant relay |
| `GET /pilot/usage` | Retained record counters (not billable charges) |

## Wallet ownership extension

| Route | Purpose |
| --- | --- |
| `POST /wallet/ownership/challenge` | Five-minute EOA signing challenge for an enrolled credential |
| `POST /wallet/ownership/verify` | Verify the EIP-191 signature; issue a 24-hour attestation |
| `GET /wallet/ownership/attestations/{attestation_id}` | Current attestation eligibility |
| `POST /wallet/ownership/revoke` | Revoke an attestation |
| `POST /wallet/ownership/credential` | Issue the optional versioned extension credential |

The extension circuit is staged; no deployed verifier accepts it. See the [wallet ownership guide](https://github.com/repfigit/clearproof/blob/main/docs/internal/WALLET_OWNERSHIP.md).

## Shared and legacy routes

| Route | Purpose |
| --- | --- |
| `GET /health` | Process liveness, not pilot readiness |
| `GET /metrics` | Operational counters |
| `GET /.well-known/clearproof.json` | Discovery metadata: exact `did:web` identity and HPKE key |
| `GET /auth/nonce`, `POST /auth/verify` | SIWE challenge and verification |
| `POST /credential/issue`, `POST /credential/revoke` | Legacy development credentials |
| `POST /proof/generate`, `POST /proof/verify` | Legacy 16-signal demo proof generation and verification |

The legacy routes serve the demo profile. A legacy proof is never current pilot authorization.

## Limits

A successful response is not legal compliance, settlement or a live counterparty's acceptance. Inspection and observation results never authorize a transfer. Only `/pilot/proof/authorize` consumes an authorization, and only after an `ALLOW`. See [architecture](/docs/architecture) and [security](/docs/security).
