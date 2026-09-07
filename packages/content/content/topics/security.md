---
title: Security
category: operations
order: 7
cli-topic: security
---

# Security and assurance

Last reviewed: September 5, 2026.

clearproof is **pre-production, pilot-stage software**. Independent circuit and contract audits have not been completed. Current proving artifacts use a development-only trusted setup. Testnet deployment and passing tests do not establish production safety.

## Current boundaries

- A cryptographically valid proof is not the same as an accepted transfer. Current off-chain verification does not yet reproduce every registry acceptance check.
- Credential authenticity, holder authority, jurisdiction and actual transfer binding require coordinated improvements across the proof statement and application.
- Recipient HPKE and legacy AES-256-GCM components exist. Key trust, discovery, rotation, failure behavior and migration need explicit integration validation.
- Public signals expose metadata, including an advisory review signal in the current proof version. Omitting a named field from a bridge does not conceal information that remains in its public-signal array.
- Domain, expiry, root and replay checks depend on the verifier and its configuration. The site does not claim that replay is universally impossible.
- Persistent storage and authentication components do not yet constitute complete durable tenant isolation.

## Controls to evaluate

Use synthetic records and testnet funds. Check approved issuer/root/artifact provenance, recipient identity, key purpose, freshness, revocation, transfer binding and duplicate handling. Confirm that sensitive inputs remain inside authorized encrypted data flows and do not appear in logs or exports.

`PII_MASTER_KEY` startup validation checks accepted encoding and minimum length. It cannot establish that a supplied value has adequate randomness. Generate secrets securely and manage retention, backup and rotation deliberately.

## Vulnerability reporting

The repository security policy lists **security@clearproof.dev** as its reporting address. Share reproduction steps and impact privately; do not post sensitive exploit details or personal information in a public issue. This documentation does not verify mailbox operation or promise a response-time SLA.

No active paid bug-bounty program is announced here. See [project status](/docs/status) for the implementation and assurance work that remains.
