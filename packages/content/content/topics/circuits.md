---
title: Circuits
category: concepts
order: 3
cli-topic: circuits
---

# Circuits

clearproof uses Circom and Groth16 over BN254. CI compiles with circom **2.2.2**. These are unaudited development components with development-only proving keys. See [security](/docs/security).

There are two proof profiles. **Never select a profile by its signal count.**

| Profile | Circuit | Public signals | Status |
| --- | --- | --- | --- |
| `pilot-transfer-v3` | `pilot_compliance.circom` | 8 | **Current** pilot profile |
| `pilot-transfer-v2` / `v1` | same circuit, earlier tree depths or binding | 8 | Historical; current checks reject them |
| Legacy | `compliance.circom` | 16 | Separate demo and parity path; never current pilot authorization |

## Current profile: pilot-transfer-v3

The circuit is instantiated as `PilotCompliance(32, 20, 20)`: an issuance tree of depth 32 (about 4.3 billion credentials per issuer), an authorized-issuer tree of depth 20 and a sanctions tree of depth 20 (1,048,574 addresses plus two boundary leaves). It has 95,408 constraints and needs `2^17` powers-of-tau parameters. The authoritative statement is [`specs/pilot-transfer-v3.md`](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md).

```text
PilotCompliance(32, 20, 20)
├── PilotTransferProjection   48 private transfer fields, exact valuation, private tier
├── PilotCredentialValidity   credential, holder secret, issuance and issuer membership
└── PilotSanctionsGap × 2     raw-address non-membership for originator and beneficiary
```

### Public signals

| Index | Signal | What the circuit enforces |
| --- | --- | --- |
| 0 | `projection_commitment` | Commits to the private transfer projection, the exact credential and the issuance root |
| 1 | `authorized_issuer_root` | The credential's issuer is a member of this tree |
| 2 | `sanctions_root` | Neither wallet is in this sorted address tree |
| 3 | `authorization_nullifier` | Derived from the holder secret and the transfer's authorization scope |
| 4 | `evaluated_at` | Evaluation time; the credential must be valid at this time |
| 5 | `proof_expires_at` | Later than `evaluated_at`, and no later than the transfer expiry, the credential expiry or `evaluated_at` + 300 seconds |
| 6 | `domain_chain_id` | Equals the private deployment field only; the registry checks the real chain |
| 7 | `domain_registry` | Equals the private deployment field only; the registry checks its own address |

The amount, tier, wallets, jurisdiction, participants and credential fields are **private**. There is no public amount tier or review flag. A verifier must reconstruct signal 0 from its own authenticated records; a proof that verifies cryptographically says nothing about which transfer it covers until that check passes.

### What each part checks

- **Transfer projection.** All 48 fields are range-checked. Time ordering (observation ≤ creation ≤ evaluation < transfer expiry ≤ quote expiry), maximum age, decimals and nonzero identities are enforced. The amount is converted to USD cents with exact integer arithmetic, and the tier is derived privately from the policy thresholds.
- **Credential.** The credential commitment must be a member of the issuance root, and the issuer's leaf must be a member of the authorized-issuer root. The holder must know the secret behind the credential's holder commitment. Tenant, subject wallet and jurisdiction must match the transfer.
- **Sanctions.** A sorted-tree gap proof shows each raw 160-bit wallet address lies strictly between two adjacent leaves. Adjacency is derived from the Merkle path bits, and all compared values are range-checked.
- **Replay and expiry.** The nullifier stays the same for a given holder and transfer scope, so a replacement proof cannot be spent twice. The five-minute expiry bound is enforced in the circuit.

Some acceptance properties live outside the circuit. The authorization service checks current roots, revocation, policy and signed facts, and consumes the nullifier in PostgreSQL. `PilotCurrentRegistry` checks the chain ID, its own address and the expiry against published statements. See [architecture](/docs/architecture).

## Legacy profile

`ComplianceProof(20, 10)` in `compliance.circom` publishes 16 values, including `is_compliant`, a tier-derived `sar_review_flag`, the amount tier, the jurisdiction and the tier thresholds. It remains a demo and parity path with its own verifier, SDK function and tests. Legacy proofs are never current pilot authorization.

## Building development artifacts

```bash
.venv/bin/python scripts/test_development_circuits.py /absolute/new-directory \
  --prepared-ptau /absolute/ppot_0080_17.ptau
```

This compiles both profiles, creates explicitly unapproved development keys and runs real proof round trips. CI uses the SHA-256-pinned [PSE perpetual powers of tau](https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_17.ptau) file (`f807e065…3a367c`). Without `--prepared-ptau`, a local single-party `2^17` setup is generated, which can take over an hour. Development keys are not production keys; the production setup path is still an open decision (ADR 0004).
