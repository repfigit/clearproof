---
title: Circuits
category: concepts
order: 3
cli-topic: circuits
---

# Circuits

The current circuit uses Circom/Groth16. CI compiles with circom **2.2.2**. Constraint counts and performance depend on the exact source, compiler and artifacts; this page does not state a current benchmark.

These are unaudited development components. See [security](/docs/security).

## Circuit hierarchy

```text
ComplianceProof(20, 10)
├── SanctionsNonMembership(20)
├── CredentialValidity(10)
└── AmountTier()
```

The main circuit also carries transfer, domain and expiry signals. Some acceptance properties are enforced by the registry rather than inside the circuit.

## Public signals

The current schema has two outputs and fourteen public inputs, appearing as sixteen values in the verification interface. They are public metadata, not automatically anonymous data.

| Index | Signal |
| --- | --- |
| 0 | `is_compliant` |
| 1 | `sar_review_flag` |
| 2 | `sanctions_tree_root` |
| 3 | `issuer_tree_root` |
| 4 | `amount_tier` |
| 5 | `transfer_timestamp` |
| 6 | `jurisdiction_code` |
| 7 | `credential_commitment` |
| 8–10 | `tier2_threshold`, `tier3_threshold`, `tier4_threshold` |
| 11 | `domain_chain_id` |
| 12 | `domain_contract_hash` |
| 13 | `transfer_id_hash` |
| 14 | `credential_nullifier` |
| 15 | `proof_expires_at` |

Public-signal changes require coordinated updates to the circuit, SDKs, contracts and fixtures. Jurisdiction is encoded from the two-letter code as a big-endian integer, such as `US` → 21843.

## Sanctions non-membership

The sorted-tree gap construction uses neighboring leaves and Merkle paths to check that the queried value lies between them. Adjacency is derived from path bits and compared values are range-checked.

This establishes a fact about the supplied tree. Authenticity, completeness and freshness of the screening source, and binding the queried wallet to the real transfer, are separate requirements.

## Credential validity

The current construction checks a credential commitment preimage, expiry relative to the transfer timestamp and issuer membership. Issuer membership alone does not authenticate an actually issued credential. Stronger subject, jurisdiction, holder and issuance binding is planned.

## Amount tier

The circuit compares an amount against three ordered public thresholds and checks the claimed tier. The verifier must authenticate the thresholds and the meaning/units of the amount.

The current `sar_review_flag` is a public tier-derived advisory output. It is not a suspicious-activity determination or filing instruction. Confidential advisory handling needs a coordinated proof-version change.

## Compiling

```bash
bash scripts/compile_circuits.sh
```

This requires the appropriate local toolchain and Powers of Tau input. Development setup artifacts are not production keys. Use `SanctionsNonMembership`; the legacy free-input `MerkleNonMembership` helper has been removed.
