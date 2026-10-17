---
id: UP-EX-011
title: Rejecting more than bad proofs — scalar aliasing, infinity and non-canonical points in a BLS verifier
date: 2026-10-19
publishAfter: 2026-10-19T00:00:00Z
sourceCommit: 88edbc805e18aa3646ba41d25cd06804e0c956d4
claimRefs:
  - docs/adr/0002-bls12381-migration.md
  - docs/internal/CEREMONY_RUNBOOK.md
  - CHANGELOG.md
  - scripts/generate_verifier_bls.mjs
  - packages/contracts/test/Groth16VerifierBLS.bench.ts
status: approved
summary: A pairing check can verify the equation perfectly and still accept a proof that is not a proof. The BLS12-381 benchmark verifier from ADR 0002 accepted s + r in place of a public signal s, because the G1 multi-scalar-multiplication precompile reduces scalars mod the field order. The verifier now reverts on signals at or above r, on infinity points in A, B or C, and on a non-canonical y on A — with tests for each case. This explainer walks the three edge cases and the honest scope of the fix.
canonical: /explainers/bls-verifier-edge-cases
templateVersion: explainer-v1
---

An on-chain Groth16 verifier does one thing: it calls the pairing precompile and
checks that the proof's elliptic-curve equation holds. If the equation holds,
the verifier returns true. That sounds like the whole story, but it is not.
The equation can hold for inputs that are not valid encodings of a proof at
all — and when that happens, the verifier accepts something it should reject.
The [BLS12-381 benchmark verifier](https://github.com/repfigit/clearproof/blob/main/scripts/generate_verifier_bls.mjs)
shipped with [ADR 0002](https://github.com/repfigit/clearproof/blob/main/docs/adr/0002-bls12381-migration.md)
had exactly three such gaps, and PR #113 closed all of them in October 2026.

## Scalar aliasing: s and s + r verify the same proof

The first gap is the subtlest. A Groth16 verifier computes the verification
key point vk_x as IC0 plus a weighted sum of the public signals. On BLS12-381
that sum runs through the [EIP-2537 G1 multi-scalar-multiplication precompile](https://eips.ethereum.org/EIPS/eip-2537),
and — like every MSM — it reduces scalars modulo r, the order of the scalar
field. So a caller submitting s + r in place of the public signal s produces
the same vk_x, the same pairing check, and the same `true`.

That matters because public signals are the part of a proof everyone can read:
in the Clearproof pilot they include chain-ID and registry-address binding
fields. A verifier that cannot distinguish s from s + r cannot fully enforce
what those bindings claim. The generated verifier now reverts with
`PublicSignalExceedsScalarField` if any public signal is at or above r, before
the MSM is called:

- every signal is checked against the scalar-field constant in the contract,
- and the [benchmark test](https://github.com/repfigit/clearproof/blob/main/packages/contracts/test/Groth16VerifierBLS.bench.ts)
  covers the s + r alias directly, not just an arbitrary out-of-field value.

## Infinity: a point that is "valid" and proves nothing

The second gap is encoding, not algebra. Under EIP-2537, the point at infinity
is encoded as all-zero bytes, and the pairing precompile accepts it. A proof
with A, B or C set to infinity can therefore sail through a pairing check that
was written for well-formed curve points. The verifier now reverts with
`ProofPointAtInfinity` if any of the three proof points is the all-zero
encoding — a defense-in-depth check the ADR explicitly calls for.

## Non-canonical coordinates: what the precompile never sees

The third gap hides in negation. The verifier negates the A point before the
pairing call, and the precompile only ever sees q − y, never A's original y
coordinate. A non-canonical y — a value at or above the base-field modulus q —
would be silently folded into a valid-looking negation. The verifier now
checks the raw 64-byte limb against the base-field constants and reverts with
`ProofPointNotCanonical` before negating anything.

Together with the pre-existing length and signal-count checks and a tampered
proof rejection test, the benchmark suite now covers each rejected class
separately: malformed lengths and signal counts, out-of-field signals
(including the s + r alias), infinity points in A, B and C, non-canonical y on
A, and a tampered proof.

## What this fix is — and is not

Honest scope matters more than a tidy story. This hardening applies to the
[ADR 0002 BLS12-381 benchmark verifier](https://github.com/repfigit/clearproof/blob/main/packages/contracts/contracts/bench/Groth16VerifierBLS.sol)
under `packages/contracts/contracts/bench/`, which runs on the EIP-2537
precompiles and is used for gas measurement against the production BN254
verifier. The [CHANGELOG](https://github.com/repfigit/clearproof/blob/main/CHANGELOG.md)
is explicit that the earlier Sepolia benchmark deployment predates the fix,
and the ADR is explicit that the deployed verifier uses the development
trusted setup and is not a production deployment.

The production path is unchanged: proving keys must come from the documented
multi-party ceremony, and the [ceremony runbook](https://github.com/repfigit/clearproof/blob/main/docs/internal/CEREMONY_RUNBOOK.md)
now targets BLS12-381 with two pre-ceremony gates — a pinned multi-party
BLS12-381 phase-1 powers-of-tau file (the BN254 Hermez file pinned for local
development cannot be used) and a re-parameterized Poseidon for the
BLS12-381 scalar field. The verifier itself is generated by
`scripts/generate_verifier_bls.mjs` — never by the snarkjs exporter, per
[ADR 0001](https://github.com/repfigit/clearproof/blob/main/docs/adr/0001-groth16-verifier-licensing.md) —
so the fixes above live in reviewed generator code, not in hand-edited
Solidity.

The takeaway generalizes beyond BLS12-381: when you port a zk-SNARK verifier
onto precompiled primitives, the precompile's algebra is not the verifier's
contract. Scalar reduction, non-canonical encodings and special points are
each a place where "the equation holds" and "this is the proof you meant"
come apart — and each one belongs in the verifier, with a test.
