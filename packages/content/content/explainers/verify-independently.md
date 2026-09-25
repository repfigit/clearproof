---
id: UP-EX-004
title: Verifying a Clearproof proof without trusting Clearproof
date: 2026-09-21
publishAfter: 2026-09-21T00:00:00Z
sourceCommit: cd63c3a06b978b5401ff9641260882c96fa31037
claimRefs:
  - packages/proof/src/verifier.ts
  - packages/proof/src/thresholds.ts
  - packages/contracts/contracts/ComplianceRegistry.sol
  - README.md
status: approved
summary: Clearproof's TypeScript SDK ships no baked-in proving or verification keys, and the CLI's verify command takes a proof file plus any verification key you point it at. This explainer walks through what an independent verifier can check — and the one signal block that a pairing check alone would let a prover abuse.
canonical: /explainers/verify-independently
templateVersion: explainer-v1
---

*Scope: this explainer walks through the SDK's `verifyProof` path for the
legacy 16-signal demo profile. Current `pilot-transfer-v3` proofs publish eight
values with no tier thresholds or review flag, and are checked by the pilot's
authorization service; see [the eight public signals](/explainers/pilot-proof-public-signals).*

A fair question for any compliance tool: do you have to trust the vendor to
check its own proofs? In Clearproof's current source, the answer is no —
verification is caller-supplied and separately runnable. This explainer walks
through what an independent verifier can check with only the public source, the
proof, and a verification key, and where the checks are stricter than a bare
pairing check.

## No baked-in keys

The [`@clearproof/proof`](https://github.com/repfigit/clearproof/blob/main/packages/proof/AGENTS.md)
SDK has **no baked-in artifacts**. `verifyProof` reads the verification key
from a caller-supplied `vkeyPath` and hands the proof, the public signals and
that key straight to `snarkjs.groth16.verify`. Nothing about the result depends
on a Clearproof-operated service. The CLI's `verify` command follows the same
shape: `--proof <file>` plus an `--artifacts <dir>` the caller controls, and it
exits non-zero when verification fails.

That design has a consequence worth stating: the security of a verification
inherits the provenance of the verification key. An independent verifier
should obtain `verification_key.json` from a source it controls or has
audited — the project's own documentation notes that production proving keys
are expected to come from a documented multi-party ceremony, and that
development artifacts are local-only and not safe for production. The tool
does not make that choice for you; it refuses to hide it.

## What a pairing check alone would miss

The circuit takes the tier thresholds (`tier2_threshold`, `tier3_threshold`,
`tier4_threshold` — public signals 8 through 10) as **unconstrained public
inputs**. The prover chooses them. A proof could therefore be cryptographically
valid while embedding an arbitrarily high `tier2_threshold`, landing any
transfer amount in tier 1 and defeating both the tier attestation and the SAR
review flag.

Clearproof's verifier handles this explicitly rather than leaving it to the
caller: `verifyProof` returns `valid = proofValid && thresholdsBound`, where
`thresholdsBound` checks the submitted thresholds against the jurisdiction
table in [`packages/proof/src/thresholds.ts`](https://github.com/repfigit/clearproof/blob/main/packages/proof/src/thresholds.ts).
That module's own comment is the design rationale: these thresholds are a
*consensus parameter*, not a local preference — if the table disagrees with the
Python SDK or the on-chain `ComplianceRegistry`, proofs will verify in one
place and fail in another.

The on-chain registry enforces the same discipline. `ComplianceRegistry`'s
`verifyAndRecord` deliberately rejects any proof whose thresholds disagree
with the table stored on-chain, and its threshold-setting function reverts if
the table is not strictly ordered (`tier2 < tier3 < tier4`), because an
out-of-order table would silently make some tiers unreachable.

## The other signals an independent verifier can read

Beyond the two interpreted outputs — `publicSignals[0]` is `is_compliant`,
`publicSignals[1]` is `sar_review_flag` — the full signal array is returned
with the verification result, so a reviewer can check:

- **Jurisdiction** (signal 6), decodable from its big-endian ASCII value
  ("US" → `0x5553`); a value that is not two uppercase ASCII letters decodes
  to `null` rather than a plausible-looking code.
- **Jurisdiction–VASP consistency**, via the optional
  `expectedJurisdiction` argument. The result distinguishes a real mismatch
  from *unverified*: with no expected jurisdiction supplied,
  `jurisdictionMatchesVASP` is `null`, never silently `true`.
- **Rejection reasons**: the result carries explicit `rejectionReasons`
  (`groth16_invalid`, `threshold_mismatch`) instead of a bare boolean, so a
  failed verification says *why*.

## What independent verification does not establish

A valid verification is a statement about one proof against one key. It does
not establish that the input commitments behind the proof came from trusted
records, that the sanctions root is current (the root is relayed across
deployed chains and staleness is a live deployment question), or that any
counterparty's policy obligations are met. Those remain the registry and
application checks described in the [previous
explainer](/explainers/who-verifies-what).

## The practical takeaway

For an evaluator, the check is concrete and runnable today: take a proof file,
a verification key from a source you control, and run the CLI's `verify`
command — the same pairing check the project itself relies on, with the
threshold-binding check that a bare snarkjs call would skip. The source makes
that path deliberately short, and deliberately honest about what a valid proof
still leaves open.
