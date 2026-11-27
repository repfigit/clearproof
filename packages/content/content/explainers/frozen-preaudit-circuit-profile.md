---
id: UP-EX-016
title: What a frozen pre-audit circuit profile guarantees — and what it refuses to claim
date: 2026-11-30
publishAfter: 2026-11-30T00:00:00Z
sourceCommit: 0233b03ecccd9f221b23a253128faa418117e357
claimRefs:
  - specs/preaudit-circuit-profile-v1.json
  - src/prover/preaudit_profile.py
  - circuits/lib/poseidon_bls12381.circom
  - scripts/generate_poseidon_constants.py
  - tests/unit/test_preaudit_profile.py
status: draft
summary: A zero-knowledge compliance system's assurance is only as trustworthy as the linkage between the code that was reviewed and the artifacts that actually run. Clearproof's frozen pre-audit circuit profile pins every circuit source file, curve parameter and compiled R1CS digest in one manifest, and a fail-closed validator rejects any drift — while explicitly printing production_eligible: false, because freezing is not an audit and no ceremony has run.
canonical: /explainers/frozen-preaudit-circuit-profile
templateVersion: explainer-v1
---

Every zero-knowledge compliance system has a question that is easy to ask and
hard to answer: when the verifier on-chain checks a Groth16 proof, which exact
circuit produced that proof, from which source files, on which curve, compiled
by which toolchain? If the answer lives in tribal knowledge, the linkage
between "what was reviewed" and "what runs" can drift silently — the same class
of cross-component failure that [the sanctions-tree-depth mismatch
explainer](/explainers/sanctions-tree-depth-must-match-circuit) covered from
the pipeline side. This explainer walks Clearproof's structural answer: a
[frozen pre-audit circuit profile
manifest](https://github.com/repfigit/clearproof/blob/main/specs/preaudit-circuit-profile-v1.json)
whose validator fails closed on any drift, and which refuses to claim more
assurance than exists.

## What the manifest pins

The profile [`clearproof-preaudit-2026-11`](https://github.com/repfigit/clearproof/blob/main/specs/preaudit-circuit-profile-v1.json)
covers three circuits: the current `pilot-transfer-v3` compliance circuit on
BN254 (8 public signals, tree depths 32/20/20, 95,408 constraints), the staged
wallet-ownership extension on BN254, and the same wallet-ownership extension
ported to BLS12-381. For each one the manifest records:

- **Source-file digests.** Every entry circuit, every `.circom` dependency and
  every generated constants file carries a SHA-256 hash and size. The pilot
  signal source (`specs/pilot-signals-v3.json`), both Poseidon constants JSON
  files and the generated Circom constants are pinned the same way.
- **A public-signal schema digest.** Each circuit's signal names, meanings,
  tree depths and domain tags are hashed, so the on-chain ABI surface is
  pinned, not just the code that produces it.
- **The compiled R1CS digest and constraint/wire counts.** Compiled artifacts
  live outside the repository, so the manifest carries the R1CS SHA-256 that a
  local compile can be checked against, and marks each entry
  `artifact_status: compiled-r1cs-pinned`.
- **Explicit assurance status.** Every circuit entry reads
  `ceremony_status: "unapproved-preaudit-no-ceremony"`, and the profile-level
  `assurance` field is `preaudit-frozen-no-ceremony`.

The last point is the one that matters most for evaluating any ZK system: the
manifest does not merely lack a claim of audit-grade assurance — it *asserts*
the absence of a ceremony and pins that assertion next to the hashes. The
project's standing rule that production proving keys must come from a
documented multi-party ceremony is enforced by the data model, not by hope.

## The validator fails closed on any drift

The companion module [`src/prover/preaudit_profile.py`](https://github.com/repfigit/clearproof/blob/main/src/prover/preaudit_profile.py)
implements `validate_preaudit_profile()`, which rebuilds the trust check from
the manifest every time it runs. It validates the manifest against a strict
schema (unknown keys, wrong types and duplicate JSON keys are rejected), then
recomputes the SHA-256 of every pinned file and compares digests with
`hmac.compare_digest`. Symlinks are rejected outright, and pinned paths are
resolved and confined to the repository root so a manifest entry cannot escape
it. Passing an optional `--trusted-digest` additionally binds the check to one
specific manifest revision, and passing `--r1cs-dir` extends the check to the
compiled artifacts on disk.

The command-line entrypoint is honest about the boundary in both directions.
On a clean checkout it prints:

```json
{"status": "ok", "profile_id": "clearproof-preaudit-2026-11",
 "assurance": "preaudit-frozen-no-ceremony",
 "manifest_digest": "539d9b6f3f2c55186e49fd7879354783717914d08c37e24dc8357cbbbba7c825",
 "circuits": ["pilot-transfer-v3-bn254", "wallet-ownership-v1-bn254", "wallet-ownership-v1-bls12381"],
 "production_eligible": false}
```

A complete, tamper-free profile still reports `production_eligible: false` —
because freezing is not an audit, and no ceremony has run. Falsified in the
other direction, [the unit tests](https://github.com/repfigit/clearproof/blob/main/tests/unit/test_preaudit_profile.py)
flip every pin — source files, Poseidon constants, R1CS digests — and assert
the validator rejects each tampering mode with a distinct fail-closed reason.

## Why the BLS12-381 side needed its own Poseidon

BLS12-381 is the pairing curve most production systems are converging on, but
Poseidon parameters are curve-specific: the round constants and MDS matrix are
derived modulo the scalar field, and a BN254 Poseidon does not transfer. The
[constant generator](https://github.com/repfigit/clearproof/blob/main/scripts/generate_poseidon_constants.py)
derives curve-correct parameters clean-room — the standard Grain-LFSR
constant stream plus the sparse-matrix construction from the Poseidon paper's
appendix, computed directly modulo the BLS12-381 scalar field — and emits both
the [Circom constants](https://github.com/repfigit/clearproof/blob/main/circuits/lib/poseidon_bls12381.circom)
and the Python-side digest table from one generator, which the manifest pins.
Known-answer tests, circomlibjs live parity, and a Circom witness-parity run
under `--prime bls12381` verify that the two implementations agree on the
curve where they must.

## The general lesson: pin the linkage, then refuse the extra claim

The failure mode this profile prevents is not an attack on the circuits; it is
*assurance drift* — the slow divergence between the code a reviewer read and
the artifacts a system actually runs. A frozen manifest plus a fail-closed
validator converts that drift from a silent possibility into a loud,
diagnosable rejection, the same structural move as pinning the sanctions-tree
depth at the build call site.

The second half — refusing the extra claim — is what makes the first half
credible. A system that froze a manifest and quietly implied "therefore
audited" would be doing the same work as one that never froze anything. Here
the freeze exists precisely so the pre-audit state is inspectable, reproducible
and bounded: every artifact a future audit will freeze is already hashed, every
drift since is detected, and the manifest itself declares that no ceremony
approved production keys. Evaluating the system later reduces to checking
which of the pinned statuses have changed — a question with a definite answer.
