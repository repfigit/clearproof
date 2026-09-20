---
id: UP-EX-006
title: Portable evidence review — taking the receipt out of the operator's hands
date: 2026-09-28
publishAfter: 2026-09-28T00:00:00Z
sourceCommit: 61d6b1f2d133ce32796efa015cdac34c06b266b0
claimRefs:
  - README.md
  - docs/operations/local-pilot-acceptance.md
  - src/services/evidence_export.py
  - src/prover/history_cli.py
  - src/prover/history.py
  - src/chain/audit_mirror.py
status: approved
summary: Clearproof's retained evidence is exported as a recipient-encrypted HPKE bundle and reviewed offline by a process that disables its own networking, with every pin supplied by the reviewer rather than the exported bundle. This explainer walks through that path and the three outcomes it can report.
canonical: /explainers/portable-evidence-review
templateVersion: explainer-v1
---

An export feature can be cosmetic: a button that hands you a file the
operator's servers must interpret. The question worth asking of any compliance
system is whether retained evidence can be carried to a reviewer and checked
without the operator in the loop. In Clearproof's current source, that path
exists end to end, and its trust placement is the interesting part: the
reviewer, not the export, decides what counts as evidence.

## The export is encrypted to a recipient, not to the operator

The local pilot's acceptance run retains a `history.encrypted.json` file —
described in [the acceptance guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/local-pilot-acceptance.md)
as the "recipient-encrypted historical evidence export." In source, the export
service (`src/services/evidence_export.py`) builds the bundle only for a
principal holding both `evidence:export` and `evidence:decrypt` roles, only
while the configured recipient's approval window is open, and only against a
pinned authorization receipt whose identity digests, transfer and context
digests must match across the receipt, the proof and the evidence manifest.
Every referenced record is re-read and compared byte-for-byte against its
pinned SHA-256, up to a hard limit of 80 records.

The bundle is then sealed with [HPKE (RFC
9180)](https://github.com/repfigit/clearproof/blob/main/src/sar/hpke_envelope.py)
to the recipient's X25519 public key, with the export binding — tenant,
receipt, reviewer, key id, export time — bound as associated data. The
operator cannot later open this file; only the holder of the reviewer key can.
And the private half of that key is never captured in reports: the acceptance
guide states plainly that it stays in `pilot/private/` and must not be
published.

## The reviewer supplies the pins; the bundle never does

`src/prover/history.py` says it in one line: "Pins and verifier come from the
reviewer, never from the exported bundle." The offline CLI (`src/prover/history_cli.py`)
takes the encrypted bundle, a separately configured reviewer trust file, and an
explicit list of trusted inputs — the artifact directory, the pinned snarkjs
runtime bundle, the Node executable, and the review clock. `open_evidence_bundle`
decrypts with the recipient's private key and immediately qualifies itself: the
docstring notes decryption "does not validate historical compliance or sender
identity." Decryption is a door, not a verdict.

The integrity pass that follows binds everything together: the receipt, proof
and manifest digests must agree, the retained proof must hash to its pinned
digest, the nullifier and expiry signals must match the receipt, and the
captured configuration — artifact manifest, verification key, asset registry,
valuation approval, root pins — must match both its recorded digests and the
artifacts the reviewer chose to trust. If a pinned record is missing entirely,
the result is `indeterminate` with `missing_evidence`, not a best-effort pass.

## What the offline review can conclude

`inspect_history_bundle` reports one of three outcomes, each with named
reasons: `supported`, `indeterminate`, or `contradicted`. Six independent
authorities stand between decryption and a `supported` verdict — statement
reconstruction at the claimed authorization time, policy replay from pinned
fact records, the signed decision attestation, historical non-revocation
status, independent timing evidence, and the information authority's signed
approval. Any authority the reviewer has not configured leaves the outcome
`indeterminate` with the specific gap named (`decision_authority_unverified`,
`historical_revocation_evidence_missing`, and so on). A mismatch — wrong
signals, invalid pairing, bad decision or information signature — is
`contradicted`.

That vocabulary is the design's honesty made mechanical: the reviewer cannot
get a clean bill of health by skipping checks, because each skipped check is
visible in the output as a named gap.

## The mirror, and what none of this establishes

Alongside on-chain events, `src/chain/audit_mirror.py` writes an append-only
JSON Lines audit mirror — for regulatory examination, offline access during
chain downtime, and context not stored on-chain — where every record carries
the SHA-256 of the previous record, forming a tamper-evident hash chain that
`verify_integrity` can re-check. Each writer derives the predecessor from the
file while holding the lock through fsync; no cached tail is trusted.

The boundaries stay explicit. This is a local source-checkout workflow with
synthetic fixtures — the acceptance guide warns that a copied trust file is
not an independently approved production trust configuration, that changing
the review clock "asks a different historical trust question," and that the
M0–M5 acceptance is complete only for the local scope. Live provider access,
customer validation and production assurance remain follow-on gates. What the
source does establish is the shape: evidence that travels encrypted to a named
reviewer, with trust placed in the reviewer's pins rather than the operator's
say-so.
