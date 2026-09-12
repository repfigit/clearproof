---
id: UP-2026-004
title: What the compliance proof actually verifies
date: 2026-09-12
publishAfter: 2026-09-12T14:30:00Z
sourceCommit: 57222b0bcad7e8dc06796fb870105a41ac87b844
claimRefs:
  - packages/content/content/topics/circuits.md
  - packages/content/content/recipes/verify-proof.md
  - packages/content/content/topics/security.md
status: approved
summary: The Groth16 circuit checks sanctions non-membership, credential validity and the amount tier — and it is worth being precise about what stays outside that boundary.
---

[The circuit documentation](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/circuits.md)
describes the three checks the current Groth16 circuit enforces:

1. **Sanctions non-membership** — a sorted-tree gap construction shows the queried value lies between neighboring leaves. This establishes a fact about the supplied tree; authenticity, completeness and freshness of the screening source are separate requirements.
2. **Credential validity** — checks performed against the credential commitment and issuer tree supplied to the circuit.
3. **Amount tier** — the amount is compared against three ordered public thresholds and the claimed tier is checked.

The public-signal array exposes all sixteen signals, including an advisory
`sar_review_flag` that is tier-derived — it is not a suspicious-activity
determination or filing instruction.

What the proof does not do: a cryptographically valid proof is not an accepted
transfer. Registry acceptance checks, credential authenticity, holder authority,
actual transfer binding and replay/expiry handling depend on the verifier and
its configuration — see the
[security boundaries](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/security.md)
page. These components are unaudited development work, and the
[off-chain verification recipe](https://github.com/repfigit/clearproof/blob/main/packages/content/content/recipes/verify-proof.md)
shows exactly which four checks a verify call performs so you can compare them
against what your own acceptance policy needs.
