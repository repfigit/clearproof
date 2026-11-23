---
id: UP-EX-015
title: Why a sanctions Merkle tree's depth must match the circuit's tree-height parameter
date: 2026-11-23
publishAfter: 2026-11-23T00:00:00Z
sourceCommit: 85f87dd04c3872ae40dd4697491736686c59ca5d
claimRefs:
  - circuits/compliance.circom
  - scripts/build_sanctions_tree.py
  - src/registry/merkle_depth.py
  - Makefile
  - .github/workflows/sanctions-update.yml
status: approved
summary: A sanctions root published from a tree built at the wrong depth is still a valid-looking root, and the on-chain registry will happily accept it — but no proof can use it, because the circuit's witness paths are a fixed length. This explainer walks the depth-8-versus-depth-20 mismatch caught in Clearproof's legacy sanctions pipeline in November 2026, what makes the failure silent, and how the fix pins the depth at both build call sites.
canonical: /explainers/sanctions-tree-depth-must-match-circuit
templateVersion: explainer-v1
---

A Merkle root is a digest of a specific tree shape. Strip the shape away and
the root is just a hash — a valid 32-byte value that the on-chain registry will
accept without question. If a zero-knowledge system builds its sanctions tree
at one depth and its circuit expects another, nothing rejects the root. It
publishes, relays, and sits on-chain, looking authoritative. The failure only
appears when a real prover tries to construct a witness against it and cannot.

Clearproof's legacy pipeline had exactly this mismatch in November 2026. This
explainer walks what went wrong, why it was silent, and how the fix pins the
depth so the pipeline cannot drift again.

## The circuit fixes the path length at compile time

The legacy 16-signal circuit is
[`circuits/compliance.circom`](https://github.com/repfigit/clearproof/blob/main/circuits/compliance.circom),
whose main declaration instantiates `ComplianceProof(20, 10)` — a 20-level
sanctions tree and a 10-level issuer tree. Those depths are Circom template
parameters: they are baked into the compiled circuit, the proving key, and the
verifier contract before anything is deployed. The witness builder supplies a
fixed-length 20-element sibling path for the sanctions non-membership gap
proof. There is no runtime input that says "this tree is 8 levels deep." A
proof generated against a depth-20 circuit can only consume a depth-20
path — full stop.

This is why changing a tree depth is a breaking change in a Groth16 system
rather than a config tweak: the compiled verifier and its keys are bound to
one height. Clearproof documents that constraint in its engineering guide,
and it is the reason the depth lives in the circuit declaration instead of a
runtime setting.

## Where the mismatch came from

The sanctions tree builder,
[`scripts/build_sanctions_tree.py`](https://github.com/repfigit/clearproof/blob/main/scripts/build_sanctions_tree.py),
accepts a `--depth` flag whose help text says the quiet part out loud:
"Explicit circuit depth (legacy compliance: 20); changes the root." Without
the flag, the script picks the natural depth — the smallest power of two tall
enough to hold the address list. During 2026 the lists were small enough that
the natural depth was 8: a tree of 256 padded leaves.

The daily sanctions-update workflow and the `build-sanctions-tree` make target
both ran the script without `--depth`, so both rebuilt the legacy tree at
depth 8. The roots they produced were correct for a depth-8 tree, and the
committed artifact recorded `"depth": 8, "padded_size": 256`. But the legacy
circuit pins `ComplianceProof(20, 10)`, so a 20-element witness path can never
match a depth-8 root and sibling set. Real proof generation on the legacy
profile could not use the artifact the pipeline produced at all.

An automated code-review bot flagged exactly this on the standing
[sanctions-update PR #142](https://github.com/repfigit/clearproof/pull/142) as
a high-severity finding: the published legacy tree records depth 8 while the
circuit instantiates `ComplianceProof(20, 10)`, and merging would relay a root
that 20-level gap proofs cannot match.

## The fix: pin the depth at every call site

Pull request
[#147](https://github.com/repfigit/clearproof/pull/147) ("fix(sanctions): build
legacy tree at circuit depth 20", merged as commit `46ebfe3`) passed `--depth
20` at both call sites:

- the `build-sanctions-tree` target in
  [`Makefile`](https://github.com/repfigit/clearproof/blob/main/Makefile), and
- the daily
  [`sanctions-update` workflow](https://github.com/repfigit/clearproof/blob/main/.github/workflows/sanctions-update.yml),
  whose run step now carries a comment explaining that the legacy 16-signal
  circuit pins `sanctions_tree_depth=20` and that auto depth drifts as the
  list grows.

The script's companion module
[`src/registry/merkle_depth.py`](https://github.com/repfigit/clearproof/blob/main/src/registry/merkle_depth.py)
does the actual work: `extend_depth()` re-extends a naturally sized tree to the
target depth by appending zero leaves and hashing them up through the missing
levels (exactly how a padded tree is built), and a natural depth that already
exceeds the configured target raises
`"Merkle tree exceeds configured depth"` — a tree taller than the circuit
expects is just as unusable as one that is shorter.

The pilot profile was unaffected. `pilot-transfer-v3` derives its own
raw-address sanctions tree with `build_pilot_sanctions_tree.py` at a fixed
depth-20, key-sorted derivation that never relied on the auto-depth path.

## The general lesson: a published root is not self-describing

The interesting property of this failure is that every individual component
worked as written. The script built a correct tree. The registry relayed the
root it was told to relay. The circuit did what its parameters said. Nothing
validated the one cross-component invariant — that the tree the pipeline
builds and the tree-height parameter the circuit compiles are the same number
— because that invariant lives between them, in the build invocation.

That is a real evaluation consideration for any zero-knowledge compliance
system, including Clearproof: ask where the binding between the published
root and the proving machinery is enforced, and whether it can drift. In
Clearproof's legacy path it now is enforced — as a hardcoded `--depth 20` at
both rebuild call sites, with the rationale committed alongside the flag
rather than left in tribal knowledge. In the pilot path it is enforced
structurally, by a derivation whose depth is fixed by construction. The
version of the system that makes the question moot — one where the depth is a
public input the prover declares — does not exist in this design, and treating
the root as self-describing would be the mistake.
