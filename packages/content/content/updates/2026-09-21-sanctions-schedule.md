---
id: UP-2026-005
title: Sanctions-tree refresh now runs on a daily schedule with a change gate
date: 2026-09-21
publishAfter: 2026-09-22T15:30:00Z
sourceCommit: 4a58f129e8640c65ad37074a37dd49114ce9db74
claimRefs:
  - .github/workflows/sanctions-update.yml
  - scripts/build_sanctions_tree.py
  - packages/content/content/recipes/update-sanctions.md
status: approved
summary: The sanctions dataset behind on-chain proof checks is refreshed daily by a scheduled workflow, with a leaf-count sanity gate and a reviewable PR when the tree changes — but the on-chain relay stays a deliberate operator step.
---

Clearproof proofs commit to a Merkle root of a sanctions dataset that the
on-chain `SanctionsOracle` stores. Keeping that root current is an operational
contract of the project — after any root update, all deployed chains must be
re-relayed consistently. The repository now runs the dataset refresh on a
schedule instead of leaving it entirely manual.

What the workflow does:

- `Update Sanctions Tree` runs daily at 06:00 UTC in GitHub Actions (scheduled
  just after the OFAC SDN list typically updates), with a manual
  `workflow_dispatch` trigger kept for operator use.
- Each run fetches the public sanctions sources and rebuilds the deterministic
  Poseidon Merkle tree with `scripts/build_sanctions_tree.py`.
- A change gate compares the built tree against the committed baseline.
- A safety check aborts the run if the leaf count drops by more than 50% — a
  guard against silently building from a broken or partial data source.
- When the tree actually changed, the workflow opens a reviewable branch and
  pull request showing the previous and new leaf counts, rather than pushing
  anything straight to the default branch.

What the workflow deliberately does not do: it does not relay a new root to
deployed chains on its own. The relay job runs on explicit `workflow_dispatch`,
so an operator still drives the on-chain update after reviewing the tree PR —
matching the documented rule that the sanctions relay is never skipped after a
root update. The [sanctions update recipe](https://github.com/repfigit/clearproof/blob/main/packages/content/content/recipes/update-sanctions.md)
walks through that operator flow.

The workflow source is readable in full in the repository at
`.github/workflows/sanctions-update.yml`.
