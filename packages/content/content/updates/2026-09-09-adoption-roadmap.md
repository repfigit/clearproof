---
id: UP-2026-001
title: Adoption roadmap and documentation split published
date: 2026-09-09
publishAfter: 2026-09-09T00:00:00Z
sourceCommit: d57aac12493ea585ad38e85d070385e9fa34d905
claimRefs:
  - docs/ADOPTION_ROADMAP.md
  - docs/PUBLISHING.md
  - README.md
status: approved
summary: The repository now carries a public adoption roadmap and publishing boundaries; internal commercial planning moved out of the public tree.
---

The main repository now includes [docs/ADOPTION_ROADMAP.md](https://github.com/repfigit/clearproof/blob/main/docs/ADOPTION_ROADMAP.md),
which describes how teams can evaluate Clearproof as pilot-stage software: what
the circuits and contracts check today, what stays outside that scope, and what
a careful evaluation record looks like.

A companion [docs/PUBLISHING.md](https://github.com/repfigit/clearproof/blob/main/docs/PUBLISHING.md)
states the project's publication boundaries: source-backed claims, verified
project-owned destinations, and no unsupported audit, customer or compliance
statements.

Clearproof remains pilot-stage software. Circuits and contracts have not
completed an independent audit, and current proving artifacts use a
development-only trusted setup. Use synthetic data and testnet funds.
