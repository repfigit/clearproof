---
id: UP-EX-008
title: Month one in the open — what changed, and what is still open
date: 2026-10-02
publishAfter: 2026-10-02T00:00:00Z
sourceCommit: 9c5f8c2368336851fda7a04c10e27b8769d5e5a8
claimRefs:
  - docs/ADOPTION_ROADMAP.md
  - docs/PUBLISHING.md
  - packages/cli/src/commands/report.ts
  - packages/proof/src/prover.ts
  - README.md
  - packages/contracts/contracts/
status: approved
summary: One month of building in the open, in facts: a working source pilot, two npm releases, a reproducible issue path, and an honest list of what is still missing — audits, production keys, automated deploys and external feedback.
canonical: /explainers/month-one-retrospective
templateVersion: explainer-v1
---

Clearproof started publishing one month ago with an unusual promise: every
substantial claim would point at the source it came from. That constraint makes
a month-one retrospective easy to write and hard to fake — the changes are in
the history, and so are the gaps. Here is both.

## What actually changed

The commit history between the first of September and today shows 211 commits
and 30 merged pull requests, ending at revision `9c5f8c2`. The arc, in order:

**A working pilot, described honestly.** The month opened by moving internal
planning out of the public tree ([PR #30](https://github.com/repfigit/clearproof/pull/30))
and replacing it with [docs/ADOPTION_ROADMAP.md](https://github.com/repfigit/clearproof/blob/main/docs/ADOPTION_ROADMAP.md) — a
statement of what the project is, what a careful evaluation record looks like,
and what it does not claim. That framing held all month: no audit, customer or
compliance language was added to the public surface.

**Circuit depth became a production decision.** The pilot's production circuit
profile moved from pilot-transfer-v2 to pilot-transfer-v3, with tree depths
raised to 32/20/20 (see [docs/operations/pilot-compatibility.md](https://github.com/repfigit/clearproof/blob/main/docs/operations/pilot-compatibility.md)
and [PR #49](https://github.com/repfigit/clearproof/pull/49)) — larger sanctions
and credential trees behind the same Groth16 proof shape, plus registrar
tree-depth validation tests.

**The project became installable.** After a month where the CLI depended on an
unpublished content package, the owner shipped two releases via npm trusted
publishing: [0.5.0](https://github.com/repfigit/clearproof/releases) (token →
OIDC switch) and [0.6.0](https://github.com/repfigit/clearproof/releases)
(04:05Z on 2026-09-26), publishing all four `@clearproof` packages —
cli, proof, content and a new source-only circuits package
([PR #56](https://github.com/repfigit/clearproof/pull/56)). The circuits
package deliberately ships source, not artifacts; 0.6.0 is a breaking change
from 0.3.0.

**Feedback got a designed path.** [PR #54](https://github.com/repfigit/clearproof/pull/54)
added `clearproof report` — a CLI command that builds a pre-filled GitHub issue
link locally (versions, platform, an optional privacy-filtered doctor summary)
and sends nothing until you open it, plus structured issue templates that treat
agent-reported issues as a first-class case. We wrote a full explainer on that
path: [Contributing useful feedback](/explainers/contributing-useful-feedback).

**Documentation was corrected, not just added.** Two passes
([#51](https://github.com/repfigit/clearproof/pull/51), [#59](https://github.com/repfigit/clearproof/pull/59))
repaired stale and inaccurate claims across the docs site, and a
[docs status page](https://docs.clearproof.world/docs/status) now states which
packages are actually published at which versions.

## What is still open

The same history shows what did not happen, and pretending otherwise would
defeat the point of publishing source-backed:

- **No independent audit.** The circuits and contracts remain unaudited, and
  all published proving artifacts still come from a development-only trusted
  setup. Production keys require a documented multi-party ceremony that has not
  happened.
- **No production deployment.** The supported path is a bounded development
  pilot with synthetic data and testnet funds. Nothing here authorizes a real
  transfer.
- **Deployment is manual.** Production docs updates go out through a
  prebuilt-deploy procedure, not an automated one; it works, but it depends on
  the person running it.
- **Almost no external feedback yet.** The reproducible issue path exists;
  nobody has used it in anger. The issue templates were merged days ago. If
  you have tried the pilot and hit friction, that path is the fastest way to
  make the next month's retrospective about your problem instead of ours.

## What month two is for

The plan for the next month is the same discipline with better raw material:
turn the pilot into something an evaluator can reproduce faster, keep the
what-it-does/what-it-trusts documentation current with each circuit or registry
change, and see whether the feedback path produces its first real reports. The
[adoption roadmap](https://github.com/repfigit/clearproof/blob/main/docs/ADOPTION_ROADMAP.md)
stays the honest list; the [project feed](/feed.xml) carries the
change-by-change record as it happens.

Clearproof remains pilot-stage software for privacy-preserving crypto transfer
evidence. Use synthetic data and testnet funds.
