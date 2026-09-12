---
id: UP-2026-003
title: What npm can install today, and what it cannot
date: 2026-09-12
publishAfter: 2026-09-12T14:30:00Z
sourceCommit: 57222b0bcad7e8dc06796fb870105a41ac87b844
claimRefs:
  - packages/content/content/topics/quickstart.md
  - README.md
status: approved
summary: Public @clearproof packages exist at 0.3.0, but the CLI cannot install from the registry and the development checkout is already 0.4.0. Here is what each path supports.
---

Clearproof's public npm packages are at **0.3.0** while the development checkout
is **0.4.0** — they are not the same thing. Verified against the npm registry on
September 12, 2026:

- [`@clearproof/proof`](https://www.npmjs.com/package/@clearproof/proof) 0.3.0 — SDK install verified, but proof generation still requires matching circuit WASM and proving-key files supplied by the caller.
- [`@clearproof/circuits`](https://www.npmjs.com/package/@clearproof/circuits) 0.3.0 — inspect package contents; installation alone is not a proving setup.
- [`@clearproof/cli`](https://www.npmjs.com/package/@clearproof/cli) 0.3.0 — public install is currently blocked because its `@clearproof/content` dependency is unavailable on the registry (confirmed returning "Not found").
- `@clearproof/content` — not published at all.

The practical path for evaluating current capabilities is a
[source checkout](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/quickstart.md):
clone, build, and run the documented checks. The README's installation table is
kept current with what each package actually supports; nothing there claims a
one-command production install, because that does not exist yet.
