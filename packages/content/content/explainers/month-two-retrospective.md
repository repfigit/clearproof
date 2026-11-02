---
id: UP-EX-012
title: Month two in the open — three releases, hardened rails, and the same honest gaps
date: 2026-11-02
publishAfter: 2026-11-02T00:00:00Z
sourceCommit: 6fc171e8f4a488f7c37705cb79cf13d5bbfdba9b
claimRefs:
  - CHANGELOG.md
  - docs/ADOPTION_ROADMAP.md
  - docs/adr/0002-bls12381-migration.md
  - docs/adr/0004-fflonk-universal-setup.md
  - docs/operations/pilot-proving-jobs.md
  - docs/operations/legacy-encryption-migration.md
  - packages/contracts/scripts/ops/measure-l2-verify-cost.ts
status: approved
summary: Month two of building in the open delivered the largest release since the pilot went public — verified-proof semantics, durable proving jobs, an explicit HKDF salt requirement — plus two patch releases that fixed our own broken version reporting on the record, a BLS12-381 decision point, and an unchanged honest list: no audit, no production deployment, no external feedback yet.
canonical: /explainers/month-two-retrospective
templateVersion: explainer-v1
---

Last month's [month-one retrospective](/explainers/month-one-retrospective) ended
with a promise: turn the pilot into something an evaluator can reproduce faster,
keep the documentation current with every circuit or registry change, and see
whether the feedback path produces its first real reports. This is the record of
what actually happened in the window 2026-10-01 through 2026-10-31, written
against revision `6fc171e` — and, as before, everything below points at the
source it came from, including the part where we shipped a defect and had to fix
our own release process in public.

The raw shape of the month: 41 pull requests were merged into `main`, 10 of
them Dependabot dependency updates, alongside the owner's own automation
bookkeeping commits that touch only their notes directory. Three releases
went out, a cluster of pull requests hardened pilot operations, and two were
documentation explainers you can read on this site.

## 0.7.0 — the biggest release since the pilot went public

[0.7.0](https://github.com/repfigit/clearproof/releases) shipped on
2026-10-06, and its [CHANGELOG entry](https://github.com/repfigit/clearproof/blob/main/CHANGELOG.md)
is the single best summary of the month's engineering. The parts that matter
most for an evaluator:

**Verified-proof semantics.** In `@clearproof/proof`, `isCompliant` and
`sarReviewFlag` are now only meaningful when a proof is valid — a wrong-length
or malformed public-signal input returns `valid: false` instead of throwing.
That closes a real evaluation trap: a caller that glanced at a compliance
field without checking validity could previously read garbage as a verdict.

**The key-derivation salt is no longer implied.** API startup now requires an
explicit `HKDF_SALT`; the historical default only exists behind
`ALLOW_INSECURE_HKDF_SALT=1` for disposable tests and demos. The
[migration note](https://github.com/repfigit/clearproof/blob/main/docs/operations/legacy-encryption-migration.md)
is explicit about the part that matters: changing the salt does not migrate
ciphertext — retained legacy envelopes stay readable only under the salt they
were written with, and compatibility tests confirm that.

**Legacy verifier governance became deliberate.** Verifier swaps and
retirement on the legacy `VerifierRouter` / `ComplianceRegistry` path are
timelocked and two-step: `setVerifierSelector` schedules, `activateVerifierSelector`
applies, retired defaults stay usable for a 24-hour grace window, and runtime
code is pinned. A compromised or hurried admin can no longer silently rebind a
verifier or cut off older proofs in one call.

**Proving became an asynchronous, durable job.** `POST /pilot/proof/jobs`
admits the request into PostgreSQL encrypted and returns `202`; a separately
supervised worker does the proving, with global and per-tenant admission
limits, fenced leases, bounded attempts, and re-checks of enrollment, policy
and approved roots both before and after proving. Generating a proof never
consumes an authorization. The design note is
[docs/operations/pilot-proving-jobs.md](https://github.com/repfigit/clearproof/blob/main/docs/operations/pilot-proving-jobs.md),
and an optional pinned native prover (`CLEARPROOF_RAPIDSNARK_BIN`) exists for
Linux operators who want one.

Node versions were also part of the breaking set — Node ≥ 20 for
`@clearproof/proof`, Node ≥ 22.12 for the CLI — and `exports` maps ended
deep imports of `dist/*`.

## 0.7.1 and 0.7.2 — fixing our own release process on the record

This is the part we could have hidden, and won't. The published `0.7.0`
tarball of `@clearproof/content` packed from the wrong tag and still reported
`npmVersion 0.6.0`. npm does not allow a tarball to be replaced once published,
so the fix had to go forward as releases: [0.7.1](https://github.com/repfigit/clearproof/releases)
packed the verified npm release, and [0.7.2](https://github.com/repfigit/clearproof/releases)
aligned the package's version reporting with what is actually published. The
durable fix is a test: `tests/unit/test_release_versions.py` now rejects a
checkout where workspace packages, the Python project, lockfiles, direct
`@clearproof/*` ranges and the project's recorded npm/source versions
disagree. Until the tarball is immutable on npm, the recorded version must be
correct when it ships — so the repository enforces it, rather than trusting
whoever runs the next release to remember.

## A full-codebase review pass, resolved

Pull request
[#63](https://github.com/repfigit/clearproof/pull/63) (merged 2026-10-05)
resolved a full-codebase review's findings across API hardening, bridges,
pilot contracts and CI. In the same week the pilot gained the operational
discipline the retrospective promised: bounded operations and pagination
([PR #103](https://github.com/repfigit/clearproof/pull/103)), scoped pilot
configuration readiness ([PR #99](https://github.com/repfigit/clearproof/pull/99)),
real-proof onboarding and a local pilot preflight
([PR #98](https://github.com/repfigit/clearproof/pull/98)), and pilot
constants generated from the canonical profile schema
([PR #93](https://github.com/repfigit/clearproof/pull/93)) instead of hand-maintained.

## BLS12-381: decided as a benchmark, hardened in public

October confirmed the BLS12-381 direction in two steps. First, PR
[#112](https://github.com/repfigit/clearproof/pull/112) recorded the Sepolia
confirmation of `Groth16VerifierBLS`, making ADR 0002 DECIDED for BLS12-381 —
with the CHANGELOG stating plainly that this verifier is a development
benchmark, not a production deployment. Second, PR
[#113](https://github.com/repfigit/clearproof/pull/113) closed three edge cases
in that verifier: it rejected public signals at or above the scalar field
order (the G1 multi-scalar-multiplication precompile previously reduced
`s + r` back to `s`), proof points at infinity, and a non-canonical `y` on
`A`. We wrote a full explainer of those three cases and their scope:
[Rejecting more than bad proofs](/explainers/bls-verifier-edge-cases). The
Sepolia benchmark deployment predates the fix.

## A decision framework, not just a decision

[ADR 0004](https://github.com/repfigit/clearproof/blob/main/docs/adr/0004-fflonk-universal-setup.md)
carries a panel-path note (2026-10-08): no production ceremony yet, no GPL
fflonk ship — freeze circuits, gather fflonk evidence, then choose once.
Supporting that choice, L2 verify-cost receipts are now measured in-source by
[`measure-l2-verify-cost.ts`](https://github.com/repfigit/clearproof/blob/main/packages/contracts/scripts/ops/measure-l2-verify-cost.ts)
on Base, Arbitrum and Optimism Sepolia. Per the CHANGELOG at current testnet
fee floors, fflonk is about 0.69× the total Groth16 cost on an L2, while the
L1/data-availability fee is roughly 2× but a negligible share of the total.
Those are benchmark numbers on testnets, not cost claims about production.

## Documentation kept current with the source

Two canonical explainers were added this month:
[What the proof does not check](/explainers/what-the-proof-does-not-check)
(UP-EX-010), walking the trusted issuers, published roots and configuration
that no circuit can check, and the BLS verifier explainer above (UP-EX-011).
The [Developer Certificate of Origin is now enforced in CI](https://github.com/repfigit/clearproof/pull/77)
— every commit must carry a `Signed-off-by` trailer — which is a small thing
that makes the contribution history auditable.

## What is still open

The same revision shows what did not happen, and saying it plainly is the
point of this series:

- **No independent audit.** Circuits and contracts remain unaudited; published
  proving artifacts still come from a development-only trusted setup.
- **No production deployment.** The only committed deployment record is the
  July 20, 2026 legacy Sepolia manifest, which the CHANGELOG now labels
  historical — it is not a deployment of the 0.7.2 contracts. A later pilot
  deployment needs an authorized funded signer, which this project does not
  have in CI or source.
- **No production ceremony.** `CEREMONY_RUNBOOK.md` targets BLS12-381, with a
  pinned multi-party phase-1 file and the Poseidon re-parameterization as
  pre-ceremony gates. None of that has run.
- **No external feedback yet.** The reproducible issue path
  ([Contributing useful feedback](/explainers/contributing-useful-feedback))
  still has not produced its first real report. Month two produced releases,
  hardening and documentation — but no evidence yet that an outside evaluator
  has run the pilot.

## Month three

The discipline does not change: reproduce faster, document honestly, and
publish the record — releases, fixes and gaps — in the same place as the code
that backs it. The [adoption roadmap](https://github.com/repfigit/clearproof/blob/main/docs/ADOPTION_ROADMAP.md)
stays the honest list, and the [project feed](/feed.xml) carries the
change-by-change record as it happens.

Clearproof remains pilot-stage software for privacy-preserving crypto transfer
evidence. Use synthetic data and testnet funds.
