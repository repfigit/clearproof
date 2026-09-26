---
id: UP-EX-001
title: What Clearproof does — and what a valid proof does not establish
date: 2026-09-13
publishAfter: 2026-09-13T20:30:00Z
sourceCommit: 4ed9a6ac19bbb9b479dc271b148731d1ecb04cb0
claimRefs:
  - README.md
  - docs/ADOPTION_ROADMAP.md
  - packages/content/content/topics/security.md
  - packages/content/content/topics/quickstart.md
status: approved
summary: Clearproof combines scoped zero-knowledge statements, encrypted transfer information, policy decisions and retained evidence for controlled evaluation. This explainer walks through what that means in the current source, and where the proof's guarantee stops.
canonical: /explainers/what-clearproof-does
templateVersion: explainer-v1
---

Clearproof is an open-source project for privacy-preserving crypto transfer
evidence. Its [README](https://github.com/repfigit/clearproof/blob/main/README.md)
states the scope plainly: scoped zero-knowledge statements, encrypted transfer
information, policy decisions and retained evidence for controlled evaluation by
stablecoin processors and custodians. In the FATF Travel Rule context, the
recurring problem is sending required transfer information to a counterparty
without exposing more than required — and retaining evidence you can review
later. Clearproof's answer is a Groth16 proof plus the required personal
information encrypted to the receiving institution's key (HPKE), bound to the
same transfer.

## What the source checkout implements today

The public source on `main` implements a local adoption pilot:

- Authenticated credential enrollment with holder-bound issuance membership and
  a canonical transfer/context projection using exact asset and valuation
  arithmetic.
- Encrypted tenant-scoped storage with retained policy, root and revocation
  history, actor-bound retries and atomic authorization consumption.
- Explained policy evaluation, comparison, review and activation history.
- Signed synthetic custody-event ingestion, simulated bilateral outcomes and
  read-only transfer investigations with independent lifecycle states.
- Non-authorizing observation reports with scoped coverage, disagreement and
  timing.
- Recipient-encrypted historical exports and offline review under independently
  configured proof, policy, source, decision, status and timing authorities.

The npm packages at 0.6.0 include the TypeScript SDK, CLI, content, contract
sources and circuit sources. The Python API and acceptance tooling are in the
same checkout and are not published to PyPI.

The current pilot proof profile, `pilot-transfer-v3`, has eight public signals
with no public amount tier or SAR advisory flag. The older 16-signal
`compliance.circom` profile remains a separate legacy demo path — the README
warns never to select artifacts by signal count alone.

## What a valid proof establishes — and what it does not

This is the boundary worth internalizing before any evaluation: a valid proof
establishes its encoded statement. It does not establish legal compliance,
source truth, counterparty acceptance or settlement by itself. Concretely, from
the [security boundaries](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/security.md)
documentation:

- Credential authenticity, holder authority, jurisdiction and actual transfer
  binding require coordinated improvements across the proof statement and the
  application.
- Replay, expiry and root checks depend on the verifier and its configuration.
- A cryptographically valid proof is not an accepted transfer.

## What is available to install

Public npm packages are at **0.6.0** and include the local pilot and
`pilot-transfer-v3`. `@clearproof/circuits` publishes circuit sources only, so
proof generation still requires compatible WASM and proving-key files compiled
locally. Those development keys are unapproved. The full evaluation path is a
[source checkout](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/quickstart.md):
clone, build from the committed lockfiles, and run the documented local pilot,
which owns a disposable PostgreSQL cluster and loopback EVM and exercises real
proofs. A documented clean-checkout checkpoint (September 7, 2026) reproduced
this workflow end to end, including an offline historical review with network
connections disabled.

## Assurance status, stated once

Current circuits and contracts have not completed an independent audit, and
generated proving keys are explicitly unapproved development artifacts. Use
synthetic data and testnet funds. Development proofs and passing local tests do
not establish production readiness — see the
[adoption roadmap](https://github.com/repfigit/clearproof/blob/main/docs/ADOPTION_ROADMAP.md)
for what the project treats as its public priorities and follow-on gates.

If that scoped problem — verifiable transfer statements with minimized data
exposure and independently reviewable retained evidence — matches a workflow you
own, the fastest next step is the [full walkthrough](https://github.com/repfigit/clearproof/blob/main/packages/content/content/recipes/full-walkthrough.md):
build the sanctions tree, issue a credential, generate a proof, verify it, and
record the verified result on a testnet registry.
