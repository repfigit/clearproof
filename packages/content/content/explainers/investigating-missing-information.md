---
id: UP-EX-009
title: Investigating missing information — the pilot observability and investigation workflow
date: 2026-10-05
publishAfter: 2026-10-07T00:00:00Z
sourceCommit: 33756f21fc4b7c4495f64e6ab259373a7515ad20
claimRefs:
  - docs/operations/pilot-observability.md
  - docs/internal/PILOT_OBSERVATION_MODE.md
  - docs/operations/local-pilot-acceptance.md
  - docs/operations/evaluating-clearproof.md
status: approved
summary: Clearproof has no single readiness endpoint, and a missing result is a finding, not a gap to fill. This explainer walks the documented pilot observability surfaces — what each can tell you, what it cannot, and the investigation workflow that keeps absence of evidence distinct from authorization.
canonical: /explainers/investigating-missing-information
templateVersion: explainer-v1
---

Two design decisions in Clearproof's pilot observability surface go against the
usual dashboard instinct. There is no aggregate readiness endpoint, and a missing
result is a finding — recorded as such — rather than a gap to fill with an
assumption. Both are deliberate, and both are documented in
[docs/operations/pilot-observability.md](https://github.com/repfigit/clearproof/blob/main/docs/operations/pilot-observability.md).

## No single readiness endpoint

`GET /health` tells you the process is alive, reports the software version and
the server clock. The observability guide is explicit about what a 200 does not
mean: no database, key, artifact, trust, chain or provider readiness is checked,
and "HTTP 200 alone is not readiness."

The other surfaces are equally scoped. `/metrics` is a process-local debug
counter set behind authentication; counters reset on restart and are not wired
to the pilot services, so "zero is not evidence that no pilot operations
occurred." `/pilot/usage` is a one tenant-scoped database snapshot — encrypted
records, bytes, observations, events, proofs, receipts, policy versions,
consumed nullifiers — that checks one database path, excludes the publication
journal, and "is not a billing ledger, HTTP request count or adoption metric."

Even a clean component picture isn't a readiness statement: "There is no single
aggregate readiness endpoint. For an operator's configured pilot, combine process
liveness with authenticated database access, an authorized encrypted-record read,
artifact inspection and the read-only current inspection path. Each must use
independently supplied tenant, deployment and trust inputs." A readiness
judgment has to be assembled, and its inputs named — a design that makes it
harder to mistake a single green light for operational assurance. The guide also
warns against probing with authorization consumption itself: "Do not use
authorization consumption as a health probe."

## Observations: durable, scoped, and bounded in what they claim

The observation service (`docs/internal/PILOT_OBSERVATION_MODE.md`) evaluates a
current pilot-transfer-v3 proof plus retained signed facts and retains an
encrypted observation record. The record design encodes skepticism into the
schema: fixed `mode: observation`, `authorization_consumed: false`,
`execution: not-requested` — and pairing can succeed while the minimized policy
result is still ALLOW, DENY, REVIEW or INDETERMINATE.

Four rules do the heavy lifting:

**A stored ALLOW is not an instruction.** "Observation never creates a retained
authorization proof/receipt or consumes a nullifier. Its storage kind is separate
from `proof`, so the consumption table's proof foreign key cannot reference an
observation, even for a caller with consumption permission. A stored ALLOW is
not an instruction to send a Travel Rule message or execute a transfer."

**An exact retry answers with the past, labeled as such.** "An exact retry after
expiry or trust changes returns the original observation with its original time.
It does not rerun acceptance or imply a current ALLOW." Want a fresh judgment?
New idempotency key, new evaluation, current checks apply.

**Latency is measured, and its scope is stated in the record.** Each v2
observation carries an integer `evaluation_duration_ns` with the explicit scope
`current-evaluation-only` — it includes retained-fact checks, statement/pairing
and policy evaluation, and excludes upload, authentication, lock waits, response
transfer, custody or counterparty latency. The cohort report's `latency` object
carries measured/unmeasured counts and `latency_status` of complete, partial or
not-recorded; empty aggregates are null, never zero. If the sample is partial,
the report says so instead of silently shrinking the denominator.

**Absence is a distinct status, in every report.** The cohort report
(`clearproof-observation-cohort-report-v2`) treats unobserved, missing and
failed-pairing cases as separate statuses. "A missing or failed-pairing result
is not automatically a disagreement, a DENY or an ALLOW." Baseline labels are
marked `caller-supplied-unverified`, and the agreement denominator counts only
labels paired with an actual policy result — a missing case never silently
enters (or silently leaves) a success rate.

## The investigation workflow, step by step

The observability guide's five-step investigation workflow is built around one
principle: independent states stay independent.

1. **Scope first.** Select the tenant and authorized transfer scope; keep bearer
   tokens and private input on the documented private channels. Run
   `investigation timeline` or `investigation queue` with the operator-selected
   API origin.
2. **Record clocks and states without collapsing them.** Record the report's
   clock, source clocks, independent states and evidence references. "Do not
   infer chain finality from custody completion, or execution from an ALLOW
   observation."
3. **Follow owners, not vibes.** Every finding carries owner and next-action
   fields. Queue age thresholds are "operational policy, not an inferred legal
   grace period." Follow all continuation pages and record whether traversal was
   partial.
4. **Provider links are pointers, not proof.** "Use scoped provider links only
   for navigation to independently approved provider sites. The API/CLI do not
   fetch them; their presence does not authenticate remote evidence."
5. **Preserve the earlier observation.** When comparing a later report with
   retained evidence, "preserve earlier observations instead of overwriting
   them." Source ordering, duplicate delivery and canonical-block changes have
   explicit semantics.

## Absence of evidence is not authorization

The failure-handling table makes the epistemics operational, not decorative.
Absence of evidence: "Check the caller's scope and retained reference. Absence
is not permission to accept, reconstruct another tenant's record or invent
source status." A missing counterparty or custody result: "Keep the independent
state unresolved and follow the queue's owner/next action. A timeout or
unsupported version does not permit an information/encryption downgrade."

The consumption-conflict path forbids the workaround too: on 409, "Do not create
new keys merely to bypass a consumed authorization or clear retained
nullifiers." And on trust rejections, "Do not substitute caller-provided
expected values or disable a check to obtain ALLOW."

## What this establishes — and what it does not

What the source shows: an observability surface where every response carries its
own scope, every missing value has a status rather than a default, and the
schema itself refuses to let an observation masquerade as an authorization. What
it does not show: production readiness, external assurance, or that any of this
has been exercised outside the documented development pilot. The
[local acceptance run](https://github.com/repfigit/clearproof/blob/main/docs/operations/local-pilot-acceptance.md)
exercises the complete synthetic path and retains per-surface reports — policy
comparison, observations, cohort coverage/disagreement, counterparty scenarios,
investigation timeline, encrypted history export, reviewer trust and an explicit
history clock — and the [evaluation guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/evaluating-clearproof.md)
treats an independently reviewed record as "not evidence that a transfer
settled." No alert threshold or metric "establishes legal compliance or
production assurance."

Clearproof remains pilot-stage software for privacy-preserving crypto transfer
evidence. Use synthetic data and testnet funds.
