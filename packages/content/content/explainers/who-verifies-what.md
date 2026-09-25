---
id: UP-EX-003
title: Who verifies what — circuit, registry and application responsibilities in Clearproof
date: 2026-09-17
publishAfter: 2026-09-17T00:00:00Z
sourceCommit: eaab3d020c6d3f2943cb20d56633e919d6c1579e
claimRefs:
  - packages/content/content/topics/architecture.md
  - specs/pilot-transfer-v3.md
  - packages/content/content/topics/security.md
  - README.md
status: approved
summary: A zero-knowledge proof is one verifier among several. Reading where Clearproof's circuit stops and the registry and application take over is the difference between evaluating the system and over-crediting the math.
canonical: /explainers/who-verifies-what
templateVersion: explainer-v1
---

A recurring evaluation mistake with zero-knowledge compliance systems is
treating the proof as the security model. In Clearproof's source, the proof is
one verifier among at least three, and the [architecture
documentation](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/architecture.md)
draws the line explicitly: "The circuit constrains particular mathematical
relationships. The application establishes trusted input sources and the policy
context. The registry additionally checks on-chain state, domain, expiry,
revocation and replay. Do not collapse these into a single claim that every
security property is proved by the circuit."

## What the circuit constrains

The pilot profile `pilot-transfer-v3` (Circom `pilot_compliance.circom`) proves
statements over the 48-field canonical transfer projection. Its public signals
include the projection commitment, issuer and sanctions tree roots, an
authorization nullifier, and domain binding (`domain_chain_id`,
`domain_registry`) that stops a proof built for one deployment being replayed
against another. The commitment binds the exact credential and issuance root
used by the credential subcircuit — the spec is explicit that it "is not a
caller-selected opaque assertion."

But the [public
statement](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md)
also states the boundary plainly: "Proof verification alone neither
authenticates those records nor establishes current roots, revocation, policy
compliance or legal compliance. The profile cannot authorize replay through
historical inspection."

## What the registry checks that the circuit does not

The registry is a second verifier. Per the architecture documentation, it
checks on-chain state, domain, expiry, revocation and replay. The development
registry includes a versioned verifier router, so a deployed registry and its
selector/artifacts must be checked against the intended proof version — v1 and
v2 profiles have the same signal count but different first-signal meanings and
different keys, and current artifact-context and root checks reject v1. That
router is what stops a proof built against one proving-key generation from
being verified against the wrong artifacts.

## What the application owns outright

The application layer establishes trusted input sources and the policy context.
The circuit never sees raw sanctions data or credential fields — it sees
commitments built from them. So the integrity of those commitments inherits
every assumption of the enrollment and projection pipeline: canonical
projection arithmetic, credential issuance membership, and the sanctions tree
build (script `scripts/build_sanctions_tree.py`, root relayed via the
SanctionsOracle). If an input source is untrusted, the proof is faithfully
proving a statement about untrusted data.

## Practical reading for evaluators

Three checks that don't require running anything:

1. **Match the profile to the artifacts.** Check the registry's versioned
   router against the manifest's named profile (v2 manifests name it
   explicitly; legacy manifests retain v1 meaning). Never select artifacts by
   signal count alone — v1 and v2 both have eight.
2. **Ask who maintains the roots.** The sanctions root is relayed to the
   oracle across all deployed chains; a stale root is a live question for any
   deployment you evaluate, and proof verification alone does not establish
   current roots or revocation.
3. **Trace trusted-input provenance.** The proof binds commitments; the
   application binds the data behind them. Evaluating only the circuit
   under-credits the registry checks and over-credits the math.

The opening line is the architecture documentation's own summary, and it is the
right one: the circuit, the registry and the application each verify a
different layer, and a complete evaluation reads all three.
