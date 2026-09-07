# clearproof Specifications

This directory holds the **protocol-facing specifications** — documents that
define interoperability between independent implementations, not just this
repository's internals.

## Lifecycle

Documents declare their status in their heading, front matter or inventory entry.
The intended publication lifecycle is:

| Status | Meaning |
|--------|---------|
| `draft` | Under active change; no compatibility promises |
| `candidate` | Feature-frozen; seeking implementation experience and review |
| `stable` | Versioned; changes only via a new minor/major spec version |
| `deprecated` | Superseded; retained for historical reference |

Versioning follows SemVer semantics for the **document**, independent of the
clearproof software version:

- **MAJOR**: wire-incompatible change (existing conforming implementations break)
- **MINOR**: backward-compatible addition (new optional fields, new capabilities)
- **PATCH**: clarifications, editorial fixes, no behavior change

Any change to a `candidate` or `stable` spec requires:

1. A version bump and dated entry in the spec's own changelog section
2. A note in the repo `CHANGELOG.md` under `[Unreleased]`
3. Review sign-off from a maintainer other than the author (spec changes are
   consensus changes, not code changes)

## Inventory

| Spec | Version | Status | Purpose |
|------|---------|--------|---------|
| [`well-known-clearproof.md`](well-known-clearproof.md) | 0.4.0 profile | development | Exact-identity discovery, HPKE keys and connection/egress policy |
| [`transfer-evidence-v1.md`](transfer-evidence-v1.md) | v1 | development | Canonical transfer, verification context, projection and separated evidence results |
| [`pilot-transfer-v2.md`](pilot-transfer-v2.md) | v2 profile | development | Eight-signal credential-bound current proof statement and v1 separation |
| [`pilot-policy-v1.schema.json`](pilot-policy-v1.schema.json) | v1 schema | development | Bounded policy document structure, not legal approval |
| [`history-reviewer-v1.schema.json`](history-reviewer-v1.schema.json) | v1 schema | development | Independently configured offline historical reviewer inputs |
| [`specs.md`](specs.md) | — | internal | Agentic implementation specification (design doc, not an interop spec) |

Development entries describe locally implemented profiles and do not imply
candidate/stable status or third-party conformance. See the
[pilot compatibility matrix](../docs/operations/pilot-compatibility.md) for
software, discovery, proof, envelope, observation and storage boundaries.

## Hybrid Payload Format

The hybrid payload (ZK proof + AES-256-GCM encrypted PII envelope) is
currently specified by the reference implementation
(`src/protocol/hybrid_payload.py`) and the data models in
`src/protocol/`. Promoting it to a versioned spec document in this directory
is a tracked roadmap item — it is the artifact other implementations need to
interoperate, and the precursor to contributing the format into a Travel Rule
standards body (TRP/TRISA extension or TAIP).

## Long-Term Home

These specs are intended to graduate to a standalone, implementation-neutral
specification repository once they reach `candidate` status, so that
counterparty implementations do not need to reference this codebase. Until
then, this directory is the single source of truth.
