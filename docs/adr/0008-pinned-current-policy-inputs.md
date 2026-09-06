# ADR 0008: Pinned current policy inputs

Status: threshold/input binding and the bounded M2 business evaluator are implemented.
Counterfactual comparison now has a Python stdin CLI and authenticated API.
Encrypted approval and reviewed-case retention are implemented as a service;
authenticated approval and stored-comparison routes are implemented. Independent
activation remains open.

`PilotPolicy` is an immutable, bounded record containing a policy identity,
revision/predecessor, tenant, EVM deployment, jurisdiction, asset catalog digest,
effective interval, three ordered unsigned 128-bit USD-cent tier boundaries,
and up to sixteen reviewed source references. Its complete canonical record is
hashed under `clearproof/pilot-policy/v1`. Changing thresholds or provenance
changes the digest bound into the transfer/context projection.

`PolicyTrustStore` receives policy records and independently configured current
digests. Records cannot declare themselves approved/current. There is exactly
one current policy per tenant, chain, registry and jurisdiction, including across
catalog changes. A higher revision merely present in the inventory is not current.
A predecessor must be present, have the same policy identity/scope and be exactly
one revision earlier. These links preserve the supplied history; they do not
prove when an operator historically activated a version.

Selection uses the independent caller tenant and the verification context's
expected deployment. Transfer and context must reference the pinned current
policy digest; the catalog must also match. Policy validity covers both the
evaluation time and the caller's current clock. Source review intervals must
cover the complete policy interval. Sources are either explicit synthetic URNs
or credential-free HTTPS references with retained evidence digests. A reference
and hash do not prove that evidence is available or its interpretation correct;
operator review and later durable evidence retention remain required.

The composed witness encoder no longer accepts a free threshold tuple. It
resolves the policy from the configured trust store, then derives the private
amount tier from its exact cent boundaries. The pure projection/arithmetic
helpers remain encoders and make no authority claim. As with quotes, witness
construction uses the claimed evaluation time for historical fixtures; current
verification must independently repeat policy selection with its tenant and
actual clock. A malicious prover can bypass Python, so the final verifier must
recompute the expected projection from approved records or authenticate a
trusted attestation of that binding.

This record only defines the supported private tier predicate. Crossing a tier
boundary is not an ALLOW/REVIEW/DENY decision, and an amount below a threshold
does not remove information-exchange, screening or other obligations. The M2
rule evaluator now provides explicit missing/unsupported-input outcomes; see
`docs/internal/PILOT_POLICY_EVALUATION.md`. Policy-diff reports are implemented for supplied snapshots. The encrypted review
service retains approvals and expected outcomes with authenticated HTTP access;
historical activation evidence remains separate work.
No legal rule or jurisdictional threshold is inferred from synthetic fixtures.

Validation includes exact cent threshold minus/equal/plus boundaries; stale and
draft version rejection; independent tenant/deployment/catalog checks; effective
intervals; source provenance changes; and invalid predecessor chains. A fresh
composed Groth16 proof with the policy digest in the transfer/context projection
also passed the actual pairing integration and tampering checks. The circuit ABI
and constraint layout remain unchanged.

## Artifact policy-schema binding

`specs/pilot-policy-v1.schema.json` publishes the structural JSON schema for
`PilotPolicy`. Its digest uses the existing restricted canonical JSON codec and
`clearproof/policy-schema/v1` domain. A regression check requires the published
schema to match the runtime model. Schema changes therefore require an explicit
review of this file and fresh manifest pins; library-generated schema changes
can also change the digest.

The development circuit builder writes this digest into new artifact manifests
instead of the former zero marker. Artifact context checking rejects manifests
whose policy schema differs from the runtime's supported schema, even when the
manifest itself is operator-pinned. Read-only artifact inspection preserves the
ability to inspect older development files and reports
`policy_schema_supported: false`; that result is not current-context acceptance.
Production still rejects all development manifests.

This digest describes structure, not all Python model validators or evaluator
semantics. It does not approve a particular policy revision, prove source truth,
activate policy, or authorize a transfer. Independent policy selection, the exact
policy revision in the transfer commitment, and current authorization checks
remain necessary. The full current-verifier integration and its context/manifest
binding remain open; this change does not claim to complete those gates.

## Synthetic manifest-bound proof reproduction

The development builder now finalizes the artifact manifest before constructing
its synthetic witness. The synthetic verification context includes that actual
manifest digest, and its private projection binds it into the proved commitment.
The builder retains `synthetic-context.json` beside the synthetic proof. These
files contain only the repository's synthetic fixture, never customer inputs.

The opt-in pairing integration reconstructs the expected synthetic context and
public signals using the pinned manifest. It checks the artifact context before
pairing and rejects the original proof under a substituted manifest's projection.
The authorization nullifier remains stable when only artifacts change, preserving
replay protection across artifact revisions.

Regenerate older test bundles that lack this context with:

```bash
uv run python scripts/test_development_circuits.py NEW_OUTPUT_DIRECTORY
```

An existing local development-only phase-two Powers of Tau file can be supplied
with `--prepared-ptau PATH`; its digest is recorded and its reuse is not a new
ceremony or production approval. This flow still uses independently constructed
synthetic roots and test trust; it does not complete durable current authorization
or historical evidence verification.
