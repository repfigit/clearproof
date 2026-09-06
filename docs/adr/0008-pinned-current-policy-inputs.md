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
