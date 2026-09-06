# ADR 0005: binding canonical transfer records to private circuit inputs

Status: development projection implemented; full authorization profile pending.

The circuit cannot infer which payment an arbitrary amount belongs to. The pilot
therefore commits to a fixed 48-field projection of a validated canonical transfer,
verification context, exact-asset catalog and policy thresholds. Verifiers must
recompute the expected commitment from those independently accepted inputs. A
commitment copied from an untrusted proof is not an expected value.

`project_transfer()` revalidates the transfer/context, checks catalog identity and
context binding/freshness, and derives the exact quotient/remainder and private
tier. Full SHA-256 digests are represented as high/low 128-bit limbs, never reduced
modulo the proof field. Wallet/contract addresses are 160-bit integers; chain IDs
are 64 bits; times are 53 bits; quantities and valuation components are 128 bits.
Projection range validation rejects field aliases before hashing.

The commitment starts with domain 201 and applies six Poseidon(9) hashes in order,
each consuming the preceding state and the next eight fields. The exact field
layout is `FIELD_NAMES` in `src/prover/pilot_projection.py`. The circuit repeats
this construction and equates its result to the verifier's expected commitment.
It also evaluates integer valuation, private tier, positive address/asset bounds,
chain audience equality and observation/transfer/evaluation/freshness constraints.

The projection includes both canonical record digests and the direct operands of
circuit predicates. This does not prove SHA-256/canonical JSON serialization inside
ZK. The verifier's recomputation binds the actual records to those operands; the
Poseidon commitment prevents replacing witness operands under that expected
commitment. A verifier lacking access to the private transfer must instead verify
an independently trusted attestation binding the canonical digest and projection.
That attestation and its on-chain acceptance still need implementation. Price
truth, issuer trust and legal policy applicability are not supplied by this hash.

A separate stable authorization scope is Poseidon(202, tenant limbs, transfer-ID
limbs, nonce limbs, deployment chain, deployment address). The holder nullifier is
Poseidon(203, holder secret, authorization scope). It deliberately excludes the
evaluation time, price and policy, so re-evaluation cannot make a new nullifier for
the same holder and immutable transfer identity. Durable transfer-ID/nonce binding
and atomic consumption remain necessary; changing the ID creates another scope.
The full parent must connect holder-secret knowledge to the issued credential.

The new projection keeps amount/tier and participant fields private. The test
harness exposes the projection commitment and authorization-scope output solely
for constraint checks. The final public signal profile is still pending and must
not include the legacy SAR signal or publish the private tier. No legacy ABI or
trusted setup artifacts are changed by these tests.

Tests alter every projected field and check commitment changes; actual Circom
witnesses reject substituted wallets, assets, amounts, valuation, jurisdiction,
audience, policy and tier under the original expected commitment. Recomputed
commitments still fail invalid valuation, time, freshness, chain or tier predicates.
These are constraint checks, not a completed Groth16 authorization flow.
