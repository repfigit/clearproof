# Proof system selection: Groth16 for the local pilot

Status: retained implementation choice; production assurance is not established.

This document records the proof-system choice. The separate
[authenticated-credential ADR 0003](0003-authenticated-pilot-credentials.md)
describes what the pilot credential proves.

The current adoption pilot uses Circom, snarkjs and Groth16 over BN254. Its
Python verifier and Solidity `PilotGroth16Verifier` check the same eight-signal
`pilot-transfer-v2` statement. The current profile binds the exact credential,
transfer projection and approved roots; it does not prove arbitrary legal or
business-policy compliance. See [ADR 0009](0009-credential-bound-pilot-profile.md)
and the [current registry trust boundary](../internal/PILOT_CURRENT_REGISTRY.md).

Keeping this proof system allows the pilot to exercise one implemented statement
through witness generation, real pairing, durable authorization and contract
receipt mirroring. A migration would require a new versioned circuit/profile,
artifact approval path and matching cross-runtime acceptance evidence. The local
pilot does not implement or validate a Noir/UltraHonk alternative.

The [older benchmark note](../internal/NOIR_BENCHMARK.md) is historical exploratory
material, not a current release benchmark. Earlier ceremony duration/cost,
provider-service, gas-price and migration-timeline estimates in this ADR lacked
sufficient evidence and must not be used for budget, schedule or production claims.
A new comparison should measure equivalent statements with pinned toolchains and
report its actual environment, artifact provenance and verification scope.

Development proving keys and self-generated manifests are explicitly unapproved.
Successful local proofs do not establish an audited setup or independent security
assurance. Production authorization remains gated on independent review, closed
findings, a documented approved setup/artifact path and deployment operations.
No production ceremony, provider engagement, launch date or chain deployment is
scheduled or authorized by this document.

Use the [local acceptance workflow](../operations/local-pilot-acceptance.md) for
reproducible development evidence and the
[adoption plan](../plans/2026-09-05-adoption-pilot-implementation.md) for the
separate F5 production gate. The legacy BLS12-381 exploration is described in
[its own ADR](0002-bls12381-migration.md); it is not the current pilot profile.
