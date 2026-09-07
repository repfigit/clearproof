# pilot-transfer-v2 public statement

Development Groth16/BN254 profile, Circom `pilot_compliance.circom`. See
[ADR 0009](../docs/adr/0009-credential-bound-pilot-profile.md) for the v1 migration
and the credential-substitution threat. All signals are canonical unsigned scalar
field decimal strings; order is mandatory.

| Index | Signal | Meaning |
| --- | --- | --- |
| 0 | projection_commitment | Poseidon(204, transfer projection, exact credential commitment, issuance root) |
| 1 | authorized_issuer_root | Aggregate authorized-issuer tree root |
| 2 | sanctions_root | Address non-membership tree root |
| 3 | authorization_nullifier | Poseidon(203, holder secret, authorization scope), unchanged from v1 |
| 4 | evaluated_at | Proof evaluation time, bounded unsigned 53-bit integer |
| 5 | proof_expires_at | Exclusive expiry, bounded by transfer/credential expiry and evaluation + 300 seconds |
| 6 | domain_chain_id | Exact EVM deployment chain |
| 7 | domain_registry | Exact nonzero EVM registry address encoded as an integer |

The private transfer projection uses the existing 48-field canonical projection
and includes the verification context's exact artifact-manifest digest. It is
provided as `transfer_projection_commitment` and checked by the transfer
subcircuit. The outer commitment binds the exact credential and issuance root
used by the credential subcircuit; it is not a caller-selected opaque assertion.

No public credential fields or amount-tier/SAR advisory signal are added. Current
verification must independently reconstruct the expected outer commitment using
its authenticated records. Proof verification alone neither authenticates those
records nor establishes current roots, revocation, policy compliance or legal
compliance. The profile cannot authorize replay through historical inspection.

V1 has the same signal count but a different first-signal meaning and different
keys. Never choose a profile by signal count. New manifests explicitly name v2;
missing-profile legacy development manifests retain their v1 meaning. Current
artifact-context and root checks reject v1. Read-only pairing inspection can use
independently pinned v1 keys and reports that profile explicitly. No existing
Sepolia deployment is claimed to implement v2.
