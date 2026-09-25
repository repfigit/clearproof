# pilot-transfer-v3 public statement

Development Groth16/BN254 profile, Circom `pilot_compliance.circom`
(`PilotCompliance(32, 20, 20)`). See
[ADR 0011](../docs/adr/0011-production-tree-depths.md) for the v2 → v3 tree-depth
change and [ADR 0009](../docs/adr/0009-credential-bound-pilot-profile.md) for the
v1 migration and the credential-substitution threat. All signals are canonical unsigned scalar
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

V1 and v2 have the same signal count but different keys (v1 also has a different
first-signal meaning). Never choose a profile by signal count. New manifests
explicitly name v3; missing-profile legacy development manifests retain their v1
meaning. Current artifact-context and root checks reject v1 and v2. Read-only
pairing inspection can use independently pinned v1 or v2 keys and reports that
profile explicitly. No existing Sepolia deployment is claimed to implement v3.

## Tree depths

Depths are fixed by the circuit and its keys:

| Tree | Depth | Capacity |
| --- | --- | --- |
| Issuance (credentials under an issuance root) | 32 | 2^32 leaves |
| Authorized issuers | 20 | 2^20 leaves |
| Sanctions (raw EVM addresses) | 20 | 2^20 − 2 addresses; two leaves are the `0` and `2^160` sentinels |

Signed root snapshots must state exactly these depths for their kind
(`issuance-root` 32, `issuer-root` 20, `sanctions-root` 20); other depths reject.

## Relationship to v2

Public signal order, meaning and hash compositions are identical to
`pilot-transfer-v2`. Only the tree depths, and therefore the keys, differ (v2 used
depth 8 for all three trees). v2 is now historical, like v1: current artifact and
context checks reject it, and read-only pairing can inspect independently pinned
v2 material. Never promote a v2 manifest by editing its profile label.

