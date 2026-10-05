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

## Sanctions non-membership relies on a key-sorted tree

Signal 2 is the root of a tree whose leaves are `Poseidon(301, key)` for each raw
EVM address key, plus the `0` and `2^160` sentinels, placed at consecutive leaf
indices in strictly ascending key order (`PilotSanctionsTree`,
`src/registry/pilot_sanctions.py`). For each party, the circuit
(`circuits/pilot_sanctions.circom`) proves only that:

- two leaves `left_key` and `right_key` are members of `sanctions_root`;
- their leaf indices are adjacent (`right_index == left_index + 1`); and
- `left_key < wallet < right_key <= 2^160`.

That is a sound non-membership proof **only if the published tree is sorted by
key**. In an unsorted tree a sanctioned address can sit elsewhere while some
adjacent pair still brackets it, so a valid proof would not imply absence. The
circuit does not and cannot check global ordering.

The root authenticity layer does not check it either. A registrar-signed
`sanctions-root` snapshot, `PilotRootCheckpoint` and the `Kind.Sanctions` head in
`PilotCurrentRegistry` authenticate *which* root is current; none of them inspects
leaves or ordering. **The sanctions-root publisher is therefore trusted for
sortedness** as well as for list completeness and source fidelity.

Auditors re-verify sortedness offline from the public leaf list, without trusting
the publisher:

1. Obtain the published artifact `artifacts/pilot_sanctions_tree.json`
   (`clearproof-pilot-sanctions-tree-v1`). It lists every address in
   `sorted_addresses`, with `root`, `depth`, `source_digest` and counts.
2. Run `uv run python scripts/build_pilot_sanctions_tree.py --verify --output <artifact>`.
   It requires canonical, nonzero, strictly ascending keys, rebuilds the depth-20
   tree with both sentinels and rejects any root, source-digest, depth or count
   mismatch (`PilotSanctionsTree.from_artifact`).
3. Check that the rebuilt `root` and `source_digest` equal the signed snapshot's
   `root` and `source_digest`, and that the snapshot digest is the current
   checkpoint/head digest on the pinned deployment.
4. Optionally rebuild the address list itself from the recorded feed digests
   (`scripts/build_sanctions_tree.py` source manifest) to check completeness.

The publication tool (`scripts/publish_pilot_sanctions_head.py`) performs steps 2
and 3 before it will send, but that is the publisher checking itself; independent
re-verification is the auditor's control.

## Relationship to v2

Public signal order, meaning and hash compositions are identical to
`pilot-transfer-v2`. Only the tree depths, and therefore the keys, differ (v2 used
depth 8 for all three trees). v2 is now historical, like v1: current artifact and
context checks reject it, and read-only pairing can inspect independently pinned
v2 material. Never promote a v2 manifest by editing its profile label.

