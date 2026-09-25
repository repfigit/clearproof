# ADR 0011: Production tree depths in pilot-transfer-v3

Status: development implementation. Keys remain `development-unapproved`; no
audit or production setup has approved this circuit.

## Context

`pilot-transfer-v2` instantiated `PilotCompliance(8, 8, 8)`. Every tree held at
most 256 leaves:

| Tree | v2 capacity | What a global deployment needs |
| --- | --- | --- |
| Issuance (credentials under one issuer's issuance root) | 256 | Large custodial VASPs serve tens to hundreds of millions of customers |
| Authorized issuers (one leaf per issuer and issuance root) | 256 | Thousands of VASPs/issuers, plus retained leaves across issuance-root rotations |
| Sanctions (raw EVM addresses plus two sentinels) | 254 addresses | Consolidated OFAC/EU/UK/UN address lists plus optional screening-provider lists |

Tree depth is fixed by the circuit, and therefore by the proving and verification
keys. It cannot change after a production setup without a new profile, new keys
and a new verifier deployment. Everything else that bounds capacity (storage
scans, registrar configuration, tree construction) is ordinary software. Depth
should therefore be chosen once, generously, before any production setup.

## Decision

Introduce `pilot-transfer-v3` with `PilotCompliance(32, 20, 20)`:

| Tree | Depth | Capacity |
| --- | --- | --- |
| Issuance | 32 | 4,294,967,296 credentials per issuance root |
| Authorized issuers | 20 | 1,048,576 issuer leaves |
| Sanctions | 20 | 1,048,574 addresses (two leaves hold the `0` and `2^160` sentinels) |

The depths are defined once in `src/registry/pilot_tree.py`
(`ISSUANCE_TREE_DEPTH`, `ISSUER_TREE_DEPTH`, `SANCTIONS_TREE_DEPTH`,
`ROOT_TREE_DEPTHS`). The witness builder, registrar, proof preparation, issuance
tree service and root verification all use them. Signed root snapshots must carry
the exact depth for their kind; a snapshot at any other depth is rejected.

Public signal order and meaning are **unchanged** from v2. The profile name still
changes, because the keys change. A v2 manifest carries eight signals and would
otherwise be indistinguishable from a v3 manifest; its proofs cannot be produced
or verified with v3 keys. Under the rule "never select a profile by signal count,"
v2 becomes a historical profile exactly as v1 did. Current artifact and context
checks reject it, and read-only pairing can still inspect pinned v2 material.

## Cost

Measured with circom 2.2.2 and `snarkjs r1cs info`:

| Depths (issuance, issuer, sanctions) | Constraints |
| --- | --- |
| 8, 8, 8 (v2) | 51,728 |
| 20, 20, 20 | 89,168 |
| **32, 20, 20 (v3)** | **95,408** |
| 32, 20, 24 | 103,728 |

Each Merkle level costs roughly 260 constraints per path. The composed circuit
has six paths: one issuance, one issuer, and four sanctions paths (a left and a
right neighbour for each of the two parties). v3 needs a `2^17` (131,072)
powers-of-tau and leaves about 37% headroom. The development zkey grows from
roughly 23 MB to 44 MB. Groth16 verification cost is unchanged because it depends
only on the public signal count.

Sanctions depth 24 was considered. It costs about 8,300 more constraints and still
fits `2^17`. It was rejected because no current consolidated list approaches one
million EVM addresses. Issuance depth 32 was preferred over 24 because the extra
~3,100 constraints remove the only realistic capacity ceiling for the largest
issuers.

## Setup parameters

- Local development generation now uses `2^17`.
- CI uses the SHA-256-pinned PSE perpetual powers of tau
  (`ppot_0080_17.ptau`, 80 contributions) through `--prepared-ptau`. This replaces
  a local single-party phase 1, which took more than 30 minutes at `2^16`.
- The phase-2 keys produced by CI remain unapproved development keys.

The phase-1 choice for production remains an ADR 0004 decision (Groth16 ceremony
vs. a universal setup).

## Not changed by this ADR

- **Address format.** The sanctions gap proof still screens raw 160-bit EVM
  addresses. Non-EVM chains (for example Bitcoin or Solana) need a separate key
  encoding and profile.
- **Software capacity limits.** These are upgradeable without new keys and are
  not addressed here:
  - the registrar is configured for 1–16 issuers;
  - issuance tree construction scans at most 256 enrollments per refresh;
  - `PilotTree` builds sparse trees in memory with pure-Python Poseidon, at about
    210 µs per hash. A one-million-address sanctions tree takes several minutes
    to build.

  Production scale needs an incremental, persisted tree service and paginated
  inventories.
- **Proving keys.** v3 keys are development-only until an approved setup exists.
