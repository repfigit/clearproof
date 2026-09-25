---
id: UP-2026-006
title: Circuit profile pilot-transfer-v3 replaces v2 with production-scale tree depths
date: 2026-09-25
publishAfter: 2026-09-25T12:00:00Z
sourceCommit: a67caef
claimRefs:
  - specs/pilot-transfer-v3.md
  - docs/adr/0011-production-tree-depths.md
  - src/registry/pilot_tree.py
  - tests/unit/test_registrar_depths.py
status: approved
summary: The pilot circuit now fixes Merkle tree depths at 32/20/20 (issuance, authorized issuers, sanctions), raising capacity from 256 leaves per tree to production-scale sizes. Groth16 verification cost is unchanged; the keys are still development-only.
---

The development circuit profile for the pilot, `pilot-transfer-v2`, fixed every
Merkle tree at depth 8: at most 256 leaves per tree. That ceiling is irrelevant
for a demo but unusable for the deployments the pilot profile models — a large
custodial VASP issues credentials to tens of millions of customers, a global
authorized-issuer set has thousands of issuers, and consolidated sanctions
address lists run to hundreds of thousands of EVM addresses.

`pilot-transfer-v3` (merged this week, PR #49) fixes the depths at
`PilotCompliance(32, 20, 20)` in the Circom circuit itself:

| Tree | v2 depth | v3 depth | v3 capacity |
| --- | --- | --- | --- |
| Issuance (credentials under an issuance root) | 8 | 32 | 2^32 credentials per issuance root |
| Authorized issuers | 8 | 20 | 2^20 issuer leaves |
| Sanctions (raw EVM addresses) | 8 | 20 | 2^20 − 2 addresses (two leaves are the `0` and `2^160` sentinels) |

Depths live in one place, `src/registry/pilot_tree.py`, and every consumer —
witness builder, registrar, proof preparation, issuance tree service and root
verification — reads them from there. Signed root snapshots must state the exact
depth for their kind; any other depth rejects.

Because tree depth is fixed by the circuit and therefore by the proving and
verification keys, the profile name changes even though the public signal order
and meaning are unchanged from v2. Keys are profile-specific: a v2 manifest
cannot be proved or verified with v3 keys. Current artifact and context checks
reject v1 and v2 as historical profiles; read-only pairing inspection can still
use independently pinned v1/v2 keys and reports the profile explicitly.

What changed in practice: constraints grow from 51,728 (v2) to 95,408 (v3), the
local development setup now uses a `2^17` powers-of-tau, and the development
zkey grows from roughly 23 MB to 44 MB. Groth16 verification cost is unchanged —
it depends only on the public signal count, which is identical to v2.

Two honest boundaries, stated plainly in [ADR 0011](https://github.com/repfigit/clearproof/blob/main/docs/adr/0011-production-tree-depths.md):

- The v3 keys remain development-unapproved — no audit or production setup has
  approved this circuit, and no existing Sepolia deployment implements v3.
- Depth is only one of the production-scaling limits. The registrar still
  configures 1–16 issuers, issuance-tree construction scans at most 256
  enrollments per refresh, and the in-memory sparse tree builds at roughly
  210 µs per hash — production scale needs an incremental persisted tree
  service. Those are ordinary software, upgradeable without new keys.

Read the full public statement at
[specs/pilot-transfer-v3.md](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md).
