"""Authenticate a pilot sanctions root before building checkpoint publication arguments.

Two pilot destinations exist. ``PilotCurrentRegistry.publishHead`` with
``Kind.Sanctions`` is the head that ``inspect`` compares with public signal 2, and
``PilotRootCheckpoint.publish`` is the independent root-approval checkpoint. Both
require a registrar-signed ``sanctions-root`` snapshot whose root, depth and source
digest equal a tree rebuilt from the published, key-sorted address list. This module
neither selects a network nor sends a transaction.
"""

from src.chain.pilot_checkpoint import HEAD_ABI, publication_arguments
from src.protocol.canonical import record_digest
from src.protocol.root_snapshot import RootSnapshot, RootTrustError, RootTrustStore, SignedRootSnapshot, root_scope_id
from src.registry.pilot_sanctions import PilotSanctionsTree
from src.registry.pilot_tree import SANCTIONS_TREE_DEPTH

SANCTIONS_KIND = 2  # PilotCurrentRegistry.Kind.Sanctions
MAX_SAFE_INTEGER = 2**53 - 1

PAUSED_ABI = {
    "type": "function",
    "name": "paused",
    "stateMutability": "view",
    "inputs": [],
    "outputs": [{"name": "", "type": "bool"}],
}

REGISTRY_ABI = [
    {
        "type": "function",
        "name": "publishHead",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "tenant", "type": "bytes32"},
            {"name": "kind", "type": "uint8"},
            {"name": "scope", "type": "bytes32"},
            {"name": "digest", "type": "bytes32"},
            {"name": "value", "type": "uint256"},
            {"name": "expectedRevision", "type": "uint64"},
            {"name": "validFrom", "type": "uint64"},
            {"name": "validUntil", "type": "uint64"},
            {"name": "enabled", "type": "bool"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "head",
        "stateMutability": "view",
        "inputs": [
            {"name": "tenant", "type": "bytes32"},
            {"name": "kind", "type": "uint8"},
            {"name": "scope", "type": "bytes32"},
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "digest", "type": "bytes32"},
                    {"name": "value", "type": "uint256"},
                    {"name": "revision", "type": "uint64"},
                    {"name": "validFrom", "type": "uint64"},
                    {"name": "validUntil", "type": "uint64"},
                    {"name": "publisherEpoch", "type": "uint64"},
                    {"name": "enabled", "type": "bool"},
                ],
            }
        ],
    },
    {
        "type": "function",
        "name": "publishers",
        "stateMutability": "view",
        "inputs": [{"name": "tenant", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "publisherEpochs",
        "stateMutability": "view",
        "inputs": [{"name": "tenant", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint64"}],
    },
    PAUSED_ABI,
]

CHECKPOINT_ABI = [
    *HEAD_ABI,
    PAUSED_ABI,
    {
        "type": "function",
        "name": "publish",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "tenantHash", "type": "bytes32"},
            {"name": "rootScope", "type": "bytes32"},
            {"name": "snapshotDigest", "type": "bytes32"},
            {"name": "root", "type": "uint256"},
            {"name": "expectedRevision", "type": "uint64"},
            {"name": "approvalRevision", "type": "uint64"},
            {"name": "validFrom", "type": "uint64"},
            {"name": "validUntil", "type": "uint64"},
        ],
        "outputs": [],
    },
]


def registry_tenant_hash(tenant_id: str) -> bytes:
    """Tenant key used by PilotCurrentRegistry (same derivation as the mirror plan)."""
    return bytes.fromhex(record_digest("clearproof/tenant-checkpoint/v1", {"tenant_id": tenant_id}))


def authenticate_sanctions_root(
    signed: SignedRootSnapshot, trust: RootTrustStore, tree: PilotSanctionsTree, *, now: int
) -> RootSnapshot:
    """Return the snapshot only if it is a trusted approval of exactly this rebuilt tree."""
    snapshot = trust.verify_historical(signed, evaluated_at=now)
    if (
        snapshot.kind != "sanctions-root"
        or snapshot.tree_depth != SANCTIONS_TREE_DEPTH
        or tree.depth != SANCTIONS_TREE_DEPTH
        or snapshot.root != tree.root
        or snapshot.source_digest != tree.source_digest
    ):
        raise RootTrustError("Sanctions approval does not match the rebuilt pilot tree")
    return snapshot


def registry_head_arguments(
    signed: SignedRootSnapshot, trust: RootTrustStore, tree: PilotSanctionsTree, *, now: int, expected_revision: int
) -> tuple:
    """Arguments for ``PilotCurrentRegistry.publishHead(..., Kind.Sanctions, ...)``.

    Scope, digest and value match the sanctions head candidate in the authorization
    mirror plan, so later ``publishBatch`` calls can reuse this head unchanged.
    """
    snapshot = authenticate_sanctions_root(signed, trust, tree, now=now)
    if type(expected_revision) is not int or not 0 <= expected_revision < MAX_SAFE_INTEGER:
        raise ValueError("Expected the current registry head revision")
    return (
        registry_tenant_hash(snapshot.tenant_id),
        SANCTIONS_KIND,
        bytes.fromhex(root_scope_id(snapshot)),
        bytes.fromhex(snapshot.digest),
        int(snapshot.root),
        expected_revision,
        snapshot.issued_at,
        snapshot.expires_at,
        True,
    )


def checkpoint_arguments(
    signed: SignedRootSnapshot, trust: RootTrustStore, tree: PilotSanctionsTree, *, now: int, expected_revision: int
) -> tuple:
    """Arguments for ``PilotRootCheckpoint.publish`` after the same tree match."""
    authenticate_sanctions_root(signed, trust, tree, now=now)
    return publication_arguments(signed, trust, now=now, expected_revision=expected_revision)
