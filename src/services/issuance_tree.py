"""Build issuance membership from eligible persisted enrollment using incremental Merkle state."""

from dataclasses import dataclass, field

from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.discovery_profile import DiscoveryError, parse_target
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.transfer import Address, Epoch, Record
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, PilotTree
from src.services.enrollment import (
    EnrollmentIneligible,
    EnrollmentIntegrityError,
    enrollment_audience,
    enrollment_scope,
    load_unrevoked_enrollment,
)
from src.services.enrollment_inventory import ENROLLMENT_PAGE_SIZE
from src.services.issuance_source import issuance_source_domain, pack_issuance_source
from src.storage.merkle import IncrementalMerkleStore, MerkleRootState
from src.storage.pilot import PilotTransaction


class IssuanceTreeContext(Record):
    issuer_did: str = Field(max_length=512)
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    now: Epoch
    depth: int = Field(ge=1, le=32)

    @model_validator(mode="after")
    def canonical_context(self):
        try:
            target = parse_target(self.issuer_did)
        except DiscoveryError:
            raise ValueError("Invalid issuance tree context") from None
        if target.did != self.issuer_did or self.registry_address == "0x" + "0" * 40:
            raise ValueError("Invalid issuance tree context")
        return self


class PersistedIssuanceTree:
    """View over the persisted incremental Merkle state with the PilotTree read surface."""

    def __init__(
        self,
        root: str,
        entries: tuple[tuple[str, str], ...],
        depth: int,
        root_version: int,
        *,
        merkle: IncrementalMerkleStore | None = None,
    ):
        self._root = root
        self._entries = entries
        self._depth = depth
        self._root_version = root_version
        self._merkle = merkle
        self._in_memory: PilotTree | None = None

    @property
    def root(self) -> str:
        return self._root

    @property
    def entries(self) -> tuple[tuple[str, str], ...]:
        return self._entries

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def root_version(self) -> int:
        return self._root_version

    def membership(self, record_id: str) -> dict:
        if self._in_memory is None:
            self._in_memory = PilotTree(list(self._entries), depth=self._depth)
        return self._in_memory.membership(record_id)

    async def persisted_membership(self, record_id: str) -> dict:
        if self._merkle is None:
            raise RuntimeError("Persisted Merkle store is unavailable")
        return await self._merkle.membership(record_id)


@dataclass(frozen=True)
class IssuanceTree:
    tree: PersistedIssuanceTree | PilotTree = field(repr=False)
    source: dict = field(repr=False)
    pages: tuple[dict, ...] = field(default=(), repr=False)
    scanned_enrollments: int = 0
    root_version: int = 0

    @property
    def source_digest(self) -> str:
        return record_digest(issuance_source_domain(self.source), self.source)


async def read_issuance_root(
    tx: PilotTransaction,
    *,
    issuer_did: str,
    chain_id: int,
    registry_address: str,
    depth: int = ISSUANCE_TREE_DEPTH,
) -> MerkleRootState | None:
    """Read the persisted incremental Merkle root state for one issuer audience under the tenant lock."""
    IssuanceTreeContext(issuer_did=issuer_did, chain_id=chain_id, registry_address=registry_address, now=0, depth=depth)
    tx.require_issuer(issuer_did)
    scope = enrollment_audience(tx.tenant_id, issuer_did, chain_id, registry_address)
    merkle = IncrementalMerkleStore(tx, scope, depth=depth)
    return await merkle.read_root()


async def read_issuance_membership(
    tx: PilotTransaction,
    credential_id: str,
    *,
    issuer_did: str,
    chain_id: int,
    registry_address: str,
    depth: int = ISSUANCE_TREE_DEPTH,
) -> dict:
    """Read an authenticated O(depth) Merkle membership path directly from persisted nodes."""
    IssuanceTreeContext(issuer_did=issuer_did, chain_id=chain_id, registry_address=registry_address, now=0, depth=depth)
    tx.require_issuer(issuer_did)
    scope = enrollment_audience(tx.tenant_id, issuer_did, chain_id, registry_address)
    merkle = IncrementalMerkleStore(tx, scope, depth=depth)
    return await merkle.membership(credential_id)


async def build_issuance_tree(
    tx: PilotTransaction,
    *,
    issuer_did: str,
    chain_id: int,
    registry_address: str,
    now: int,
    depth: int = ISSUANCE_TREE_DEPTH,
    scan_limit: int | None = None,
) -> IssuanceTree:
    """Caller holds the tenant lock through candidate construction.

    Scans the complete persisted audience inventory in bounded pages and updates
    the persisted incremental Merkle tree under the held tenant lock. When new
    eligible enrollments extend the prior leaf set, only the appended paths are
    hashed and written (O(delta * depth)) instead of rebuilding the full tree.
    When an optional ``scan_limit`` is supplied, scanning fails closed before
    returning a partial tree.
    The registrar must separately authorize the issuer and sign the resulting
    root/source digest; this function neither signs nor approves arbitrary roots.
    """
    IssuanceTreeContext(
        issuer_did=issuer_did, chain_id=chain_id, registry_address=registry_address, now=now, depth=depth
    )
    if scan_limit is not None and (type(scan_limit) is not int or not 0 <= scan_limit <= 2**depth):
        raise ValueError("Invalid enrollment scan budget")
    tx.require_issuer(issuer_did)
    await tx.check_enrollment_inventory()
    scope = enrollment_audience(tx.tenant_id, issuer_did, chain_id, registry_address)
    entries: list[tuple[str, str]] = []
    after = None
    scanned = 0
    capacity = 2**depth
    while True:
        ids = await tx.enrollment_ids(scope, after=after, limit=ENROLLMENT_PAGE_SIZE)
        for credential_id in ids:
            scanned += 1
            if scan_limit is not None and scanned > scan_limit:
                raise ValueError("Enrollment audience scan capacity exceeded")
            stored = await tx.get("credential", credential_id)
            consent = EnrollmentConsent.model_validate(stored["consent"])
            if enrollment_scope(consent) != scope:
                raise EnrollmentIntegrityError("Enrollment inventory audience differs")
            try:
                credential = await load_unrevoked_enrollment(
                    tx, credential_id, chain_id=chain_id, registry_address=registry_address, now=now
                )
            except EnrollmentIneligible:
                continue
            if len(entries) >= capacity:
                raise ValueError("Pilot issuance tree capacity exceeded")
            entries.append((credential_id, credential.commitment))
        if len(ids) < ENROLLMENT_PAGE_SIZE:
            break
        after = ids[-1]
    ordered = tuple(sorted(entries))
    merkle = IncrementalMerkleStore(tx, scope, depth=depth)
    state = await merkle.sync_entries(list(ordered))
    tree = PersistedIssuanceTree(state.root_hash, ordered, depth, state.root_version, merkle=merkle)
    source, pages = pack_issuance_source(
        {
            "tenant_id": tx.tenant_id,
            "issuer_did": issuer_did,
            "chain_id": chain_id,
            "registry_address": registry_address,
            "evaluated_at": now,
            "depth": depth,
        },
        tree.entries,
    )
    return IssuanceTree(tree, source, pages, scanned, root_version=state.root_version)
