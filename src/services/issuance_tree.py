"""Build issuance membership only from eligible persisted enrollment in one tenant transaction."""

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
from src.services.issuance_source import MAX_ISSUANCE_ENTRIES, issuance_source_domain, pack_issuance_source
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


@dataclass(frozen=True)
class IssuanceTree:
    tree: PilotTree = field(repr=False)
    source: dict = field(repr=False)
    pages: tuple[dict, ...] = field(default=(), repr=False)
    scanned_enrollments: int = 0

    @property
    def source_digest(self) -> str:
        return record_digest(issuance_source_domain(self.source), self.source)


async def build_issuance_tree(
    tx: PilotTransaction,
    *,
    issuer_did: str,
    chain_id: int,
    registry_address: str,
    now: int,
    depth: int = ISSUANCE_TREE_DEPTH,
    scan_limit: int = MAX_ISSUANCE_ENTRIES,
) -> IssuanceTree:
    """Caller holds the tenant lock through candidate construction.

    Scan the complete persisted audience inventory in bounded pages. The current
    source is paged above 256 leaves, with a bounded 1024-entry construction.
    Revocation changes cannot interleave with this scan.
    The registrar must separately authorize the issuer and sign the resulting
    root/source digest; this function neither signs nor approves arbitrary roots.
    """
    IssuanceTreeContext(
        issuer_did=issuer_did, chain_id=chain_id, registry_address=registry_address, now=now, depth=depth
    )
    if type(scan_limit) is not int or not 0 <= scan_limit <= MAX_ISSUANCE_ENTRIES:
        raise ValueError("Invalid enrollment scan budget")
    tx.require_issuer(issuer_did)
    await tx.check_enrollment_inventory()
    scope = enrollment_audience(tx.tenant_id, issuer_did, chain_id, registry_address)
    entries = []
    after = None
    scanned = 0
    while True:
        ids = await tx.enrollment_ids(scope, after=after, limit=ENROLLMENT_PAGE_SIZE)
        for credential_id in ids:
            scanned += 1
            if scanned > scan_limit:
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
            if len(entries) >= min(MAX_ISSUANCE_ENTRIES, 2**depth):
                raise ValueError("Pilot issuance tree capacity exceeded")
            entries.append((credential_id, credential.commitment))
        if len(ids) < ENROLLMENT_PAGE_SIZE:
            break
        after = ids[-1]
    tree = PilotTree(entries, depth=depth)
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
    return IssuanceTree(tree, source, pages, scanned)
