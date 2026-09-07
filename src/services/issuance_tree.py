"""Build issuance membership only from eligible persisted enrollment in one tenant transaction."""

from dataclasses import dataclass, field

from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.discovery_profile import parse_target
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.transfer import Address, Epoch, Record
from src.registry.pilot_tree import PilotTree
from src.services.enrollment import EnrollmentIneligible, load_unrevoked_enrollment
from src.storage.pilot import PilotTransaction


class IssuanceTreeContext(Record):
    issuer_did: str = Field(max_length=512)
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    now: Epoch
    depth: int = Field(ge=1, le=20)

    @model_validator(mode="after")
    def canonical_context(self):
        if parse_target(self.issuer_did).did != self.issuer_did or self.registry_address == "0x" + "0" * 40:
            raise ValueError("Invalid issuance tree context")
        return self


@dataclass(frozen=True)
class IssuanceTree:
    tree: PilotTree = field(repr=False)
    source: dict = field(repr=False)

    @property
    def source_digest(self) -> str:
        return record_digest("clearproof/issuance-source/v1", self.source)


async def build_issuance_tree(
    tx: PilotTransaction, *, issuer_did: str, chain_id: int, registry_address: str, now: int, depth: int = 8
) -> IssuanceTree:
    """Caller holds the tenant lock through candidate construction.

    Pilot scan is explicitly capped at 256 tenant enrollments and fails rather
    than silently truncating. Revocation changes cannot interleave with this scan.
    The registrar must separately authorize the issuer and sign the resulting
    root/source digest; this function neither signs nor approves arbitrary roots.
    """
    IssuanceTreeContext(
        issuer_did=issuer_did, chain_id=chain_id, registry_address=registry_address, now=now, depth=depth
    )
    tx.require_issuer(issuer_did)
    ids = await tx.record_ids("credential")
    if len(ids) == 256 and await tx.record_ids("credential", after=ids[-1], limit=1):
        raise ValueError("Pilot enrollment scan capacity exceeded")
    entries = []
    for credential_id in ids:
        stored = await tx.get("credential", credential_id)
        consent = EnrollmentConsent.model_validate(stored["consent"])
        if (
            consent.credential.issuer_did != issuer_did
            or consent.chain_id != chain_id
            or consent.registry_address != registry_address
        ):
            continue
        try:
            credential = await load_unrevoked_enrollment(
                tx, credential_id, chain_id=chain_id, registry_address=registry_address, now=now
            )
        except EnrollmentIneligible:
            continue
        entries.append((credential_id, credential.commitment))
    tree = PilotTree(entries, depth=depth)
    return IssuanceTree(
        tree,
        {
            "tenant_id": tx.tenant_id,
            "issuer_did": issuer_did,
            "chain_id": chain_id,
            "registry_address": registry_address,
            "evaluated_at": now,
            "depth": depth,
            "entries": [{"credential_id": key, "commitment": leaf} for key, leaf in tree.entries],
        },
    )
