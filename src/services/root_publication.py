"""Persist registrar-approved root revisions with atomic predecessor checks."""

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.protocol.root_snapshot import RootSnapshot, RootTrustError, RootTrustStore, SignedRootSnapshot
from src.storage.database import Database
from src.storage.pilot import PilotStore, PilotTransaction, RecordConflict
from src.storage.pilot_cipher import RecordCipher


def root_record_id(snapshot: RootSnapshot) -> str:
    return record_digest(
        "clearproof/root-scope/v1",
        {
            "kind": snapshot.kind,
            "issuer_did": snapshot.issuer_did,
            "chain_id": snapshot.chain_id,
            "registry_address": snapshot.registry_address,
            "proof_profile": snapshot.proof_profile,
        },
    )


class RootPublicationService:
    def __init__(self, db: Database, cipher: RecordCipher, principal: Principal, trust: RootTrustStore):
        self._principal = Principal.model_validate(principal)
        self._store = PilotStore(db, cipher, self._principal)
        self._trust = trust

    async def publish(self, signed: SignedRootSnapshot, *, idempotency_key: str, now: int) -> dict:
        signed = SignedRootSnapshot.model_validate(signed)
        self._principal.require("tenant:admin")
        snapshot = self._trust.verify_historical(signed, evaluated_at=now)
        if snapshot.tenant_id != self._principal.tenant_id:
            raise RootTrustError("Root publication tenant mismatch")
        if snapshot.kind == "issuance-root":
            self._principal.require_issuer(snapshot.issuer_did)

        async def persist(tx):
            return await persist_approved_root(tx, signed, self._trust, now=now)

        return await self._store.run_idempotent("update-root", idempotency_key, signed.model_dump(mode="json"), persist)


async def persist_approved_root(
    tx: PilotTransaction, signed: SignedRootSnapshot, trust: RootTrustStore, *, now: int
) -> dict:
    """Shared transaction boundary for direct and locally coordinated approvals."""
    signed = SignedRootSnapshot.model_validate(signed)
    tx.require_admin()
    snapshot = trust.verify_historical(signed, evaluated_at=now)
    if snapshot.tenant_id != tx.tenant_id:
        raise RootTrustError("Root publication tenant mismatch")
    if snapshot.kind == "issuance-root":
        tx.require_issuer(snapshot.issuer_did)
    rid = root_record_id(snapshot)
    previous = await tx.read(snapshot.kind, rid)
    if previous is None:
        if snapshot.revision != 1:
            raise RecordConflict("Initial root revision must be one")
    else:
        prior = SignedRootSnapshot.model_validate(previous.value)
        previous_snapshot = trust.verify_historical(prior, evaluated_at=prior.snapshot.issued_at)
        if (
            previous_snapshot.revision != previous.revision
            or root_record_id(previous_snapshot) != rid
            or snapshot.revision != previous.revision + 1
            or snapshot.previous_digest != previous_snapshot.digest
            or snapshot.issued_at < previous_snapshot.issued_at
            or snapshot.chain_id != previous_snapshot.chain_id
            or snapshot.registry_address != previous_snapshot.registry_address
            or snapshot.tree_depth != previous_snapshot.tree_depth
        ):
            raise RecordConflict("Root predecessor, audience or tree profile differs")
    await tx.put(
        snapshot.kind,
        rid,
        signed.model_dump(mode="json"),
        expected_revision=previous.revision if previous else None,
    )
    return {"snapshot_digest": snapshot.digest, "revision": snapshot.revision, "status": "published"}
