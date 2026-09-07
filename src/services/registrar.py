"""Local pilot registrar: construct, sign and persist issuer roots atomically."""

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.protocol.credential import digest_limbs
from src.protocol.root_snapshot import RootSnapshot, RootTrustStore, SignedRootSnapshot, root_key_id, sign_root
from src.registry.pilot_tree import PilotTree
from src.registry.poseidon import poseidon_hash
from src.services.issuance_tree import IssuanceTreeContext, build_issuance_tree
from src.services.root_publication import persist_approved_root, root_record_id
from src.storage.database import Database
from src.storage.pilot import PilotStore, RecordConflict
from src.storage.pilot_cipher import RecordCipher


class PilotRegistrar:
    """Operator-provisioned signer and issuer set; never populate these from a request."""

    def __init__(
        self,
        db: Database,
        cipher: RecordCipher,
        principal: Principal,
        trust: RootTrustStore,
        signer: Ed25519PrivateKey,
        *,
        issuers: tuple[str, ...],
        chain_id: int,
        registry_address: str,
        depth: int = 8,
    ):
        self._principal = Principal.model_validate(principal)
        if type(issuers) is not tuple or not 1 <= len(issuers) <= 16 or len(set(issuers)) != len(issuers):
            raise ValueError("Configure 1–16 unique issuer identities")
        for issuer in issuers:
            IssuanceTreeContext(
                issuer_did=issuer, chain_id=chain_id, registry_address=registry_address, now=0, depth=depth
            )
        self._issuers = tuple(sorted(issuers))
        self._store = PilotStore(db, cipher, self._principal)
        self._trust, self._signer = trust, signer
        self._chain_id, self._registry_address, self._depth = chain_id, registry_address, depth

    async def refresh(self, *, expected_revision: int, idempotency_key: str, now: int, ttl: int = 300) -> dict:
        self._principal.require("tenant:admin")
        self._principal.require("evidence:decrypt")
        for issuer in self._issuers:
            self._principal.require_issuer(issuer)
        if type(expected_revision) is not int or not 0 <= expected_revision < 2**53 - 1:
            raise ValueError("Expected revision must be a nonnegative safe integer")
        if type(ttl) is not int or not 1 <= ttl <= 86400:
            raise ValueError("Approval lifetime must be 1–86400 seconds")
        key_id = root_key_id(self._signer.public_key().public_bytes_raw())
        base = dict(
            tenant_id=self._principal.tenant_id,
            chain_id=self._chain_id,
            registry_address=self._registry_address,
            tree_depth=self._depth,
            issued_at=now,
            expires_at=now + ttl,
            key_id=key_id,
            revision=1,
        )
        prototype = RootSnapshot(**base, kind="issuer-root", root="0", source_digest="0" * 64)
        request = {
            "issuers": list(self._issuers),
            "chain_id": self._chain_id,
            "registry_address": self._registry_address,
            "depth": self._depth,
            "ttl": ttl,
            "key_id": key_id,
            "expected_revision": expected_revision,
            "operation": "registrar-refresh-v1",
        }

        async def persist(tx):
            aggregate = await tx.read("issuer-root", root_record_id(prototype))
            if (aggregate.revision if aggregate else 0) != expected_revision:
                raise RecordConflict("Registrar expected head revision differs")

            async def approve(kind, issuer, root, source, domain):
                source_digest = record_digest(domain, source)
                snapshot = RootSnapshot(**base, kind=kind, issuer_did=issuer, root=root, source_digest=source_digest)
                previous = await tx.read(kind, root_record_id(snapshot))
                if previous:
                    prior = SignedRootSnapshot.model_validate(previous.value)
                    snapshot = RootSnapshot.model_validate(
                        {
                            **snapshot.model_dump(),
                            "revision": previous.revision + 1,
                            "previous_digest": prior.snapshot.digest,
                        }
                    )
                signed = sign_root(snapshot, self._signer)
                # Signature scope and predecessor checks happen before commit.
                await persist_approved_root(tx, signed, self._trust, now=now)
                existing = await tx.get("root-source", source_digest)
                if existing is None:
                    await tx.put("root-source", source_digest, source)
                elif existing != source:
                    raise RecordConflict("Root source digest collision or inconsistent record")
                return signed

            leaves, issuer_sources = [], []
            for issuer in self._issuers:
                candidate = await build_issuance_tree(
                    tx,
                    issuer_did=issuer,
                    chain_id=self._chain_id,
                    registry_address=self._registry_address,
                    now=now,
                    depth=self._depth,
                )
                signed = await approve(
                    "issuance-root", issuer, candidate.tree.root, candidate.source, "clearproof/issuance-source/v1"
                )
                issuer_id = hashlib.sha256(issuer.encode("ascii")).hexdigest()
                leaf = str(poseidon_hash([103, *digest_limbs(issuer), int(candidate.tree.root)]))
                leaves.append((issuer_id, leaf))
                issuer_sources.append(
                    {
                        "issuer_did": issuer,
                        "entry_id": issuer_id,
                        "issuance_snapshot_digest": signed.snapshot.digest,
                        "issuance_root": candidate.tree.root,
                    }
                )
            issuer_tree = PilotTree(leaves, depth=self._depth)
            source = {
                "tenant_id": tx.tenant_id,
                "chain_id": self._chain_id,
                "registry_address": self._registry_address,
                "evaluated_at": now,
                "depth": self._depth,
                "issuers": issuer_sources,
            }
            head = await approve("issuer-root", None, issuer_tree.root, source, "clearproof/issuer-source/v1")
            return {
                "status": "published",
                "snapshot_digest": head.snapshot.digest,
                "revision": head.snapshot.revision,
                "root": head.snapshot.root,
            }

        return await self._store.run_idempotent("update-root", idempotency_key, request, persist)
