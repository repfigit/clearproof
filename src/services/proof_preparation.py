"""Prepare private pilot witnesses from the registrar's durable tenant inventories."""

import hashlib

from src.protocol.canonical import record_digest
from src.protocol.credential import digest_limbs
from src.protocol.root_snapshot import RootTrustError
from src.prover.pilot_compliance import PUBLIC_SIGNALS, compliance_witness
from src.prover.pilot_current import expected_current_signals
from src.registry.pilot_sanctions import PilotSanctionsTree
from src.registry.pilot_tree import PilotTree
from src.registry.poseidon import poseidon_hash
from src.services.proof_inspection import ProofInspectionService


class ProofPreparationService(ProofInspectionService):
    async def prepare_witness(
        self, credential_id: str, *, secret: str, sanctions_tree: PilotSanctionsTree, now: int
    ) -> dict:
        """Read one consistent snapshot; return private inputs without retaining them.

        The caller owns the holder secret and supplies the sanctions inventory;
        its root must match the independently approved current head. Issuance
        paths come exclusively from retained registrar sources. Generate the
        proof after this method returns, outside the tenant transaction. Current
        authorization must recheck state because roots or revocation can change
        while proving. Never log or persist this return value in plaintext.
        """
        for role in ("proof:generate", "policy:read", "evidence:decrypt"):
            self._principal.require(role)
        async with self._store.transaction() as tx:
            credential = await self._load_current_credential(tx, credential_id, now=now)
            sources = []
            for name, domain in (("issuance", "issuance"), ("issuers", "issuer")):
                snapshot = self._inputs[name].snapshot
                source = await tx.get("root-source", snapshot.source_digest)
                if source is None or record_digest(f"clearproof/{domain}-source/v1", source) != snapshot.source_digest:
                    raise RootTrustError("Retained registrar source is missing or inconsistent")
                if any(
                    source.get(key) != value
                    for key, value in {
                        "tenant_id": snapshot.tenant_id,
                        "chain_id": snapshot.chain_id,
                        "registry_address": snapshot.registry_address,
                        "evaluated_at": snapshot.issued_at,
                        "depth": snapshot.tree_depth,
                    }.items()
                ):
                    raise RootTrustError("Retained registrar source scope differs")
                sources.append(source)
            issuance_source, issuer_source = sources
            if issuance_source.get("issuer_did") != credential.issuer_did:
                raise RootTrustError("Retained issuance source issuer differs")
            issuance_tree = PilotTree(
                [(entry["credential_id"], entry["commitment"]) for entry in issuance_source["entries"]], depth=8
            )
            if (credential_id, credential.commitment) not in issuance_tree.entries:
                raise RootTrustError("Enrollment is absent from retained issuance inventory")
            issuer_id = hashlib.sha256(credential.issuer_did.encode("ascii")).hexdigest()
            entries = issuer_source["issuers"]
            selected = [entry for entry in entries if entry["entry_id"] == issuer_id]
            if len(selected) != 1 or selected[0] != {
                "issuer_did": credential.issuer_did,
                "entry_id": issuer_id,
                "issuance_snapshot_digest": self._inputs["issuance"].snapshot.digest,
                "issuance_root": issuance_tree.root,
            }:
                raise RootTrustError("Retained issuer inventory does not bind the issuance approval")
            issuer_tree = PilotTree(
                [
                    (
                        entry["entry_id"],
                        str(poseidon_hash([103, *digest_limbs(entry["issuer_did"]), int(entry["issuance_root"])])),
                    )
                    for entry in entries
                ],
                depth=8,
            )
            if (issuance_tree.root, issuer_tree.root, sanctions_tree.root) != tuple(
                self._inputs[name].snapshot.root for name in ("issuance", "issuers", "sanctions")
            ):
                raise RootTrustError("Witness inventory roots differ from approved heads")
            witness = compliance_witness(
                self._inputs["transfer"],
                self._context,
                self._inputs["registry"],
                credential,
                secret=secret,
                issuance_path=issuance_tree.membership(credential_id),
                issuer_path=issuer_tree.membership(issuer_id),
                sanctions=sanctions_tree,
                valuation_approval=self._inputs["valuation_approval"],
                valuation_trust=self._inputs["valuation_trust"],
                policy_trust=self._inputs["policy_trust"],
            )
            signals = tuple(witness[name] for name in PUBLIC_SIGNALS)
            expected = expected_current_signals(
                artifacts=self._verifier.artifacts,
                credential=credential,
                signals=list(signals),
                now=now,
                **self._inputs,
            )
            if signals != expected:
                raise RootTrustError("Prepared witness differs from current statement")
            return witness
