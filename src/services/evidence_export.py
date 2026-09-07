"""Read-only encrypted export of exact retained authorization evidence."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import model_validator

from src.auth.principal import Principal
from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.transfer import Epoch, Hex32, OpaqueId, Record
from src.prover.pilot_artifacts import strict_json
from src.sar.hpke_envelope import derive_key_id, open_envelope, seal_envelope
from src.services.timestamp_evidence import timestamp_record_bytes, timestamp_record_id
from src.storage.pilot import PilotStore

MAX_BUNDLE_BYTES = 8 * 1024 * 1024


class EvidenceRecipient(Record):
    """Server-approved reviewer, distinct from the transfer's beneficiary VASP."""

    tenant_id: OpaqueId
    reviewer_id: OpaqueId
    public_key: Hex32
    not_before: Epoch
    not_after: Epoch

    @model_validator(mode="after")
    def valid_key(self):
        if self.not_before >= self.not_after:
            raise ValueError("Invalid evidence recipient validity")
        X25519PrivateKey.from_private_bytes(bytes([9]) * 32).exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key))
        )
        return self


class EvidenceExportService:
    def __init__(self, db, cipher, principal: Principal, recipient: EvidenceRecipient):
        self.principal = Principal.model_validate(principal)
        self.recipient = EvidenceRecipient.model_validate(recipient)
        if self.recipient.tenant_id != self.principal.tenant_id:
            raise ValueError("Evidence recipient tenant mismatch")
        self.store = PilotStore(db, cipher, self.principal)

    async def export(self, receipt_id: str, *, now: int) -> bytes:
        for role in ("evidence:export", "evidence:decrypt"):
            self.principal.require(role)
        if type(now) is not int or not self.recipient.not_before <= now < self.recipient.not_after:
            raise ValueError("Evidence recipient is not currently approved")
        async with self.store.transaction() as tx:
            receipt = await tx.get("receipt", receipt_id)
            if receipt is None or receipt.get("schema_version") != "clearproof-local-authorization-v1":
                raise ValueError("Authorization receipt unavailable")
            if (
                receipt.get("tenant_id") != tx.tenant_id
                or record_digest("clearproof/local-authorization/v1", receipt) != receipt_id
            ):
                raise ValueError("Authorization receipt identity mismatch")
            proof = await tx.get("proof", receipt["proof_id"])
            manifest = await tx.get("authorization-evidence", receipt["evidence_id"])
            if (
                proof is None
                or manifest is None
                or proof.get("schema_version") != "clearproof-retained-proof-v1"
                or manifest.get("schema_version") != "clearproof-authorization-evidence-v1"
                or manifest.get("tenant_id") != tx.tenant_id
                or record_digest("clearproof/authorization-evidence/v1", manifest) != receipt["evidence_id"]
                or any(
                    proof.get(k) != receipt[k] or manifest.get(k) != receipt[k]
                    for k in ("transfer_digest", "context_digest")
                )
            ):
                raise ValueError("Authorization evidence identity mismatch")
            references = manifest["records"]
            if type(references) is not list or not 1 <= len(references) <= 80:
                raise ValueError("Invalid evidence reference count")
            records = []
            for reference in references:
                row = await tx.read(reference["kind"], reference["record_id"], revision=reference["revision"])
                if row is None or hashlib.sha256(canonical_bytes(row.value)).hexdigest() != reference["sha256"]:
                    raise ValueError("Pinned evidence record unavailable or changed")
                records.append({**reference, "value": row.value})
            configuration = {}
            if set(manifest["configuration"]) != {
                "artifact_manifest",
                "verification_key",
                "asset_registry",
                "valuation_approval",
                "root_pins",
            }:
                raise ValueError("Unsupported evidence configuration")
            for name, descriptor in manifest["configuration"].items():
                if not 1 <= len(descriptor["chunks"]) <= 4:
                    raise ValueError("Invalid configuration chunk count")
                raw = b""
                for identity in descriptor["chunks"]:
                    chunk = await tx.get("authorization-evidence", identity)
                    if chunk is None or record_digest("clearproof/evidence-chunk/v1", chunk) != identity:
                        raise ValueError("Pinned evidence chunk unavailable or changed")
                    raw += base64.b64decode("".join(chunk["data"]), validate=True)
                if len(raw) != descriptor["size"] or hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
                    raise ValueError("Captured configuration digest mismatch")
                configuration[name] = base64.b64encode(raw).decode("ascii")
            bundle = {
                "schema_version": "clearproof-history-bundle-v1",
                "tenant_id": tx.tenant_id,
                "receipt_id": receipt_id,
                "receipt": receipt,
                "proof": proof,
                "evidence_manifest": manifest,
                "records": records,
                "configuration_base64": configuration,
                "exported_at": now,
                "exported_by": self.principal.actor_id,
                "timing_authority": "operator-clock-only",
            }
            timestamp = await tx.get("authorization-evidence", timestamp_record_id(receipt_id))
            if timestamp is not None:
                timestamp_record_bytes(timestamp, tenant_id=tx.tenant_id, receipt_id=receipt_id)
                bundle["decision_timestamp"] = timestamp
            raw = json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            if len(raw) > MAX_BUNDLE_BYTES:
                raise ValueError("Evidence bundle exceeds export limit")
        binding = {
            "tenant_id": self.principal.tenant_id,
            "receipt_id": receipt_id,
            "reviewer_id": self.recipient.reviewer_id,
            "key_id": derive_key_id(bytes.fromhex(self.recipient.public_key)),
            "exported_at": now,
        }
        return json.dumps(
            {
                "schema_version": "clearproof-encrypted-history-v1",
                "binding": binding,
                "hpke": seal_envelope(
                    raw,
                    bytes.fromhex(self.recipient.public_key),
                    record_digest("clearproof/history-export-binding/v1", binding),
                ),
            },
            separators=(",", ":"),
        ).encode("ascii")


def open_evidence_bundle(raw: bytes, private_key: bytes, *, expected_binding: dict) -> dict:
    """Decrypt offline; this does not validate historical compliance or sender identity."""
    envelope = strict_json(raw, limit=12 * 1024 * 1024)
    if (
        type(envelope) is not dict
        or set(envelope) != {"schema_version", "binding", "hpke"}
        or envelope["schema_version"] != "clearproof-encrypted-history-v1"
        or envelope["binding"] != expected_binding
    ):
        raise ValueError("Evidence export binding mismatch")
    public = X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
    hpke = envelope["hpke"]
    if (
        type(hpke) is not dict
        or set(hpke) != {"v", "kem", "kdf", "aead", "kid", "enc", "ct", "aad"}
        or hpke["kid"] != derive_key_id(public)
        or hpke["kid"] != expected_binding.get("key_id")
        or hpke["aad"] != record_digest("clearproof/history-export-binding/v1", expected_binding)
    ):
        raise ValueError("Evidence export recipient mismatch")
    bundle = strict_json(open_envelope(hpke, private_key), limit=MAX_BUNDLE_BYTES)
    if (
        type(bundle) is not dict
        or bundle.get("schema_version") != "clearproof-history-bundle-v1"
        or any(bundle.get(key) != expected_binding[key] for key in ("tenant_id", "receipt_id", "exported_at"))
    ):
        raise ValueError("Evidence bundle scope mismatch")
    return bundle
