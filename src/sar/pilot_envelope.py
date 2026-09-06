"""Transfer-bound HPKE with independently configured recipient key authority."""

from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.discovery_profile import parse_target
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record, Transfer, VerificationContext
from src.sar.hpke_envelope import derive_key_id, open_envelope, seal_envelope

MAX_PAYLOAD_BYTES = 32768


class RecipientAuthority(Record):
    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, lt=2**64)
    registry_address: Address
    recipient_did: str = Field(max_length=512)
    public_key: Hex32
    not_before: Epoch
    not_after: Epoch

    @model_validator(mode="after")
    def valid_scope(self):
        if parse_target(self.recipient_did).did != self.recipient_did or self.not_before >= self.not_after:
            raise ValueError("Invalid recipient authority")
        # Reject unusable low-order public keys before any encryption operation.
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        X25519PrivateKey.from_private_bytes(bytes([9]) * 32).exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key))
        )
        return self

    @property
    def key_id(self):
        return derive_key_id(bytes.fromhex(self.public_key))


class RecipientTrustStore:
    def __init__(self, authorities: list[RecipientAuthority]):
        values = tuple(RecipientAuthority.model_validate(a) for a in authorities)
        if not 1 <= len(values) <= 256 or len({a.key_id for a in values}) != len(values):
            raise ValueError("Expected distinct independently approved recipient keys")
        self._keys = MappingProxyType({a.key_id: a for a in values})

    def select(self, key_id: str, transfer: Transfer, context: VerificationContext, *, now: int) -> RecipientAuthority:
        context.check_transfer(transfer)
        key = self._keys.get(key_id)
        if (
            key is None
            or type(now) is not int
            or not key.not_before <= now < key.not_after
            or key.tenant_id != transfer.tenant_id
            or key.chain_id != int(context.deployment_chain_id)
            or key.registry_address != context.deployment_address
            or transfer.beneficiary.kind != "vasp"
            or key.recipient_did != transfer.beneficiary.vasp_did
        ):
            raise ValueError("Recipient key is outside current transfer authority")
        return key


def seal_pilot_envelope(
    plaintext: bytes,
    trust: RecipientTrustStore,
    key_id: str,
    transfer: Transfer,
    context: VerificationContext,
    *,
    proof_digest: str,
    now: int,
) -> dict:
    if type(plaintext) is not bytes or not 1 <= len(plaintext) <= MAX_PAYLOAD_BYTES:
        raise ValueError("Expected 1–32768 payload bytes")
    authority = trust.select(key_id, transfer, context, now=now)
    binding = {
        "tenant_id": transfer.tenant_id,
        "transfer_digest": transfer.digest,
        "context_digest": context.digest,
        "proof_digest": proof_digest,
        "recipient_did": authority.recipient_did,
        "recipient_key_id": authority.key_id,
        "sealed_at": now,
    }
    aad = record_digest("clearproof/pilot-envelope-binding/v1", binding)
    hpke = seal_envelope(plaintext, bytes.fromhex(authority.public_key), aad)
    ciphertext = hpke.pop("ct")
    hpke["ct_chunks"] = [ciphertext[start : start + 2048] for start in range(0, len(ciphertext), 2048)]
    return {
        "schema_version": "clearproof-pilot-envelope-v1",
        "binding": binding,
        "hpke": hpke,
    }


def open_pilot_envelope(envelope: dict, private_key: bytes, *, expected_binding: dict) -> bytes:
    """Decrypt against independently expected transfer/proof/recipient metadata.

    Base-mode HPKE does not authenticate sender identity or prove payload semantics.
    Do not construct expected_binding merely by copying an untrusted envelope.
    """
    if (
        type(envelope) is not dict
        or set(envelope) != {"schema_version", "binding", "hpke"}
        or envelope["schema_version"] != "clearproof-pilot-envelope-v1"
        or envelope["binding"] != expected_binding
    ):
        raise ValueError("Envelope binding mismatch")
    public = X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
    hpke = envelope["hpke"]
    if (
        type(hpke) is not dict
        or set(hpke) != {"v", "kem", "kdf", "aead", "kid", "enc", "ct_chunks", "aad"}
        or hpke["kid"] != derive_key_id(public)
        or hpke["kid"] != expected_binding.get("recipient_key_id")
        or hpke["aad"] != record_digest("clearproof/pilot-envelope-binding/v1", expected_binding)
    ):
        raise ValueError("Envelope recipient or associated data mismatch")
    chunks = hpke["ct_chunks"]
    if (
        type(chunks) is not list
        or not 1 <= len(chunks) <= 22
        or any(type(chunk) is not str or not 1 <= len(chunk) <= 2048 for chunk in chunks)
        or any(len(chunk) != 2048 for chunk in chunks[:-1])
    ):
        raise ValueError("Invalid ciphertext chunks")
    return open_envelope({**{k: v for k, v in hpke.items() if k != "ct_chunks"}, "ct": "".join(chunks)}, private_key)
