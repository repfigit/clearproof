"""Purpose-separated approval of exact private transfer information bytes."""

import hashlib
from types import MappingProxyType
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record, Transfer, VerificationContext


def information_key_id(public: bytes) -> str:
    return hashlib.sha256(b"clearproof/information-key/v1\0" + public).hexdigest()


class InformationApproval(Record):
    schema_version: Literal["clearproof-information-approval-v1"] = "clearproof-information-approval-v1"
    information_schema: Literal["clearproof-transfer-information-v1"] = "clearproof-transfer-information-v1"
    tenant_id: OpaqueId
    transfer_digest: Hex32
    context_digest: Hex32
    credential_id: Hex32
    payload_digest: Hex32
    source_id: OpaqueId
    source_evidence_digest: Hex32
    signed_at: Epoch
    expires_at: Epoch
    key_id: Hex32

    @model_validator(mode="after")
    def interval(self):
        if self.signed_at >= self.expires_at:
            raise ValueError("Invalid information approval interval")
        return self

    def signing_bytes(self):
        return b"clearproof/information-approval/v1\0" + self.canonical_bytes()


class SignedInformationApproval(Record):
    approval: InformationApproval
    signature: str = Field(pattern=r"^[0-9a-f]{128}$", min_length=128, max_length=128)


class InformationAuthority(Record):
    public_key: Hex32
    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    source_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=16)
    not_before: Epoch
    not_after: Epoch
    max_lifetime_seconds: int = Field(ge=1, le=86400)

    @model_validator(mode="after")
    def scope(self):
        if self.not_before >= self.not_after or len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("Invalid information authority scope")
        return self

    @property
    def key_id(self):
        return information_key_id(bytes.fromhex(self.public_key))


class InformationTrustStore:
    def __init__(self, authorities: list[InformationAuthority]):
        values = tuple(InformationAuthority.model_validate(a) for a in authorities)
        if not 1 <= len(values) <= 256 or len({a.key_id for a in values}) != len(values):
            raise ValueError("Expected distinct independently approved information keys")
        self._keys = MappingProxyType({a.key_id: a for a in values})

    def verify(
        self,
        signed: SignedInformationApproval,
        payload: bytes,
        transfer: Transfer,
        context: VerificationContext,
        *,
        credential_id: str,
        now: int,
    ) -> None:
        signed = SignedInformationApproval.model_validate(signed)
        approval = signed.approval
        context.check_transfer(transfer)
        authority = self._keys.get(approval.key_id)
        if (
            type(payload) is not bytes
            or not 1 <= len(payload) <= 32768
            or type(now) is not int
            or not context.evaluated_at <= now < transfer.expires_at
            or approval.tenant_id != transfer.tenant_id
            or approval.transfer_digest != transfer.digest
            or approval.context_digest != context.digest
            or approval.credential_id != credential_id
            or approval.payload_digest != hashlib.sha256(payload).hexdigest()
            or not transfer.created_at <= approval.signed_at <= now < approval.expires_at <= transfer.expires_at
            or authority is None
            or authority.tenant_id != transfer.tenant_id
            or authority.chain_id != int(context.deployment_chain_id)
            or authority.registry_address != context.deployment_address
            or approval.source_id not in authority.source_ids
            or not authority.not_before <= approval.signed_at < approval.expires_at <= authority.not_after
            or approval.expires_at - approval.signed_at > authority.max_lifetime_seconds
        ):
            raise ValueError("Information approval is outside current payload authority")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(authority.public_key)).verify(
                bytes.fromhex(signed.signature), approval.signing_bytes()
            )
        except InvalidSignature:
            raise ValueError("Information approval signature is invalid") from None


def sign_information(approval: InformationApproval, key: Ed25519PrivateKey) -> SignedInformationApproval:
    """Authority utility: source review must occur before signing, outside this helper."""
    approval = InformationApproval.model_validate(approval)
    if information_key_id(key.public_key().public_bytes_raw()) != approval.key_id:
        raise ValueError("Information signing key mismatch")
    return SignedInformationApproval(approval=approval, signature=key.sign(approval.signing_bytes()).hex())
