"""Scoped signatures for local decisions, distinct from trusted timestamp evidence."""

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record, VerificationContext


class DecisionTrustError(ValueError):
    pass


class DecisionSignatureError(ValueError):
    pass


class DecisionAttestation(Record):
    schema_version: Literal["clearproof-decision-attestation-v1"] = "clearproof-decision-attestation-v1"
    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    receipt_digest: Hex32
    evidence_digest: Hex32
    context_digest: Hex32
    decision_at: Epoch
    clock: Literal["operator-clock-only"] = "operator-clock-only"
    key_id: Hex32

    def signing_bytes(self):
        return b"clearproof/decision-attestation/v1\0" + self.canonical_bytes()


class SignedDecision(Record):
    statement: DecisionAttestation
    signature: str = Field(pattern=r"^[0-9a-f]{128}$", min_length=128, max_length=128)


class DecisionAuthority(Record):
    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    public_key: Hex32
    not_before: Epoch
    not_after: Epoch
    compromised_at: Epoch | None = None

    @model_validator(mode="after")
    def interval(self):
        if self.not_before >= self.not_after:
            raise ValueError("Invalid decision authority interval")
        return self

    @property
    def key_id(self):
        return hashlib.sha256(b"clearproof/decision-key/v1\0" + bytes.fromhex(self.public_key)).hexdigest()


class DecisionTrustStore:
    def __init__(self, authorities: list[DecisionAuthority]):
        values = tuple(DecisionAuthority.model_validate(a) for a in authorities)
        if not 1 <= len(values) <= 256 or len({a.key_id for a in values}) != len(values):
            raise ValueError("Expected distinct independently approved decision keys")
        self._keys = MappingProxyType({a.key_id: a for a in values})

    def verify(self, signed: SignedDecision, receipt: dict, context: VerificationContext, *, verified_at: int) -> None:
        signed = SignedDecision.model_validate(signed)
        statement = signed.statement
        authority = self._keys.get(statement.key_id)
        if (
            type(verified_at) is not int
            or not statement.decision_at <= verified_at < 2**53
            or authority is None
            or (authority.tenant_id, authority.chain_id, authority.registry_address)
            != (statement.tenant_id, statement.chain_id, statement.registry_address)
            or not authority.not_before <= statement.decision_at < authority.not_after
            or (authority.compromised_at is not None and authority.compromised_at <= verified_at)
        ):
            raise DecisionTrustError("Decision signer is not trusted for this historical claim")
        if (
            receipt.get("schema_version") != "clearproof-local-authorization-v1"
            or receipt.get("outcome") != "ALLOW"
            or statement.tenant_id != receipt["tenant_id"]
            or statement.tenant_id != context.tenant_id
            or statement.chain_id != int(context.deployment_chain_id)
            or statement.registry_address != context.deployment_address
            or statement.context_digest != context.digest
            or statement.context_digest != receipt["context_digest"]
            or statement.receipt_digest != record_digest("clearproof/local-authorization/v1", receipt)
            or statement.evidence_digest != receipt["evidence_id"]
            or statement.decision_at != receipt["authorized_at"]
        ):
            raise DecisionSignatureError("Decision attestation does not bind the receipt")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(authority.public_key)).verify(
                bytes.fromhex(signed.signature), statement.signing_bytes()
            )
        except InvalidSignature:
            raise DecisionSignatureError("Invalid decision signature") from None


@dataclass(frozen=True, repr=False)
class DecisionSigner:
    authority: DecisionAuthority
    key: Ed25519PrivateKey

    def sign(self, receipt: dict, context: VerificationContext) -> SignedDecision:
        authority = DecisionAuthority.model_validate(self.authority)
        if self.key.public_key().public_bytes_raw().hex() != authority.public_key:
            raise DecisionTrustError("Decision signing key mismatch")
        statement = DecisionAttestation(
            tenant_id=receipt["tenant_id"],
            chain_id=int(context.deployment_chain_id),
            registry_address=context.deployment_address,
            receipt_digest=record_digest("clearproof/local-authorization/v1", receipt),
            evidence_digest=receipt["evidence_id"],
            context_digest=context.digest,
            decision_at=receipt["authorized_at"],
            key_id=authority.key_id,
        )
        signed = SignedDecision(statement=statement, signature=self.key.sign(statement.signing_bytes()).hex())
        DecisionTrustStore([authority]).verify(signed, receipt, context, verified_at=receipt["authorized_at"])
        return signed
