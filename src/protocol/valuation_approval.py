"""Scoped signatures over exact valuation inputs; pricing truth remains an authority assumption."""

from __future__ import annotations

import hashlib
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.transfer import AssetRegistry, Epoch, Hex32, OpaqueId, Record, Transfer, Valuation, asset_chain


class ValuationTrustError(ValueError):
    """Generic trust failure, without quote/customer details."""


def valuation_key_id(public_key: bytes) -> str:
    return hashlib.sha256(b"clearproof/valuation-key/v1\0" + public_key).hexdigest()


class ValuationApproval(Record):
    schema_version: Literal["clearproof-valuation-approval-v1"] = "clearproof-valuation-approval-v1"
    tenant_id: OpaqueId
    asset_registry_digest: Hex32
    valuation: Valuation
    signed_at: Epoch
    key_id: Hex32

    @model_validator(mode="after")
    def observation_before_signature(self):
        if not self.valuation.observed_at <= self.signed_at < self.valuation.expires_at:
            raise ValueError("Approval must be signed during the quote validity interval")
        return self

    def signing_bytes(self) -> bytes:
        return b"clearproof/valuation-approval/v1\0" + self.canonical_bytes()

    @property
    def digest(self) -> str:
        return record_digest("clearproof/valuation-approval/v1", self.model_dump(mode="json"))


class SignedValuationApproval(Record):
    approval: ValuationApproval
    signature: str = Field(pattern=r"^[0-9a-f]{128}$", min_length=128, max_length=128)


class ValuationAuthority(Record):
    """Operator-configured source, catalog, asset and tenant scope for one key."""

    public_key: Hex32
    tenant_id: OpaqueId
    asset_registry_digest: Hex32
    asset_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    source_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=16)
    not_before: Epoch
    not_after: Epoch
    compromised_at: Epoch | None = None
    max_quote_lifetime_seconds: int = Field(ge=1, le=86400)
    max_observation_age_seconds: int = Field(ge=1, le=86400)

    @model_validator(mode="after")
    def valid_scope(self):
        if self.not_after <= self.not_before:
            raise ValueError("Authority requires a positive validity interval")
        if len(set(self.asset_ids)) != len(self.asset_ids) or len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("Duplicate authority scope")
        for value in self.asset_ids:
            asset_chain(value)
        return self

    @property
    def key_id(self) -> str:
        return valuation_key_id(bytes.fromhex(self.public_key))


class ValuationTrustStore:
    def __init__(self, authorities: list[ValuationAuthority]):
        if type(authorities) is not list or not 1 <= len(authorities) <= 256:
            raise ValueError("Configure 1–256 valuation authorities")
        self._authorities = tuple(ValuationAuthority.model_validate(a) for a in authorities)

    def verify_for_transfer(
        self,
        signed: SignedValuationApproval,
        transfer: Transfer,
        registry: AssetRegistry,
        *,
        tenant_id: str,
        now: int,
        verified_at: int | None = None,
    ) -> ValuationApproval:
        return self._verify_with_validity(
            signed, transfer, registry, tenant_id=tenant_id, now=now, verified_at=verified_at
        )[0]

    def current_valid_until(self, signed, transfer, registry, *, tenant_id: str, now: int) -> int:
        """Exclusive scheduled cutoff after authentication; trust changes still require revalidation."""
        return self._verify_with_validity(signed, transfer, registry, tenant_id=tenant_id, now=now)[1]

    def _verify_with_validity(
        self,
        signed: SignedValuationApproval,
        transfer: Transfer,
        registry: AssetRegistry,
        *,
        tenant_id: str,
        now: int,
        verified_at: int | None = None,
    ) -> tuple[ValuationApproval, int]:
        """Use the authenticated tenant and an operator clock, not request-supplied values.

        No latest-quote claim, provider fetch, policy approval or key-revocation
        lookup occurs here. Key removal/rotation is operator trust configuration.
        """
        signed = SignedValuationApproval.model_validate(signed)
        transfer = Transfer.model_validate(transfer)
        approval, quote = signed.approval, signed.approval.valuation
        review_at = now if verified_at is None else verified_at
        if type(review_at) is not int or type(now) is not int or not 0 <= now <= review_at < 2**53:
            raise ValuationTrustError("Invalid valuation review time")
        if any(
            a.key_id == approval.key_id and a.compromised_at is not None and a.compromised_at <= review_at
            for a in self._authorities
        ):
            raise ValuationTrustError("Valuation authority compromise is unresolved")
        if type(now) is not int or not approval.signed_at <= now < quote.expires_at:
            raise ValuationTrustError("Valuation approval is outside its validity interval")
        transfer.validate_catalog(registry)
        if (
            approval.tenant_id != tenant_id
            or transfer.tenant_id != tenant_id
            or approval.asset_registry_digest != registry.digest
            or quote != transfer.valuation
        ):
            raise ValuationTrustError("Valuation approval does not bind the expected transfer")
        for authority in self._authorities:
            if (
                authority.key_id != approval.key_id
                or authority.tenant_id != tenant_id
                or authority.asset_registry_digest != registry.digest
                or quote.asset_id not in authority.asset_ids
                or quote.source_id not in authority.source_ids
                or not authority.not_before
                <= quote.observed_at
                <= approval.signed_at
                < quote.expires_at
                <= authority.not_after
                or quote.expires_at - quote.observed_at > authority.max_quote_lifetime_seconds
                or now - quote.observed_at > authority.max_observation_age_seconds
            ):
                continue
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(authority.public_key)).verify(
                    bytes.fromhex(signed.signature), approval.signing_bytes()
                )
            except InvalidSignature:
                raise ValuationTrustError("Valuation approval signature is invalid") from None
            return approval, min(
                quote.expires_at,
                quote.observed_at + authority.max_observation_age_seconds + 1,
                *(
                    a.compromised_at
                    for a in self._authorities
                    if a.key_id == approval.key_id and a.compromised_at is not None
                ),
            )
        raise ValuationTrustError("Valuation approval has no trusted authority in scope")


def sign_valuation(approval: ValuationApproval, private_key: Ed25519PrivateKey) -> SignedValuationApproval:
    """Authority utility; the signer must validate its source evidence before calling."""
    approval = ValuationApproval.model_validate(approval)
    if valuation_key_id(private_key.public_key().public_bytes_raw()) != approval.key_id:
        raise ValuationTrustError("Signing key does not match approval")
    return SignedValuationApproval(approval=approval, signature=private_key.sign(approval.signing_bytes()).hex())
