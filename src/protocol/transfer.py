"""Canonical private transfer facts and explicit valuation for the local pilot.

Keep serialized transfers inside encrypted envelopes. Digests identify records;
this module does not prove issuance, holder authority, price truth or compliance.
"""

from __future__ import annotations

import re
from math import gcd
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.discovery_profile import parse_target

Hex32 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
Address = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{40}$", min_length=42, max_length=42)]
OpaqueId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$", min_length=1, max_length=64)]
UInt128 = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,38})$", min_length=1, max_length=39)]
Epoch = Annotated[int, Field(ge=0, le=2**53 - 1)]


class Record(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, hide_input_in_errors=True, revalidate_instances="always"
    )

    def __repr_args__(self):
        # Normal logging must not disclose transfer facts through model repr/str.
        return [("record_type", type(self).__name__)]

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json"))


def asset_chain(asset_id: str) -> int:
    match = re.fullmatch(r"eip155:([1-9][0-9]{0,19})/erc20:(0x[0-9a-f]{40})", asset_id)
    if not match or int(match[1]) > 2**64 - 1 or match[2] == "0x" + "0" * 40:
        raise ValueError("Expected a canonical EVM ERC-20 asset type")
    return int(match[1])


def uint128(value: str) -> str:
    if not re.fullmatch(r"0|[1-9][0-9]{0,38}", value) or int(value) >= 2**128:
        raise ValueError("Expected canonical unsigned 128-bit decimal string")
    return value


class AssetDefinition(Record):
    asset_id: str = Field(max_length=100)
    symbol: str = Field(pattern=r"^[A-Z0-9]{1,16}$", max_length=16)
    decimals: int = Field(ge=0, le=18)

    @field_validator("asset_id")
    @classmethod
    def check_asset(cls, value):
        asset_chain(value)
        return value


class AssetRegistry:
    """Immutable operator-supplied catalog; symbols never resolve identities."""

    def __init__(self, assets: list[AssetDefinition]):
        if not assets or len(assets) > 256 or len({a.asset_id for a in assets}) != len(assets):
            raise ValueError("Asset catalog must contain 1–256 unique asset identities")
        self._assets = MappingProxyType({a.asset_id: a for a in assets})
        self._digest = record_digest(
            "clearproof/asset-registry/v1",
            [a.model_dump(mode="json") for a in sorted(assets, key=lambda a: a.asset_id)],
        )

    @property
    def digest(self) -> str:
        return self._digest

    def get(self, asset_id: str) -> AssetDefinition:
        try:
            return self._assets[asset_id]
        except KeyError:
            raise ValueError("Unknown asset identity") from None

    @property
    def definitions(self) -> tuple[AssetDefinition, ...]:
        return tuple(self._assets[key] for key in sorted(self._assets))

    def parse_amount(self, asset_id: str, amount: str) -> str:
        asset = self.get(asset_id)
        if type(amount) is not str or len(amount) > 58 or not re.fullmatch(r"(0|[1-9][0-9]{0,38})(\.[0-9]+)?", amount):
            raise ValueError("Amount must be an unambiguous decimal string")
        whole, _, fraction = amount.partition(".")
        if len(fraction) > asset.decimals:
            raise ValueError("Amount exceeds asset precision")
        units = int(whole) * 10**asset.decimals + int(fraction.ljust(asset.decimals, "0") or "0")
        if units <= 0:
            raise ValueError("Transfer amount must be positive")
        return uint128(str(units))


class Participant(Record):
    wallet: Address
    kind: Literal["vasp", "self_hosted"]
    vasp_did: str | None

    @model_validator(mode="after")
    def identity(self):
        if self.kind == "vasp":
            if self.vasp_did is None or parse_target(self.vasp_did).did != self.vasp_did:
                raise ValueError("VASP participant requires a canonical did:web identity")
        elif self.vasp_did is not None:
            raise ValueError("Self-hosted participant cannot declare a VASP identity")
        if self.wallet == "0x" + "0" * 40:
            raise ValueError("Participant wallet cannot be zero")
        return self


class Valuation(Record):
    schema_version: Literal["clearproof-valuation-v1"]
    asset_id: str = Field(max_length=100)
    currency: Literal["USD"]
    # Rational USD cents per one base unit; never assume a stablecoin peg.
    numerator: UInt128
    denominator: UInt128
    observed_at: Epoch
    expires_at: Epoch
    source_id: OpaqueId
    source_evidence_digest: Hex32

    @model_validator(mode="after")
    def coherent(self):
        asset_chain(self.asset_id)
        if not int(uint128(self.numerator)) or not int(uint128(self.denominator)):
            raise ValueError("Valuation ratio must be positive")
        if gcd(int(self.numerator), int(self.denominator)) != 1:
            raise ValueError("Valuation ratio must be reduced")
        if self.expires_at <= self.observed_at:
            raise ValueError("Valuation expiry must follow observation")
        return self


class Transfer(Record):
    schema_version: Literal["clearproof-transfer-v1"]
    tenant_id: OpaqueId
    transfer_id: OpaqueId
    nonce: Hex32
    originator: Participant
    beneficiary: Participant
    asset_id: str = Field(max_length=100)
    asset_registry_digest: Hex32
    amount_base_units: UInt128
    valuation: Valuation
    usd_cents: UInt128
    jurisdiction: str = Field(pattern=r"^[A-Z]{2}$", min_length=2, max_length=2)
    policy_digest: Hex32
    created_at: Epoch
    expires_at: Epoch

    @model_validator(mode="after")
    def coherent(self):
        asset_chain(self.asset_id)
        amount = int(uint128(self.amount_base_units))
        cents = int(uint128(self.usd_cents))
        if amount <= 0 or cents <= 0:
            raise ValueError("Transfer and USD valuation must be positive")
        if self.valuation.asset_id != self.asset_id:
            raise ValueError("Valuation asset does not match transfer")
        if cents != amount * int(self.valuation.numerator) // int(self.valuation.denominator):
            raise ValueError("USD cents must equal the explicitly rounded rational valuation")
        if not self.valuation.observed_at <= self.created_at < self.expires_at <= self.valuation.expires_at:
            raise ValueError("Transfer validity must lie within valuation validity")
        return self

    @property
    def digest(self) -> str:
        return record_digest("clearproof/transfer/v1", self.model_dump(mode="json"))

    def validate_catalog(self, registry: AssetRegistry) -> None:
        registry.get(self.asset_id)
        if registry.digest != self.asset_registry_digest:
            raise ValueError("Asset registry digest mismatch")


def parse_transfer(data: dict, registry: AssetRegistry) -> Transfer:
    """Application entry point: schema checks plus trusted catalog membership."""
    transfer = Transfer.model_validate(data)
    transfer.validate_catalog(registry)
    return transfer


class VerificationContext(Record):
    """Expected values supplied by the verifier, never copied from an untrusted proof."""

    schema_version: Literal["clearproof-verification-context-v1"]
    tenant_id: OpaqueId
    transfer_digest: Hex32
    deployment_chain_id: UInt128
    deployment_address: Address
    policy_digest: Hex32
    artifact_manifest_digest: Hex32
    proof_profile: OpaqueId
    sanctions_snapshot_digest: Hex32
    issuer_snapshot_digest: Hex32
    issuance_snapshot_digest: Hex32
    revocation_snapshot_digest: Hex32
    evaluated_at: Epoch
    max_transfer_age_seconds: int = Field(ge=0, le=86400)

    @model_validator(mode="after")
    def deployment(self):
        if not 0 < int(uint128(self.deployment_chain_id)) <= 2**64 - 1:
            raise ValueError("Invalid deployment chain ID")
        if self.deployment_address == "0x" + "0" * 40:
            raise ValueError("Deployment address cannot be zero")
        return self

    def check_transfer(self, transfer: Transfer) -> None:
        if self.tenant_id != transfer.tenant_id or self.transfer_digest != transfer.digest:
            raise ValueError("Verification context does not identify this tenant and transfer")
        if self.policy_digest != transfer.policy_digest:
            raise ValueError("Verification policy mismatch")
        if int(self.deployment_chain_id) != asset_chain(transfer.asset_id):
            raise ValueError("Verification deployment chain differs from transfer asset chain")
        if not transfer.created_at <= self.evaluated_at < transfer.expires_at:
            raise ValueError("Transfer is future-dated or expired")
        if self.evaluated_at - transfer.created_at > self.max_transfer_age_seconds:
            raise ValueError("Transfer exceeds verifier freshness limit")

    @property
    def digest(self) -> str:
        return record_digest("clearproof/verification-context/v1", self.model_dump(mode="json"))


class EvidenceReceipt(Record):
    """Minimized result references. A digest alone is not an attestation signature."""

    schema_version: Literal["clearproof-evidence-receipt-v1"]
    receipt_id: OpaqueId
    tenant_id: OpaqueId
    transfer_digest: Hex32
    verification_context_digest: Hex32
    encrypted_envelope_digest: Hex32
    proof_digest: Hex32 | None
    cryptographic_result: Literal["valid", "invalid", "unavailable", "not_evaluated"]
    policy_result: Literal["allow", "review", "deny", "indeterminate"]
    exchange_result: Literal["not_sent", "sent", "accepted", "rejected", "unknown"]
    settlement_result: Literal["not_observed", "pending", "confirmed", "failed", "unknown"]
    authorization_result: Literal["not_requested", "not_consumed", "consumed", "rejected"]
    observed_at: Epoch

    @model_validator(mode="after")
    def proof_reference(self):
        if self.cryptographic_result in ("valid", "invalid") and self.proof_digest is None:
            raise ValueError("Evaluated proof requires its digest")
        if self.authorization_result == "consumed" and (
            self.cryptographic_result != "valid" or self.policy_result != "allow"
        ):
            raise ValueError("Consumed authorization requires valid proof and allow policy result")
        return self

    @property
    def digest(self) -> str:
        return record_digest("clearproof/evidence-receipt/v1", self.model_dump(mode="json"))
