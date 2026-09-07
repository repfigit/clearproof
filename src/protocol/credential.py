"""Versioned credential preimage; issuance/holder enrollment must be authenticated separately."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from src.protocol.discovery_profile import parse_target
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record
from src.registry.poseidon import BN254_SCALAR_FIELD, poseidon_hash

Scalar = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,76})$", min_length=1, max_length=77)]


def scalar(value: str, *, nonzero: bool = False) -> int:
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        raise ValueError("Expected canonical scalar")
    if len(value) > 77 or (len(value) > 1 and value[0] == "0"):
        raise ValueError("Expected canonical scalar")
    number = int(value)
    if not int(nonzero) <= number < BN254_SCALAR_FIELD:
        raise ValueError("Scalar is outside the permitted field range")
    return number


def digest_limbs(value: str) -> tuple[int, int]:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")


def holder_commitment(secret: str) -> str:
    return str(poseidon_hash([101, scalar(secret, nonzero=True)]))


class PilotCredential(Record):
    schema_version: Literal["clearproof-credential-v1"] = "clearproof-credential-v1"
    tenant_id: OpaqueId
    credential_nonce: Hex32
    issuer_did: str = Field(max_length=512)
    subject_wallet: Address
    holder_commitment: Scalar
    jurisdiction: str = Field(pattern=r"^[A-Z]{2}$", min_length=2, max_length=2)
    kyc_tier: int = Field(ge=1, le=3)
    sanctions_clear: bool
    issued_at: Epoch
    expires_at: Epoch

    @field_validator("issuer_did")
    @classmethod
    def issuer_identity(cls, value):
        if parse_target(value).did != value:
            raise ValueError("Issuer requires canonical did:web identity")
        return value

    @field_validator("holder_commitment")
    @classmethod
    def holder_field(cls, value):
        scalar(value, nonzero=True)
        return value

    @model_validator(mode="after")
    def valid_interval(self):
        if self.expires_at <= self.issued_at or self.subject_wallet == "0x" + "0" * 40:
            raise ValueError("Credential requires a nonzero subject and positive validity interval")
        if self.credential_nonce == "0" * 64:
            raise ValueError("Credential nonce must be nonzero")
        return self

    def fields(self) -> list[int]:
        nonce = bytes.fromhex(self.credential_nonce)
        return [
            102,
            *digest_limbs(self.issuer_did),
            *digest_limbs(self.tenant_id),
            int.from_bytes(nonce[:16], "big"),
            int.from_bytes(nonce[16:], "big"),
            int(self.subject_wallet, 16),
            scalar(self.holder_commitment),
            int.from_bytes(self.jurisdiction.encode("ascii"), "big"),
            self.kyc_tier,
            self.issued_at,
            self.expires_at,
            int(self.sanctions_clear),
        ]

    @property
    def commitment(self) -> str:
        return str(poseidon_hash(self.fields()))

    def authorized_issuer_leaf(self, issuance_root: str) -> str:
        return str(poseidon_hash([103, *digest_limbs(self.issuer_did), scalar(issuance_root)]))

    def witness(
        self,
        *,
        secret: str,
        evaluated_at: int,
        issuance_root: str,
        authorized_issuer_root: str,
        issuance_siblings: list[str],
        issuance_indices: list[int],
        issuer_siblings: list[str],
        issuer_indices: list[int],
    ) -> dict:
        """Encode the subcircuit inputs; caller must authenticate the roots.

        This contains private data and must never be logged or persisted in clear.
        The composed verifier supplies expected tenant/subject/jurisdiction from
        its independently validated transfer context.
        """
        PilotCredential.model_validate(self)
        if type(evaluated_at) is not int or not self.issued_at <= evaluated_at < self.expires_at:
            raise ValueError("Credential is outside its validity interval")
        if not self.sanctions_clear or holder_commitment(secret) != self.holder_commitment:
            raise ValueError("Credential screening or holder binding failed")
        scalar(issuance_root)
        scalar(authorized_issuer_root)
        for siblings, indices in ((issuance_siblings, issuance_indices), (issuer_siblings, issuer_indices)):
            if type(siblings) is not list or type(indices) is not list or not 1 <= len(siblings) <= 32:
                raise ValueError("Invalid membership path")
            if len(siblings) != len(indices) or any(type(i) is not int or i not in (0, 1) for i in indices):
                raise ValueError("Invalid membership direction")
            for sibling in siblings:
                scalar(sibling)
        return {
            "fields": [str(x) for x in self.fields()[1:]],
            "holder_secret": secret,
            "credential_commitment": self.commitment,
            "issuance_root": issuance_root,
            "authorized_issuer_root": authorized_issuer_root,
            "issuance_siblings": list(issuance_siblings),
            "issuance_indices": list(issuance_indices),
            "issuer_siblings": list(issuer_siblings),
            "issuer_indices": list(issuer_indices),
            "expected_tenant": [str(x) for x in digest_limbs(self.tenant_id)],
            "expected_subject": str(int(self.subject_wallet, 16)),
            "expected_jurisdiction": str(int.from_bytes(self.jurisdiction.encode("ascii"), "big")),
            "evaluated_at": str(evaluated_at),
        }
