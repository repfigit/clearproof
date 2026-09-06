"""Registrar-signed root approvals; trust anchors are operator configuration."""

from __future__ import annotations

import hashlib
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, field_validator, model_validator

from src.protocol.canonical import record_digest
from src.protocol.credential import Scalar, scalar
from src.protocol.discovery_profile import parse_target
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record

RootKind = Literal["issuance-root", "issuer-root", "sanctions-root"]


class RootTrustError(ValueError):
    """Snapshot signature, trust scope, freshness or current-head binding failed."""


def root_key_id(public_key: bytes) -> str:
    return hashlib.sha256(b"clearproof/root-key/v1\0" + public_key).hexdigest()


class RootSnapshot(Record):
    schema_version: Literal["clearproof-root-snapshot-v1"] = "clearproof-root-snapshot-v1"
    proof_profile: Literal["clearproof-credential-v1"] = "clearproof-credential-v1"
    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    kind: RootKind
    issuer_did: str | None = Field(default=None, max_length=512)
    root: Scalar
    tree_depth: int = Field(ge=1, le=32)
    source_digest: Hex32
    revision: int = Field(ge=1, le=2**53 - 1)
    previous_digest: Hex32 | None = None
    issued_at: Epoch
    expires_at: Epoch
    key_id: Hex32

    @field_validator("root")
    @classmethod
    def root_field(cls, value):
        scalar(value)
        return value

    @model_validator(mode="after")
    def scope_and_validity(self):
        if self.registry_address == "0x" + "0" * 40:
            raise ValueError("Root audience must be nonzero")
        if not self.issued_at < self.expires_at <= self.issued_at + 86400:
            raise ValueError("Root approval requires a validity interval of at most one day")
        if (self.revision == 1) != (self.previous_digest is None):
            raise ValueError("Root revision requires the preceding snapshot digest")
        if self.kind == "issuance-root":
            if self.issuer_did is None or parse_target(self.issuer_did).did != self.issuer_did:
                raise ValueError("Issuance root requires canonical issuer identity")
        elif self.issuer_did is not None:
            raise ValueError("Only issuance roots carry an issuer identity")
        return self

    @property
    def digest(self) -> str:
        return record_digest("clearproof/root-snapshot/v1", self.model_dump(mode="json"))

    def signing_bytes(self) -> bytes:
        return b"clearproof/root-approval/v1\0" + self.canonical_bytes()


class SignedRootSnapshot(Record):
    snapshot: RootSnapshot
    signature: str = Field(pattern=r"^[0-9a-f]{128}$", min_length=128, max_length=128)


class RootAuthority(Record):
    """Pinned verification key and scope, supplied outside untrusted evidence."""

    public_key: Hex32
    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    kinds: tuple[RootKind, ...] = Field(min_length=1, max_length=3)
    issuer_dids: tuple[str, ...] = Field(default=(), max_length=256)
    not_before: Epoch
    not_after: Epoch
    compromised_at: Epoch | None = None

    @model_validator(mode="after")
    def scope(self):
        if self.not_after <= self.not_before or len(set(self.kinds)) != len(self.kinds):
            raise ValueError("Invalid root authority interval or duplicate scope")
        if len(set(self.issuer_dids)) != len(self.issuer_dids):
            raise ValueError("Duplicate issuer scope")
        for issuer in self.issuer_dids:
            if parse_target(issuer).did != issuer:
                raise ValueError("Noncanonical issuer scope")
        return self

    @property
    def key_id(self) -> str:
        return root_key_id(bytes.fromhex(self.public_key))


class RootTrustStore:
    def __init__(self, authorities: list[RootAuthority]):
        if not authorities or len(authorities) > 256:
            raise ValueError("Configure 1–256 root authorities")
        self._authorities = tuple(RootAuthority.model_validate(a) for a in authorities)

    def verify_historical(
        self, signed: SignedRootSnapshot, *, evaluated_at: int, verified_at: int | None = None
    ) -> RootSnapshot:
        """Authenticate approval at a given time; does NOT prove it was the current head."""
        signed = SignedRootSnapshot.model_validate(signed)
        snapshot = signed.snapshot
        review_at = evaluated_at if verified_at is None else verified_at
        if type(review_at) is not int or type(evaluated_at) is not int or not 0 <= evaluated_at <= review_at < 2**53:
            raise RootTrustError("Invalid root review time")
        if any(
            a.key_id == snapshot.key_id and a.compromised_at is not None and a.compromised_at <= review_at
            for a in self._authorities
        ):
            raise RootTrustError("Root authority compromise is unresolved")
        if type(evaluated_at) is not int or not snapshot.issued_at <= evaluated_at < snapshot.expires_at:
            raise RootTrustError("Root approval is outside its validity interval")
        for authority in self._authorities:
            if (
                authority.key_id != snapshot.key_id
                or authority.tenant_id != snapshot.tenant_id
                or authority.chain_id != snapshot.chain_id
                or authority.registry_address != snapshot.registry_address
                or snapshot.kind not in authority.kinds
            ):
                continue
            if snapshot.kind == "issuance-root" and snapshot.issuer_did not in authority.issuer_dids:
                continue
            if not authority.not_before <= snapshot.issued_at < snapshot.expires_at <= authority.not_after:
                continue
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(authority.public_key)).verify(
                    bytes.fromhex(signed.signature), snapshot.signing_bytes()
                )
            except InvalidSignature as exc:
                raise RootTrustError("Root approval signature is invalid") from exc
            return snapshot
        raise RootTrustError("Root approval has no trusted authority in scope")

    def verify_current(
        self,
        signed: SignedRootSnapshot,
        *,
        now: int,
        expected_digest: str,
        tenant_id: str,
        chain_id: int,
        registry_address: str,
        kind: RootKind,
    ) -> RootSnapshot:
        """Expected head digest must come from an independently trusted current source."""
        snapshot = self.verify_historical(signed, evaluated_at=now)
        if (
            snapshot.digest != expected_digest
            or snapshot.tenant_id != tenant_id
            or snapshot.chain_id != chain_id
            or snapshot.registry_address != registry_address
            or snapshot.kind != kind
        ):
            raise RootTrustError("Root approval does not match the trusted current context")
        return snapshot


def sign_root(snapshot: RootSnapshot, private_key: Ed25519PrivateKey) -> SignedRootSnapshot:
    """Registrar utility. Call only after checking source evidence and authorization."""
    snapshot = RootSnapshot.model_validate(snapshot)
    if root_key_id(private_key.public_key().public_bytes_raw()) != snapshot.key_id:
        raise RootTrustError("Signing key does not match the snapshot")
    return SignedRootSnapshot(snapshot=snapshot, signature=private_key.sign(snapshot.signing_bytes()).hex())


def root_scope_id(snapshot: RootSnapshot) -> str:
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
