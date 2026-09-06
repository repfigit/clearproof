"""Scoped attestations for external business facts, separate from proof-derived facts."""

import hashlib
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from src.policy.evaluator import PolicyFact, PolicyFacts
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record, Transfer, VerificationContext

EXTERNAL_FACTS = frozenset(
    (
        "applicability_resolved",
        "counterparty_trusted",
        "required_information_complete",
        "counterparty_acknowledged",
    )
)


class FactTrustError(ValueError):
    """Fact attestation authenticity, scope, freshness or conflict failed."""


def fact_key_id(public_key: bytes) -> str:
    return hashlib.sha256(b"clearproof/fact-key/v1\0" + public_key).hexdigest()


class FactApproval(Record):
    schema_version: Literal["clearproof-fact-approval-v1"] = "clearproof-fact-approval-v1"
    tenant_id: OpaqueId
    transfer_digest: Hex32
    context_digest: Hex32
    source_id: OpaqueId
    fact: PolicyFact
    signed_at: Epoch
    key_id: Hex32

    @model_validator(mode="after")
    def coherent(self):
        if self.fact.predicate not in EXTERNAL_FACTS:
            raise ValueError("Attestors cannot supply proof-derived predicates")
        if not self.fact.observed_at <= self.signed_at < self.fact.expires_at:
            raise ValueError("Attestation must be signed within fact validity")
        return self

    def signing_bytes(self):
        return b"clearproof/fact-approval/v1\0" + self.canonical_bytes()


class SignedFactApproval(Record):
    approval: FactApproval
    signature: str = Field(pattern=r"^[0-9a-f]{128}$", min_length=128, max_length=128)


class FactAuthority(Record):
    public_key: Hex32
    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    source_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=16)
    predicates: tuple[OpaqueId, ...] = Field(min_length=1, max_length=4)
    not_before: Epoch
    not_after: Epoch
    max_lifetime_seconds: int = Field(ge=1, le=86400)
    max_observation_age_seconds: int = Field(ge=1, le=86400)

    @model_validator(mode="after")
    def coherent(self):
        if (
            self.not_before >= self.not_after
            or int(self.registry_address, 16) == 0
            or len(set(self.source_ids)) != len(self.source_ids)
            or len(set(self.predicates)) != len(self.predicates)
            or not set(self.predicates) <= EXTERNAL_FACTS
        ):
            raise ValueError("Invalid fact authority scope")
        return self

    @property
    def key_id(self):
        return fact_key_id(bytes.fromhex(self.public_key))


def sign_fact(approval: FactApproval, key: Ed25519PrivateKey) -> SignedFactApproval:
    approval = FactApproval.model_validate(approval)
    if approval.key_id != fact_key_id(key.public_key().public_bytes_raw()):
        raise FactTrustError("Fact signing key mismatch")
    return SignedFactApproval(approval=approval, signature=key.sign(approval.signing_bytes()).hex())


class FactTrustStore:
    def __init__(self, authorities: list[FactAuthority]):
        if type(authorities) is not list or not 1 <= len(authorities) <= 256:
            raise ValueError("Configure 1–256 fact authorities")
        self._authorities = tuple(FactAuthority.model_validate(a) for a in authorities)

    def verify_for_context(
        self,
        approvals: tuple[SignedFactApproval, ...],
        *,
        transfer: Transfer,
        context: VerificationContext,
        tenant_id: str,
        now: int,
    ) -> PolicyFacts:
        """Authenticate evidence; missing/false facts remain missing/false, never ALLOW.

        Keys, scopes and clock are independent operator configuration. A signature
        authenticates the attestor's claim, not its truth or legal sufficiency.
        """
        transfer, context = Transfer.model_validate(transfer), VerificationContext.model_validate(context)
        context.check_transfer(transfer)
        if type(approvals) is not tuple or len(approvals) > 64:
            raise FactTrustError("Fact approval count exceeded")
        if type(now) is not int or not context.evaluated_at <= now < transfer.expires_at:
            raise FactTrustError("Invalid current fact verification time")
        if tenant_id != transfer.tenant_id:
            raise FactTrustError("Fact verification tenant mismatch")
        unique = {}
        for value in approvals:
            signed = SignedFactApproval.model_validate(value)
            approval, fact = signed.approval, signed.approval.fact
            if (approval.tenant_id, approval.transfer_digest, approval.context_digest) != (
                tenant_id,
                transfer.digest,
                context.digest,
            ) or not approval.signed_at <= now < fact.expires_at:
                raise FactTrustError("Fact approval context or time mismatch")
            matching = [
                a
                for a in self._authorities
                if (
                    a.key_id == approval.key_id
                    and a.tenant_id == tenant_id
                    and str(a.chain_id) == context.deployment_chain_id
                    and a.registry_address == context.deployment_address
                    and approval.source_id in a.source_ids
                    and fact.predicate in a.predicates
                    and a.not_before <= fact.observed_at <= approval.signed_at < fact.expires_at <= a.not_after
                    and fact.expires_at - fact.observed_at <= a.max_lifetime_seconds
                    and now - fact.observed_at <= a.max_observation_age_seconds
                )
            ]
            if not matching:
                raise FactTrustError("Fact has no trusted authority in scope")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(matching[0].public_key)).verify(
                    bytes.fromhex(signed.signature), approval.signing_bytes()
                )
            except InvalidSignature:
                raise FactTrustError("Fact signature is invalid") from None
            prior = unique.get(fact.predicate)
            if prior is not None and prior != signed:
                raise FactTrustError("Conflicting attestations for one predicate")
            unique[fact.predicate] = signed
        return PolicyFacts(
            tenant_id=tenant_id,
            transfer_digest=transfer.digest,
            facts=tuple(unique[p].approval.fact for p in sorted(unique)),
        )
