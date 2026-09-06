"""Immutable policy inputs selected by independently configured current pins.

These thresholds define private amount tiers, not legal applicability or a
complete allow/deny policy. Source references require independent review.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.transfer import (
    Address,
    Epoch,
    Hex32,
    OpaqueId,
    Record,
    Transfer,
    UInt128,
    VerificationContext,
    uint128,
)


class PolicyTrustError(ValueError):
    """Policy selection/freshness failed without exposing transfer facts."""


class PolicySource(Record):
    source_id: OpaqueId
    kind: Literal["synthetic", "reviewed-reference"]
    reference: str = Field(min_length=1, max_length=1024)
    evidence_digest: Hex32
    reviewed_at: Epoch
    valid_until: Epoch

    @model_validator(mode="after")
    def valid_reference(self):
        if not self.reviewed_at < self.valid_until or not self.reference.isascii():
            raise ValueError("Source requires a valid review interval and ASCII reference")
        if self.kind == "synthetic":
            if not self.reference.startswith("urn:clearproof:synthetic:"):
                raise ValueError("Synthetic source requires an explicit synthetic reference")
        else:
            parts = urlsplit(self.reference)
            if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
                raise ValueError("Reviewed source requires a credential-free HTTPS reference")
        return self


class PolicyRule(Record):
    rule_id: OpaqueId
    predicate: OpaqueId
    operator: Literal["is_true", "is_false", "at_least", "below"]
    threshold_usd_cents: UInt128 | None = None
    effect: Literal["ALLOW", "REVIEW", "DENY"]
    source_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def coherent_rule(self):
        numeric = self.operator in ("at_least", "below")
        if numeric != (self.threshold_usd_cents is not None):
            raise ValueError("Only amount comparisons require a threshold")
        if numeric:
            if self.predicate != "usd_cents" or int(uint128(self.threshold_usd_cents)) <= 0:
                raise ValueError("Amount rules require positive USD cents")
        elif self.predicate == "usd_cents":
            raise ValueError("Amount requires an integer comparison")
        if len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("Rule source IDs must be distinct")
        return self


class PilotPolicy(Record):
    schema_version: Literal["clearproof-pilot-policy-v1"] = "clearproof-pilot-policy-v1"
    policy_id: OpaqueId
    revision: int = Field(ge=1, le=2**53 - 1)
    previous_digest: Hex32 | None = None
    tenant_id: OpaqueId
    chain_id: UInt128
    registry_address: Address
    jurisdiction: str = Field(pattern=r"^[A-Z]{2}$", min_length=2, max_length=2)
    asset_registry_digest: Hex32
    effective_from: Epoch
    effective_until: Epoch
    # USD cents, exact unsigned integers, for the private tier predicate only.
    tier_thresholds_usd_cents: tuple[UInt128, UInt128, UInt128]
    sources: tuple[PolicySource, ...] = Field(min_length=1, max_length=16)
    rules: tuple[PolicyRule, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def coherent(self):
        if not 0 < int(uint128(self.chain_id)) < 2**64 or int(self.registry_address, 16) == 0:
            raise ValueError("Policy requires a nonzero EVM deployment")
        if not self.effective_from < self.effective_until:
            raise ValueError("Policy requires a positive effective interval")
        if (self.revision == 1) != (self.previous_digest is None):
            raise ValueError("Policy revision requires its predecessor digest")
        bounds = tuple(int(uint128(value)) for value in self.tier_thresholds_usd_cents)
        if not 0 < bounds[0] < bounds[1] < bounds[2]:
            raise ValueError("Policy thresholds must be positive and ordered")
        if len({source.source_id for source in self.sources}) != len(self.sources):
            raise ValueError("Policy source IDs must be unique")
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("Policy rule IDs must be unique")
        if any(set(rule.source_ids) - {source.source_id for source in self.sources} for rule in self.rules):
            raise ValueError("Rule requires policy source references")
        if any(
            source.reviewed_at > self.effective_from or source.valid_until < self.effective_until
            for source in self.sources
        ):
            raise ValueError("Source review intervals must cover the policy interval")
        return self

    @property
    def digest(self) -> str:
        return record_digest("clearproof/pilot-policy/v1", self.model_dump(mode="json"))

    @property
    def scope(self) -> tuple[str, ...]:
        return (self.tenant_id, self.chain_id, self.registry_address, self.jurisdiction)


class PolicyTrustStore:
    def __init__(self, policies: list[PilotPolicy], *, current_digests: tuple[str, ...]):
        """Pins are operator configuration, never fields accepted from a proof request.

        Exactly one current policy is permitted per scope. Historical or draft
        records in the input inventory cannot select themselves as current.
        """
        if type(policies) is not list or not 1 <= len(policies) <= 256:
            raise ValueError("Configure 1–256 policy records")
        if type(current_digests) is not tuple or not 1 <= len(current_digests) <= 256:
            raise ValueError("Configure 1–256 current policy pins")
        records = {}
        for policy in policies:
            policy = PilotPolicy.model_validate(policy)
            if policy.digest in records:
                raise ValueError("Duplicate policy record")
            records[policy.digest] = policy
        for policy in records.values():
            if policy.previous_digest is not None:
                previous = records.get(policy.previous_digest)
                if (
                    previous is None
                    or previous.scope != policy.scope
                    or previous.policy_id != policy.policy_id
                    or previous.revision + 1 != policy.revision
                ):
                    raise ValueError("Policy predecessor must be present and extend the same policy scope")
        if len(set(current_digests)) != len(current_digests) or any(pin not in records for pin in current_digests):
            raise ValueError("Current pins require distinct known policy records")
        current = {}
        for pin in current_digests:
            policy = records[pin]
            if policy.scope in current:
                raise ValueError("Conflicting current policies in one scope")
            current[policy.scope] = policy
        self._current = MappingProxyType(current)

    def for_transfer(
        self, transfer: Transfer, context: VerificationContext, *, tenant_id: str, now: int
    ) -> PilotPolicy:
        transfer = Transfer.model_validate(transfer)
        context = VerificationContext.model_validate(context)
        context.check_transfer(transfer)
        scope = (tenant_id, context.deployment_chain_id, context.deployment_address, transfer.jurisdiction)
        policy = self._current.get(scope)
        if policy is None or transfer.tenant_id != tenant_id:
            raise PolicyTrustError("No current policy in the authenticated scope")
        if (
            policy.digest != transfer.policy_digest
            or policy.digest != context.policy_digest
            or policy.asset_registry_digest != transfer.asset_registry_digest
        ):
            raise PolicyTrustError("Transfer does not bind the current policy")
        if type(now) is not int or not policy.effective_from <= context.evaluated_at <= now < policy.effective_until:
            raise PolicyTrustError("Policy is outside its effective interval")
        return policy
