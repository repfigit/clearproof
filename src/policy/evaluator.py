"""Deterministic policy replay over supplied evidence; never authorization or I/O."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from src.policy.model import PilotPolicy
from src.protocol.transfer import Epoch, Hex32, OpaqueId, Record, Transfer, VerificationContext

# Minimum evidence completeness for this pilot's ALLOW result. These are not
# a declaration that this list exhausts any jurisdiction's legal obligations.
REQUIRED_FACTS = (
    "applicability_resolved",
    "credential_valid",
    "sanctions_clear",
    "counterparty_trusted",
    "required_information_complete",
    "valuation_authenticated",
)
SUPPORTED_FACTS = frozenset((*REQUIRED_FACTS, "proof_valid", "counterparty_acknowledged"))
Outcome = Literal["ALLOW", "REVIEW", "DENY", "INDETERMINATE"]


class PolicyFact(Record):
    predicate: OpaqueId
    value: bool
    observed_at: Epoch
    expires_at: Epoch
    evidence_digest: Hex32

    @model_validator(mode="after")
    def interval(self):
        if self.expires_at <= self.observed_at:
            raise ValueError("Fact requires a positive validity interval")
        return self


class PolicyFacts(Record):
    tenant_id: OpaqueId
    transfer_digest: Hex32
    facts: tuple[PolicyFact, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def unique_facts(self):
        if len({fact.predicate for fact in self.facts}) != len(self.facts):
            raise ValueError("Conflicting duplicate facts")
        return self


class PolicyEvaluation(Record):
    schema_version: Literal["clearproof-policy-evaluation-v1"] = "clearproof-policy-evaluation-v1"
    policy_digest: Hex32
    transfer_digest: Hex32
    evaluated_at: Epoch
    outcome: Outcome
    matched_rule_ids: tuple[OpaqueId, ...]
    missing_predicates: tuple[OpaqueId, ...]
    unsupported_predicates: tuple[OpaqueId, ...]
    reasons: tuple[OpaqueId, ...]
    conflicting_effects: bool
    # Policy logic is not asserted to be encoded by the Groth16 circuit.
    zk_coverage: Literal["not-established"] = "not-established"


def with_verified_statement_facts(
    external: PolicyFacts, *, proof_digest: str, expires_at: int, observed_at: int
) -> PolicyFacts:
    """Caller establishes statement/status preconditions; this helper grants no authority."""
    return PolicyFacts(
        tenant_id=external.tenant_id,
        transfer_digest=external.transfer_digest,
        facts=(
            *external.facts,
            *(
                PolicyFact(
                    predicate=predicate,
                    value=True,
                    observed_at=observed_at,
                    expires_at=expires_at,
                    evidence_digest=proof_digest,
                )
                for predicate in ("credential_valid", "sanctions_clear", "valuation_authenticated", "proof_valid")
            ),
        ),
    )


def evaluate_policy(
    policy: PilotPolicy,
    transfer: Transfer,
    context: VerificationContext,
    facts: PolicyFacts,
    *,
    now: int,
) -> PolicyEvaluation:
    """Supports counterfactual policy versions without mutating the original transfer.

    Caller must authenticate the facts, quote, tenant and policy provenance.
    This function checks supplied scope/time/consistency and performs no network,
    persistence, proof consumption, signing or payment/settlement operation.
    Reports contain no raw amounts, wallets or fact values; keep them tenant-private.
    """
    policy = PilotPolicy.model_validate(policy)
    transfer = Transfer.model_validate(transfer)
    context = VerificationContext.model_validate(context)
    facts = PolicyFacts.model_validate(facts)
    if type(now) is not int or not 0 <= now < 2**53:
        raise ValueError("Invalid policy evaluation time")
    context.check_transfer(transfer)
    if (
        facts.tenant_id != transfer.tenant_id
        or facts.transfer_digest != transfer.digest
        or policy.scope
        != (transfer.tenant_id, context.deployment_chain_id, context.deployment_address, transfer.jurisdiction)
        or policy.asset_registry_digest != transfer.asset_registry_digest
    ):
        raise ValueError("Policy evaluation scope mismatch")
    reasons, missing, unsupported, matched, effects = set(), set(), set(), [], set()
    if not policy.effective_from <= now < policy.effective_until:
        reasons.add("policy_not_effective")
    if not transfer.created_at <= now < transfer.expires_at:
        reasons.add("transfer_not_effective")
    if now < context.evaluated_at:
        reasons.add("context_not_effective")
    if any(not source.reviewed_at <= now < source.valid_until for source in policy.sources):
        reasons.add("source_not_effective")
    supplied = {fact.predicate: fact for fact in facts.facts}

    def value(predicate):
        fact = supplied.get(predicate)
        if fact is None or not fact.observed_at <= now < fact.expires_at:
            missing.add(predicate)
            return None
        return fact.value

    incomplete = False
    for predicate in REQUIRED_FACTS:
        state = value(predicate)
        if state is False:
            if predicate == "applicability_resolved":
                reasons.add("applicability_unresolved")
            else:
                incomplete = True
    for rule in policy.rules:
        if rule.predicate == "usd_cents":
            if value("valuation_authenticated") is not True:
                reasons.add("valuation_not_authenticated")
                continue
            amount, threshold = int(transfer.usd_cents), int(rule.threshold_usd_cents)
            matches = amount >= threshold if rule.operator == "at_least" else amount < threshold
        elif rule.predicate not in SUPPORTED_FACTS:
            unsupported.add(rule.predicate)
            continue
        else:
            state = value(rule.predicate)
            if state is None:
                continue
            matches = state if rule.operator == "is_true" else not state
        if matches:
            matched.append(rule.rule_id)
            effects.add(rule.effect)
    if reasons & {"policy_not_effective", "transfer_not_effective", "source_not_effective", "context_not_effective"}:
        outcome = "INDETERMINATE"
    elif "DENY" in effects:
        outcome = "DENY"
    elif reasons or missing or unsupported:
        outcome = "INDETERMINATE"
    elif "REVIEW" in effects or incomplete:
        outcome = "REVIEW"
    elif "ALLOW" in effects:
        outcome = "ALLOW"
    else:
        outcome = "INDETERMINATE"
        reasons.add("no_decisive_rule")
    if incomplete:
        reasons.add("required_checks_incomplete")
    return PolicyEvaluation(
        policy_digest=policy.digest,
        transfer_digest=transfer.digest,
        evaluated_at=now,
        outcome=outcome,
        matched_rule_ids=tuple(sorted(matched)),
        missing_predicates=tuple(sorted(missing)),
        unsupported_predicates=tuple(sorted(unsupported)),
        reasons=tuple(sorted(reasons)),
        conflicting_effects=len(effects) > 1,
    )
