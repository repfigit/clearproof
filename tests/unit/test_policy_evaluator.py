"""Deterministic replay and conservative evidence completeness."""

import runpy
from pathlib import Path

import pytest

from src.policy.evaluator import REQUIRED_FACTS, PolicyFact, PolicyFacts, evaluate_policy
from src.policy.model import PilotPolicy, PolicyRule

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def case():
    # Shared synthetic policy/transfer setup; this imports no service or network.
    policy, transfer, context = runpy.run_path(str(ROOT / "tests/unit/test_pilot_policy.py"))["case"].__wrapped__()

    def rule(name, predicate, effect, operator="is_true", threshold=None):
        return PolicyRule(
            rule_id=name,
            predicate=predicate,
            effect=effect,
            operator=operator,
            threshold_usd_cents=threshold,
            source_ids=("fixture",),
        )

    rules = (
        rule("allow-small", "usd_cents", "ALLOW", "below", "200000"),
        rule("review-large", "usd_cents", "REVIEW", "at_least", "200000"),
        rule("deny-screening", "sanctions_clear", "DENY", "is_false"),
    )
    policy = PilotPolicy.model_validate({**policy.model_dump(), "rules": rules})
    facts = PolicyFacts(
        tenant_id=transfer.tenant_id,
        transfer_digest=transfer.digest,
        facts=tuple(
            PolicyFact(
                predicate=p,
                value=True,
                observed_at=transfer.created_at,
                expires_at=transfer.expires_at,
                evidence_digest="ab" * 32,
            )
            for p in REQUIRED_FACTS
        ),
    )
    return policy, transfer, context, facts


def evaluate(case):
    return evaluate_policy(*case, now=case[2].evaluated_at)


def test_allow_requires_complete_evidence_and_is_deterministic(case):
    before = tuple(item.canonical_bytes() for item in case)
    first = evaluate(case)
    assert first.outcome == "ALLOW"
    assert first.canonical_bytes() == evaluate(case).canonical_bytes()
    assert before == tuple(item.canonical_bytes() for item in case)
    encoded = first.canonical_bytes().decode()
    assert case[1].originator.wallet not in encoded
    assert '"usd_cents"' not in encoded
    assert first.zk_coverage == "not-established"


@pytest.mark.parametrize("predicate", REQUIRED_FACTS)
def test_small_amount_cannot_remove_other_requirements(case, predicate):
    policy, transfer, context, facts = case
    facts = PolicyFacts.model_validate(
        {**facts.model_dump(), "facts": tuple(f for f in facts.facts if f.predicate != predicate)}
    )
    result = evaluate((policy, transfer, context, facts))
    assert result.outcome == "INDETERMINATE"
    assert predicate in result.missing_predicates


def test_false_screening_denies_and_reports_conflict(case):
    policy, transfer, context, facts = case
    updated = tuple(
        PolicyFact.model_validate({**f.model_dump(), "value": False}) if f.predicate == "sanctions_clear" else f
        for f in facts.facts
    )
    result = evaluate((policy, transfer, context, PolicyFacts.model_validate({**facts.model_dump(), "facts": updated})))
    assert result.outcome == "DENY"
    assert result.conflicting_effects
    assert result.matched_rule_ids == ("allow-small", "deny-screening")


def test_incomplete_information_requires_review(case):
    policy, transfer, context, facts = case
    updated = tuple(
        PolicyFact.model_validate({**f.model_dump(), "value": False})
        if f.predicate == "required_information_complete"
        else f
        for f in facts.facts
    )
    result = evaluate((policy, transfer, context, PolicyFacts.model_validate({**facts.model_dump(), "facts": updated})))
    assert result.outcome == "REVIEW"


@pytest.mark.parametrize("delta,expected", [(-1, "REVIEW"), (0, "REVIEW"), (1, "ALLOW")])
def test_exact_cent_rule_boundaries(case, delta, expected):
    policy, transfer, context, facts = case
    amount = int(transfer.usd_cents)
    rules = tuple(
        PolicyRule.model_validate({**r.model_dump(), "threshold_usd_cents": str(amount + delta)})
        if r.predicate == "usd_cents"
        else r
        for r in policy.rules
    )
    policy = PilotPolicy.model_validate({**policy.model_dump(), "rules": rules})
    assert evaluate((policy, transfer, context, facts)).outcome == expected


def test_unknown_predicate_is_not_treated_as_false(case):
    policy, transfer, context, facts = case
    rule = PolicyRule(
        rule_id="unsupported", predicate="live_feed_risk", operator="is_true", effect="DENY", source_ids=("fixture",)
    )
    policy = PilotPolicy.model_validate({**policy.model_dump(), "rules": (*policy.rules, rule)})
    result = evaluate((policy, transfer, context, facts))
    assert result.outcome == "INDETERMINATE"
    assert result.unsupported_predicates == ("live_feed_risk",)


@pytest.mark.parametrize("kind", ["expired-fact", "future-fact", "expired-policy", "future-context"])
def test_invalid_time_cannot_allow(case, kind):
    policy, transfer, context, facts = case
    now = context.evaluated_at
    if kind.endswith("fact"):
        fact = facts.facts[0]
        change = {"expires_at": now} if kind == "expired-fact" else {"observed_at": now + 1}
        facts = PolicyFacts.model_validate(
            {
                **facts.model_dump(),
                "facts": (PolicyFact.model_validate({**fact.model_dump(), **change}), *facts.facts[1:]),
            }
        )
    elif kind == "expired-policy":
        policy = PilotPolicy.model_validate({**policy.model_dump(), "effective_until": now})
    else:
        now -= 1
    assert evaluate_policy(policy, transfer, context, facts, now=now).outcome == "INDETERMINATE"


def test_no_rules_is_not_implicit_allow(case):
    policy, transfer, context, facts = case
    policy = PilotPolicy.model_validate({**policy.model_dump(), "rules": ()})
    result = evaluate((policy, transfer, context, facts))
    assert result.outcome == "INDETERMINATE" and "no_decisive_rule" in result.reasons


def test_foreign_or_conflicting_fact_snapshot_rejected(case):
    policy, transfer, context, facts = case
    with pytest.raises(ValueError, match="scope mismatch"):
        evaluate((policy, transfer, context, PolicyFacts.model_validate({**facts.model_dump(), "tenant_id": "other"})))
    with pytest.raises(ValueError, match="duplicate facts"):
        PolicyFacts.model_validate({**facts.model_dump(), "facts": (*facts.facts, facts.facts[0])})
