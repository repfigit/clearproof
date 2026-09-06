"""Cohort denominators and baseline semantics using minimized synthetic records."""

import pytest

from src.policy.evaluator import PolicyEvaluation
from src.services.observation_report import ObservationCase, ObservationCohort, summarize_observations
from src.services.proof_observation import ObservationRecord


def observation(outcome):
    policy = (
        PolicyEvaluation(
            policy_digest="aa" * 32,
            transfer_digest="bb" * 32,
            evaluated_at=1000,
            outcome=outcome,
            matched_rule_ids=(),
            missing_predicates=(),
            unsupported_predicates=(),
            reasons=(),
            conflicting_effects=False,
        )
        if outcome is not None
        else None
    )
    return ObservationRecord(
        assurance="development-unapproved",
        tenant_id="tenant-a",
        actor_id="observer",
        request_digest="ab" * 32,
        credential_id="credential",
        proof_digest="cd" * 32,
        signals_digest="de" * 32,
        transfer_digest="bb" * 32,
        context_digest="ef" * 32,
        policy_digest="aa" * 32,
        manifest_digest="fe" * 32,
        proof_profile="pilot-transfer-v2",
        fact_ids=(),
        observed_at=1000,
        cryptographic_valid=outcome is not None,
        policy=policy,
    )


def test_missing_failed_and_indeterminate_cases_have_distinct_denominators():
    records = [observation("ALLOW"), observation("INDETERMINATE"), observation(None)]
    cohort = ObservationCohort(
        cohort_id="synthetic",
        cases=(
            ObservationCase(case_id="allow", observation_id=records[0].digest, baseline_outcome="ALLOW"),
            ObservationCase(case_id="indeterminate", observation_id=records[1].digest, baseline_outcome="DENY"),
            ObservationCase(case_id="failed", observation_id=records[2].digest, baseline_outcome="DENY"),
            ObservationCase(case_id="missing", observation_id=None, baseline_outcome="ALLOW"),
            ObservationCase(case_id="unavailable", observation_id="00" * 32),
        ),
    )
    report = summarize_observations(cohort, {r.digest: r for r in records})
    assert report["case_count"] == 5 and report["observed_count"] == 3 and report["missing_count"] == 2
    assert report["policy_count"] == 2 and report["determinate_count"] == 1
    assert report["failed_pairing_count"] == 1 and report["distinct_observed_transfers"] == 1
    assert report["baseline_label_count"] == 4 and report["comparable_count"] == 2
    assert report["agreement_count"] == 1 and report["disagreement_count"] == 1
    cases = {c["case_id"]: c for c in report["cases"]}
    assert cases["failed"]["status"] == "observed" and cases["failed"]["outcome"] is None
    assert cases["failed"]["agrees_with_baseline"] is None
    assert cases["missing"]["status"] == "not-observed" and cases["unavailable"]["status"] == "unavailable"
    assert report["latency_status"] == "not-recorded"
    assert report["baseline_authority"] == "caller-supplied-unverified"
    reversed_cohort = ObservationCohort(cohort_id=cohort.cohort_id, cases=tuple(reversed(cohort.cases)))
    assert summarize_observations(reversed_cohort, {r.digest: r for r in records}) == report


def test_duplicate_cases_or_observations_cannot_bias_counts():
    case = ObservationCase(case_id="one", observation_id="ab" * 32)
    with pytest.raises(ValueError, match="Duplicate cohort case"):
        ObservationCohort(cohort_id="synthetic", cases=(case, case))
    other = ObservationCase(case_id="two", observation_id=case.observation_id)
    with pytest.raises(ValueError, match="Duplicate observation"):
        ObservationCohort(cohort_id="synthetic", cases=(case, other))
    with pytest.raises(ValueError):
        ObservationCohort(cohort_id="synthetic", cases=())
    with pytest.raises(ValueError):
        ObservationCohort(
            cohort_id="synthetic",
            cases=tuple(ObservationCase(case_id=f"case-{i}", observation_id=None) for i in range(65)),
        )
    record = observation("ALLOW")
    with pytest.raises(ValueError, match="reference mismatch"):
        summarize_observations(ObservationCohort(cohort_id="synthetic", cases=(case,)), {case.observation_id: record})
