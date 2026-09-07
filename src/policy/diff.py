"""Bounded counterfactual policy comparison; stdin CLI avoids plaintext input files."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Literal

from pydantic import Field, model_validator

from src.policy.evaluator import PolicyEvaluation, PolicyFacts, evaluate_policy
from src.policy.model import PilotPolicy
from src.protocol.transfer import Epoch, Hex32, OpaqueId, Record, Transfer, VerificationContext
from src.prover.pilot_artifacts import strict_json

MAX_INPUT_BYTES = 1024 * 1024


class PolicyCase(Record):
    case_id: OpaqueId
    transfer: Transfer
    context: VerificationContext
    facts: PolicyFacts
    evaluated_at: Epoch


class PolicyDiffRequest(Record):
    before: PilotPolicy
    after: PilotPolicy
    cases: tuple[PolicyCase, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def comparable(self):
        if (
            self.before.scope != self.after.scope
            or self.before.asset_registry_digest != self.after.asset_registry_digest
        ):
            raise ValueError("Comparison requires the same tenant/deployment/jurisdiction/catalog")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Duplicate comparison case ID")
        if len({(case.transfer.tenant_id, case.transfer.transfer_id) for case in self.cases}) != len(self.cases):
            raise ValueError("Duplicate transfer would bias comparison counts")
        return self

    @classmethod
    def parse(cls, raw: bytes):
        strict_json(raw, limit=MAX_INPUT_BYTES)
        return cls.model_validate_json(raw)


class CaseComparison(Record):
    case_id: OpaqueId
    before: PolicyEvaluation
    after: PolicyEvaluation
    decision_changed: bool
    explanation_changed: bool
    entered_review: bool
    left_review: bool
    changed_rule_ids: tuple[OpaqueId, ...]


class PolicyDiffReport(Record):
    schema_version: Literal["clearproof-policy-diff-v1"] = "clearproof-policy-diff-v1"
    mode: Literal["counterfactual"] = "counterfactual"
    before_digest: Hex32
    after_digest: Hex32
    cases: tuple[CaseComparison, ...]
    decision_changes: int
    review_before: int
    review_after: int
    review_delta: int
    indeterminate_before: int
    indeterminate_after: int


def compare_policies(request: PolicyDiffRequest) -> PolicyDiffReport:
    request = PolicyDiffRequest.model_validate(request)
    before_rules = {rule.rule_id: rule for rule in request.before.rules}
    after_rules = {rule.rule_id: rule for rule in request.after.rules}
    edited = {
        name for name in before_rules.keys() | after_rules.keys() if before_rules.get(name) != after_rules.get(name)
    }
    comparisons = []
    for case in sorted(request.cases, key=lambda item: item.case_id):
        before = evaluate_policy(request.before, case.transfer, case.context, case.facts, now=case.evaluated_at)
        after = evaluate_policy(request.after, case.transfer, case.context, case.facts, now=case.evaluated_at)
        explanation_fields = (
            "matched_rule_ids",
            "missing_predicates",
            "unsupported_predicates",
            "reasons",
            "conflicting_effects",
        )
        comparisons.append(
            CaseComparison(
                case_id=case.case_id,
                before=before,
                after=after,
                decision_changed=before.outcome != after.outcome,
                explanation_changed=(
                    any(getattr(before, f) != getattr(after, f) for f in explanation_fields)
                    or bool(edited & (set(before.matched_rule_ids) | set(after.matched_rule_ids)))
                ),
                entered_review=before.outcome != "REVIEW" and after.outcome == "REVIEW",
                left_review=before.outcome == "REVIEW" and after.outcome != "REVIEW",
                # Candidate causes, not a claim of counterfactual causal attribution.
                changed_rule_ids=tuple(sorted(edited | (set(before.matched_rule_ids) ^ set(after.matched_rule_ids)))),
            )
        )
    before_review = sum(case.before.outcome == "REVIEW" for case in comparisons)
    after_review = sum(case.after.outcome == "REVIEW" for case in comparisons)
    return PolicyDiffReport(
        before_digest=request.before.digest,
        after_digest=request.after.digest,
        cases=tuple(comparisons),
        decision_changes=sum(case.decision_changed for case in comparisons),
        review_before=before_review,
        review_after=after_review,
        review_delta=after_review - before_review,
        indeterminate_before=sum(case.before.outcome == "INDETERMINATE" for case in comparisons),
        indeterminate_after=sum(case.after.outcome == "INDETERMINATE" for case in comparisons),
    )


def main() -> int:
    argparse.ArgumentParser(
        description="Read policy comparison JSON from stdin; return a tenant-private simulation report"
    ).parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        report = compare_policies(PolicyDiffRequest.parse(raw))
    except (ValueError, TypeError, RecursionError):
        print(json.dumps({"status": "rejected", "reason": "invalid_policy_comparison"}))
        return 1
    print(report.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
