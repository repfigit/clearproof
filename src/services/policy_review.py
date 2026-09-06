"""Encrypted policy approval and reviewed-case retention; never activates policy."""

import json
from typing import Literal

from pydantic import Field

from src.auth.principal import Principal
from src.policy.diff import PolicyCase, PolicyDiffRequest, compare_policies
from src.policy.evaluator import evaluate_policy
from src.policy.model import PilotPolicy
from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.transfer import Hex32, Record
from src.storage.pilot import PilotStore, RecordConflict


class ReviewedCase(Record):
    case: PolicyCase
    expected: Literal["ALLOW", "REVIEW", "DENY", "INDETERMINATE"]


class PolicyReviewRequest(Record):
    policy: PilotPolicy
    cases: tuple[ReviewedCase, ...] = Field(min_length=1, max_length=16)


class StoredPolicyComparison(Record):
    before_digest: Hex32
    after_digest: Hex32
    case_digests: tuple[Hex32, ...] = Field(min_length=1, max_length=64)


class PolicyRecordMissing(ValueError):
    pass


class PolicyReviewService:
    def __init__(self, db, cipher, principal: Principal):
        self.principal = Principal.model_validate(principal)
        self.store = PilotStore(db, cipher, self.principal)

    async def approve(self, request: PolicyReviewRequest, *, idempotency_key: str, now: int) -> dict:
        self.principal.require("policy:approve")
        self.principal.require("evidence:decrypt")
        request = PolicyReviewRequest.model_validate(request)
        policy = request.policy
        if type(now) is not int or not policy.effective_from <= now < policy.effective_until:
            raise ValueError("Approval requires a currently effective policy")
        if policy.tenant_id != self.principal.tenant_id:
            raise ValueError("Policy is outside the authenticated tenant")
        if len({r.case.case_id for r in request.cases}) != len(request.cases) or len(
            {r.case.transfer.transfer_id for r in request.cases}
        ) != len(request.cases):
            raise ValueError("Review cases require unique business transfers and case IDs")
        retained, reviews = [], []
        for item in sorted(request.cases, key=lambda r: r.case.case_id):
            case = item.case
            if case.evaluated_at > now:
                raise ValueError("Review cannot assert future observations")
            result = evaluate_policy(policy, case.transfer, case.context, case.facts, now=case.evaluated_at)
            if result.outcome != item.expected:
                raise ValueError("Reviewed expected outcome does not match evaluation")
            value = case.model_dump(mode="json")
            case_digest = record_digest("clearproof/review-case/v1", value)
            retained.append((case_digest, value))
            reviews.append(
                {"case_digest": case_digest, "expected": item.expected, "evaluation": result.model_dump(mode="json")}
            )
        approval = {
            "schema_version": "clearproof-policy-approval-v1",
            "policy": policy.model_dump(mode="json"),
            "actor_id": self.principal.actor_id,
            "approved_at": now,
            "reviews": reviews,
        }
        canonical_bytes(approval)  # Bound the complete encrypted record before opening a transaction.
        request_digest = record_digest(
            "clearproof/policy-review-request/v1",
            {
                "policy_digest": policy.digest,
                "reviews": [{"case_digest": r["case_digest"], "expected": r["expected"]} for r in reviews],
            },
        )

        async def persist(tx):
            if policy.previous_digest:
                previous = await tx.get("policy", policy.previous_digest)
                if not previous or previous.get("schema_version") != "clearproof-policy-approval-v1":
                    raise ValueError("Approved predecessor is missing")
                parent = PilotPolicy.model_validate_json(json.dumps(previous["policy"]))
                if (
                    parent.digest != policy.previous_digest
                    or parent.scope != policy.scope
                    or parent.policy_id != policy.policy_id
                    or parent.revision + 1 != policy.revision
                    or previous["approved_at"] > now
                ):
                    raise ValueError("Approval does not extend the retained policy history")
            for key, value in retained:
                existing = await tx.get("policy", key)
                envelope = {"schema_version": "clearproof-reviewed-case-v1", "case": value}
                if existing is None:
                    await tx.put("policy", key, envelope)
                elif existing != envelope:
                    raise RecordConflict("Reviewed case content differs")
            await tx.put("policy", policy.digest, approval)
            return {"policy_digest": policy.digest, "approved_at": now, "reviewed_cases": len(reviews)}

        # Server clock is deliberately excluded: identical retries return the original approval time.
        return await self.store.run_idempotent(
            "approve-policy", idempotency_key, {"request_digest": request_digest}, persist
        )

    async def compare_stored(self, request: StoredPolicyComparison):
        self.principal.require("policy:read")
        self.principal.require("evidence:decrypt")
        request = StoredPolicyComparison.model_validate(request)
        if len(set(request.case_digests)) != len(request.case_digests):
            raise ValueError("Duplicate retained case")
        policies, cases = [], []
        async with self.store.transaction() as tx:
            for digest in (request.before_digest, request.after_digest):
                value = await tx.get("policy", digest)
                if not value or value.get("schema_version") != "clearproof-policy-approval-v1":
                    raise PolicyRecordMissing("Retained policy or case is unavailable")
                policy = PilotPolicy.model_validate_json(json.dumps(value["policy"]))
                if policy.digest != digest or policy.tenant_id != self.principal.tenant_id:
                    raise ValueError("Retained policy binding is invalid")
                policies.append(policy)
            for digest in request.case_digests:
                value = await tx.get("policy", digest)
                if not value or value.get("schema_version") != "clearproof-reviewed-case-v1":
                    raise PolicyRecordMissing("Retained policy or case is unavailable")
                case = PolicyCase.model_validate_json(json.dumps(value["case"]))
                if record_digest("clearproof/review-case/v1", case.model_dump(mode="json")) != digest:
                    raise ValueError("Retained case binding is invalid")
                cases.append(case)
        return compare_policies(PolicyDiffRequest(before=policies[0], after=policies[1], cases=tuple(cases)))
