"""Counterfactual comparisons, stdin CLI and actual JWT-protected HTTP requests."""

import json
import runpy
import subprocess
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.api.routes.policy import router
from src.policy.diff import MAX_INPUT_BYTES, PolicyCase, PolicyDiffRequest, compare_policies
from src.policy.model import PilotPolicy, PolicyRule

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def comparison():
    before, transfer, context, facts = runpy.run_path(str(ROOT / "tests/unit/test_policy_evaluator.py"))[
        "case"
    ].__wrapped__()
    rules = tuple(
        PolicyRule.model_validate({**r.model_dump(), "threshold_usd_cents": "100000"})
        if r.predicate == "usd_cents"
        else r
        for r in before.rules
    )
    after = PilotPolicy.model_validate(
        {**before.model_dump(), "revision": 2, "previous_digest": before.digest, "rules": rules}
    )
    return PolicyDiffRequest(
        before=before,
        after=after,
        cases=(
            PolicyCase(
                case_id="case-001",
                transfer=transfer,
                context=context,
                facts=facts,
                evaluated_at=context.evaluated_at,
            ),
        ),
    )


def test_diff_reports_review_impact_without_mutating_inputs(comparison):
    before = comparison.model_dump_json()
    result = compare_policies(comparison)
    assert result.decision_changes == result.review_delta == 1
    assert (result.review_before, result.review_after) == (0, 1)
    assert result.cases[0].entered_review and not result.cases[0].left_review
    assert result.cases[0].before.outcome == "ALLOW" and result.cases[0].after.outcome == "REVIEW"
    assert result.cases[0].changed_rule_ids == ("allow-small", "review-large")
    assert result.model_dump_json() == compare_policies(comparison).model_dump_json()
    assert comparison.model_dump_json() == before
    assert comparison.cases[0].transfer.originator.wallet not in result.model_dump_json()


def test_identical_versions_and_reverse_comparison(comparison):
    same = PolicyDiffRequest.model_validate({**comparison.model_dump(), "after": comparison.before})
    assert compare_policies(same).decision_changes == 0
    reverse = PolicyDiffRequest.model_validate(
        {**comparison.model_dump(), "before": comparison.after, "after": comparison.before}
    )
    report = compare_policies(reverse)
    assert report.review_delta == -1 and report.cases[0].left_review


def test_unsupported_and_missing_evidence_reported(comparison):
    case = comparison.cases[0]
    facts = case.facts.model_copy(update={"facts": ()})
    request = PolicyDiffRequest.model_validate(
        {**comparison.model_dump(), "cases": (PolicyCase.model_validate({**case.model_dump(), "facts": facts}),)}
    )
    report = compare_policies(request)
    assert report.indeterminate_before == report.indeterminate_after == 1
    assert "sanctions_clear" in report.cases[0].after.missing_predicates
    assert report.cases[0].after.zk_coverage == "not-established"


def test_duplicate_business_transfers_and_oversize_batch_rejected(comparison):
    case = comparison.cases[0]
    duplicate = PolicyCase.model_validate({**case.model_dump(), "case_id": "case-002"})
    with pytest.raises(ValueError, match="Duplicate transfer"):
        PolicyDiffRequest.model_validate({**comparison.model_dump(), "cases": (case, duplicate)})
    with pytest.raises(ValueError):
        PolicyDiffRequest.model_validate({**comparison.model_dump(), "cases": (case,) * 65})


def test_cli_actual_stdin_success_and_redacted_failure(comparison):
    command = [sys.executable, "-m", "src.policy.diff"]
    good = subprocess.run(command, input=comparison.model_dump_json().encode(), capture_output=True, timeout=15)
    assert good.returncode == 0, good.stderr
    assert json.loads(good.stdout)["review_delta"] == 1
    bad = subprocess.run(
        command, input=b'{"customer":"never-echo-this","before":null}', capture_output=True, timeout=15
    )
    assert bad.returncode == 1
    assert b"never-echo-this" not in bad.stdout + bad.stderr


@pytest.fixture
def authenticated_app(monkeypatch):
    from src.api.middleware import auth

    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    monkeypatch.setattr(
        auth,
        "JWT_PUBLIC_KEY",
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    app = FastAPI()
    app.include_router(router)

    def token(*, tenant="tenant-a", roles=("policy:read", "evidence:decrypt"), signer=key):
        now = int(time.time())
        return jwt.encode(
            {
                "tenant_id": tenant,
                "actor_id": "actor-a",
                "roles": list(roles),
                "issuer_dids": [],
                "iss": auth.JWT_ISSUER,
                "aud": auth.JWT_AUDIENCE,
                "sub": "test-subject",
                "iat": now,
                "exp": now + 60,
            },
            signer,
            algorithm="ES256",
        )

    return app, token


async def test_http_real_jwt_tenant_and_role_enforcement(comparison, authenticated_app):
    app, token = authenticated_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = comparison.model_dump(mode="json")
        response = await client.post(
            "/pilot/policy/diff", json=body, headers={"Authorization": "Bearer " + token(), "X-Tenant-ID": "other"}
        )
        assert response.status_code == 200 and response.json()["review_delta"] == 1
        for value, expected in [
            (token(tenant="other"), 403),
            (token(roles=("policy:read",)), 403),
            (token(signer=ec.generate_private_key(ec.SECP256R1())), 401),
        ]:
            response = await client.post("/pilot/policy/diff", json=body, headers={"Authorization": "Bearer " + value})
            assert response.status_code == expected
        assert (await client.post("/pilot/policy/diff", json=body)).status_code == 401


async def test_http_rejects_large_or_sensitive_malformed_body(authenticated_app):
    app, token = authenticated_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {"Authorization": "Bearer " + token()}
        response = await client.post("/pilot/policy/diff", content=b"x" * (MAX_INPUT_BYTES + 1), headers=headers)
        assert response.status_code == 413
        response = await client.post("/pilot/policy/diff", json={"customer": "never-echo-this"}, headers=headers)
        assert response.status_code == 422 and "never-echo-this" not in response.text


def test_batch_order_is_stable_and_counts_each_business_transfer_once(comparison):
    from src.policy.evaluator import PolicyFacts
    from src.protocol.transfer import Transfer, VerificationContext

    case = comparison.cases[0]
    transfer = Transfer.model_validate({**case.transfer.model_dump(), "transfer_id": "transfer-002"})
    context = VerificationContext.model_validate({**case.context.model_dump(), "transfer_digest": transfer.digest})
    facts = PolicyFacts.model_validate({**case.facts.model_dump(), "transfer_digest": transfer.digest})
    second = PolicyCase(
        case_id="case-002", transfer=transfer, context=context, facts=facts, evaluated_at=case.evaluated_at
    )
    ordered = PolicyDiffRequest.model_validate({**comparison.model_dump(), "cases": (case, second)})
    reversed_input = PolicyDiffRequest.model_validate({**comparison.model_dump(), "cases": (second, case)})
    assert compare_policies(ordered).model_dump_json() == compare_policies(reversed_input).model_dump_json()
    assert compare_policies(ordered).review_delta == 2
    altered = Transfer.model_validate({**case.transfer.model_dump(), "nonce": "cd" * 32})
    duplicate = PolicyCase.model_validate({**case.model_dump(), "case_id": "case-003", "transfer": altered})
    assert altered.digest != case.transfer.digest
    with pytest.raises(ValueError, match="Duplicate transfer"):
        PolicyDiffRequest.model_validate({**comparison.model_dump(), "cases": (case, duplicate)})


def test_changed_effect_under_same_rule_id_changes_explanation(comparison):
    rules = tuple(
        PolicyRule.model_validate({**rule.model_dump(), "effect": "REVIEW"}) if rule.rule_id == "allow-small" else rule
        for rule in comparison.before.rules
    )
    after = PilotPolicy.model_validate({**comparison.after.model_dump(), "rules": rules})
    request = PolicyDiffRequest.model_validate({**comparison.model_dump(), "after": after})
    result = compare_policies(request).cases[0]
    assert result.before.matched_rule_ids == result.after.matched_rule_ids
    assert result.decision_changed and result.explanation_changed


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "different-tenant"),
        ("chain_id", "31338"),
        ("registry_address", "0x" + "ab" * 20),
        ("jurisdiction", "GB"),
        ("asset_registry_digest", "cd" * 32),
    ],
)
def test_comparison_rejects_incompatible_policy_scope(comparison, field, value):
    after = PilotPolicy.model_validate({**comparison.after.model_dump(), field: value})
    with pytest.raises(ValueError, match="Comparison requires the same tenant/deployment/jurisdiction/catalog"):
        PolicyDiffRequest.model_validate({**comparison.model_dump(), "after": after})


def test_duplicate_case_labels_reject_even_for_distinct_transfers(comparison):
    case = comparison.cases[0]
    transfer = type(case.transfer).model_validate({**case.transfer.model_dump(), "transfer_id": "different-transfer"})
    context = type(case.context).model_validate({**case.context.model_dump(), "transfer_digest": transfer.digest})
    facts = type(case.facts).model_validate({**case.facts.model_dump(), "transfer_digest": transfer.digest})
    other = PolicyCase.model_validate({**case.model_dump(), "transfer": transfer, "context": context, "facts": facts})
    assert other.transfer.digest != case.transfer.digest
    with pytest.raises(ValueError, match="Duplicate comparison case ID"):
        PolicyDiffRequest.model_validate({**comparison.model_dump(), "cases": (case, other)})


@pytest.mark.parametrize("failure", [ValueError, TypeError])
async def test_http_comparison_failure_does_not_expose_internal_details(
    comparison, authenticated_app, monkeypatch, failure
):
    from unittest.mock import Mock

    from src.api.routes import policy as routes

    app, token = authenticated_app
    compare = Mock(side_effect=failure("synthetic-private-comparison-detail"))
    monkeypatch.setattr(routes, "compare_policies", compare)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/pilot/policy/diff",
            json=comparison.model_dump(mode="json"),
            headers={"Authorization": "Bearer " + token()},
        )
    assert response.status_code == 422
    assert response.json() == {"detail": "Policy comparison scope or evidence is invalid"}
    compare.assert_called_once()
