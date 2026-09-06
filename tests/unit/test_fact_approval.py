"""Real scoped business-fact signatures, no inferred proof or policy authorization."""

import runpy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.policy.evaluator import PolicyFact, evaluate_policy
from src.policy.fact_approval import (
    EXTERNAL_FACTS,
    FactApproval,
    FactAuthority,
    FactTrustError,
    FactTrustStore,
    SignedFactApproval,
    sign_fact,
)


@pytest.fixture
def case():
    policy, transfer, context, _ = runpy.run_path(str(Path(__file__).with_name("test_policy_evaluator.py")))[
        "case"
    ].__wrapped__()
    key = Ed25519PrivateKey.generate()
    authority = FactAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id=transfer.tenant_id,
        chain_id=int(context.deployment_chain_id),
        registry_address=context.deployment_address,
        source_ids=("business-source",),
        predicates=tuple(sorted(EXTERNAL_FACTS)),
        not_before=transfer.created_at,
        not_after=transfer.expires_at,
        max_lifetime_seconds=86400,
        max_observation_age_seconds=86400,
    )
    approvals = tuple(
        sign_fact(
            FactApproval(
                tenant_id=transfer.tenant_id,
                transfer_digest=transfer.digest,
                context_digest=context.digest,
                source_id="business-source",
                signed_at=transfer.created_at,
                key_id=authority.key_id,
                fact=PolicyFact(
                    predicate=p,
                    value=True,
                    observed_at=transfer.created_at,
                    expires_at=transfer.expires_at,
                    evidence_digest="ab" * 32,
                ),
            ),
            key,
        )
        for p in sorted(EXTERNAL_FACTS)
    )
    args = dict(transfer=transfer, context=context, tenant_id=transfer.tenant_id, now=context.evaluated_at)
    return key, authority, approvals, args, policy


def test_order_retries_and_missing_derived_facts(case):
    _, authority, approvals, args, policy = case
    trust = FactTrustStore([authority])
    facts = trust.verify_for_context(approvals, **args)
    assert facts == trust.verify_for_context(tuple(reversed(approvals)) + (approvals[0],), **args)
    result = evaluate_policy(policy, args["transfer"], args["context"], facts, now=args["now"])
    assert result.outcome == "INDETERMINATE"
    assert {"credential_valid", "sanctions_clear", "valuation_authenticated"} <= set(result.missing_predicates)
    assert trust.verify_for_context((), **args).facts == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "foreign"),
        ("transfer_digest", "00" * 32),
        ("context_digest", "00" * 32),
        ("source_id", "other-source"),
        ("key_id", "00" * 32),
    ],
)
def test_substituted_approval_rejected(case, field, value):
    _, authority, approvals, args, _ = case
    altered = SignedFactApproval.model_validate(
        {
            "approval": {**approvals[0].approval.model_dump(), field: value},
            "signature": approvals[0].signature,
        }
    )
    with pytest.raises(FactTrustError):
        FactTrustStore([authority]).verify_for_context((altered,), **args)


@pytest.mark.parametrize(
    "scope",
    [
        {"tenant_id": "foreign"},
        {"chain_id": 999},
        {"registry_address": "0x" + "34" * 20},
        {"source_ids": ("other",)},
        {"predicates": ("counterparty_trusted",)},
    ],
)
def test_valid_signature_requires_independent_authority_scope(case, scope):
    _, authority, approvals, args, _ = case
    changed = FactAuthority.model_validate({**authority.model_dump(), **scope})
    with pytest.raises(FactTrustError):
        FactTrustStore([changed]).verify_for_context(approvals, **args)


def test_false_fact_is_preserved_and_conflicts_fail(case):
    key, authority, approvals, args, _ = case
    original = approvals[0].approval
    false = sign_fact(
        FactApproval.model_validate(
            {
                **original.model_dump(),
                "fact": {**original.fact.model_dump(), "value": False},
            }
        ),
        key,
    )
    trust = FactTrustStore([authority])
    assert trust.verify_for_context((false,), **args).facts[0].value is False
    for pair in [(false, approvals[0]), (approvals[0], false)]:
        with pytest.raises(FactTrustError, match="Conflicting"):
            trust.verify_for_context(pair, **args)
    tampered = SignedFactApproval(approval=false.approval, signature=approvals[0].signature)
    with pytest.raises(FactTrustError, match="signature"):
        trust.verify_for_context((tampered,), **args)


def test_rotation_purpose_and_current_clock(case):
    key, authority, approvals, args, _ = case
    other_key = Ed25519PrivateKey.generate()
    other = FactAuthority.model_validate(
        {**authority.model_dump(), "public_key": other_key.public_key().public_bytes_raw().hex()}
    )
    assert FactTrustStore([authority, other]).verify_for_context(approvals, **args).facts
    with pytest.raises(FactTrustError):
        FactTrustStore([other]).verify_for_context(approvals, **args)
    wrong = SignedFactApproval(
        approval=approvals[0].approval,
        signature=key.sign(b"different-purpose\0" + approvals[0].approval.signing_bytes()).hex(),
    )
    with pytest.raises(FactTrustError, match="signature"):
        FactTrustStore([authority]).verify_for_context((wrong,), **args)
    for now in [True, args["context"].evaluated_at - 1, args["transfer"].expires_at]:
        with pytest.raises(FactTrustError):
            FactTrustStore([authority]).verify_for_context(approvals, **{**args, "now": now})
    short = FactAuthority.model_validate({**authority.model_dump(), "max_observation_age_seconds": 1})
    with pytest.raises(FactTrustError):
        FactTrustStore([short]).verify_for_context(
            approvals, **{**args, "now": max(args["now"], authority.not_before + 2)}
        )


@pytest.mark.parametrize("predicate", ["credential_valid", "sanctions_clear", "proof_valid", "valuation_authenticated"])
def test_attestors_cannot_claim_proof_derived_results(case, predicate):
    _, _, approvals, _, _ = case
    approval = approvals[0].approval
    with pytest.raises(ValueError, match="proof-derived"):
        FactApproval.model_validate(
            {**approval.model_dump(), "fact": {**approval.fact.model_dump(), "predicate": predicate}}
        )
