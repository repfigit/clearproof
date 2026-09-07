"""Current policy selection, predecessor integrity and confidential tier units."""

import json
from pathlib import Path

import pytest

from src.policy.model import PilotPolicy, PolicySource, PolicyTrustError, PolicyTrustStore
from src.protocol.transfer import Transfer, VerificationContext
from src.prover.pilot_valuation import private_tier_witness


@pytest.fixture
def case():
    fixture = json.loads((Path(__file__).resolve().parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    transfer = Transfer.model_validate(fixture["records"][0]["value"])
    context = VerificationContext.model_validate(fixture["records"][1]["value"])
    policy = PilotPolicy(
        policy_id="synthetic-rules",
        revision=1,
        tenant_id=transfer.tenant_id,
        chain_id=context.deployment_chain_id,
        registry_address=context.deployment_address,
        jurisdiction=transfer.jurisdiction,
        asset_registry_digest=transfer.asset_registry_digest,
        effective_from=transfer.created_at,
        effective_until=transfer.valuation.expires_at,
        tier_thresholds_usd_cents=("10000", "100000", "1000000"),
        sources=(
            PolicySource(
                source_id="fixture",
                kind="synthetic",
                reference="urn:clearproof:synthetic:fixture",
                evidence_digest="ab" * 32,
                reviewed_at=transfer.created_at,
                valid_until=transfer.valuation.expires_at,
            ),
        ),
    )
    return policy, *bind(policy, transfer, context)


def bind(policy, transfer, context):
    transfer = Transfer.model_validate({**transfer.model_dump(), "policy_digest": policy.digest})
    context = VerificationContext.model_validate(
        {**context.model_dump(), "policy_digest": policy.digest, "transfer_digest": transfer.digest}
    )
    return transfer, context


def current(case, **kwargs):
    policy, transfer, context = case
    return PolicyTrustStore([policy], current_digests=(policy.digest,)).for_transfer(
        transfer,
        context,
        **{"tenant_id": transfer.tenant_id, "now": context.evaluated_at, **kwargs},
    )


def test_current_policy_selected_and_exact_cent_boundaries(case):
    policy = current(case)
    assert policy == case[0]
    thresholds = policy.tier_thresholds_usd_cents
    for i, bound in enumerate(map(int, thresholds), start=1):
        assert private_tier_witness(str(bound - 1), thresholds)["tier"] == str(i)
        assert private_tier_witness(str(bound), thresholds)["tier"] == str(i + 1)
        assert private_tier_witness(str(bound + 1), thresholds)["tier"] == str(i + 1)


def test_operator_pin_prevents_older_policy_or_draft_self_selection(case):
    old, transfer, context = case
    new = PilotPolicy.model_validate(
        {
            **old.model_dump(),
            "revision": 2,
            "previous_digest": old.digest,
            "tier_thresholds_usd_cents": ("20000", "200000", "2000000"),
        }
    )
    current_new = PolicyTrustStore([old, new], current_digests=(new.digest,))
    with pytest.raises(PolicyTrustError, match="current policy"):
        current_new.for_transfer(transfer, context, tenant_id=transfer.tenant_id, now=context.evaluated_at)
    changed_transfer, changed_context = bind(new, transfer, context)
    assert (
        current_new.for_transfer(
            changed_transfer, changed_context, tenant_id=transfer.tenant_id, now=context.evaluated_at
        )
        == new
    )
    # A higher version in inventory stays a draft until independently pinned.
    current_old = PolicyTrustStore([old, new], current_digests=(old.digest,))
    assert current_old.for_transfer(transfer, context, tenant_id=transfer.tenant_id, now=context.evaluated_at) == old
    with pytest.raises(PolicyTrustError):
        current_old.for_transfer(
            changed_transfer, changed_context, tenant_id=transfer.tenant_id, now=context.evaluated_at
        )
    with pytest.raises(ValueError, match="Conflicting current"):
        PolicyTrustStore([old, new], current_digests=(old.digest, new.digest))


@pytest.mark.parametrize("change", ["missing", "tenant", "policy-id", "revision", "domain"])
def test_predecessor_chain_cannot_be_fabricated(case, change):
    old, _, _ = case
    values = {**old.model_dump(), "revision": 2, "previous_digest": old.digest}
    changes = {
        "missing": {"previous_digest": "cd" * 32},
        "tenant": {"tenant_id": "other"},
        "policy-id": {"policy_id": "different"},
        "revision": {"revision": 3},
        "domain": {"chain_id": "31338"},
    }
    new = PilotPolicy.model_validate({**values, **changes[change]})
    with pytest.raises(ValueError, match="predecessor"):
        PolicyTrustStore([old, new], current_digests=(new.digest,))


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "other"),
        ("chain_id", "31338"),
        ("registry_address", "0x" + "ab" * 20),
        ("jurisdiction", "GB"),
        ("asset_registry_digest", "cd" * 32),
    ],
)
def test_policy_scope_cannot_be_substituted(case, field, value):
    policy, transfer, context = case
    other = PilotPolicy.model_validate({**policy.model_dump(), field: value})
    with pytest.raises(PolicyTrustError):
        current((other, transfer, context))


@pytest.mark.parametrize("now", [1788649999, 1788650600, True])
def test_policy_time_boundaries(case, now):
    with pytest.raises(PolicyTrustError):
        current(case, now=now)


def test_tenant_is_supplied_independently(case):
    with pytest.raises(PolicyTrustError, match="authenticated scope"):
        current(case, tenant_id="other")


@pytest.mark.parametrize(
    "bounds", [("0", "1", "2"), ("3", "2", "1"), ("01", "2", "3"), ("1", "1", "3"), ("1", "2", str(2**128))]
)
def test_policy_rejects_ambiguous_or_unordered_thresholds(case, bounds):
    with pytest.raises(ValueError):
        PilotPolicy.model_validate({**case[0].model_dump(), "tier_thresholds_usd_cents": bounds})


def test_source_provenance_is_bound_and_must_cover_policy(case):
    policy, _, _ = case
    source = policy.sources[0]
    changed = PolicySource.model_validate({**source.model_dump(), "evidence_digest": "cd" * 32})
    updated = PilotPolicy.model_validate({**policy.model_dump(), "sources": (changed,)})
    assert updated.digest != policy.digest
    with pytest.raises(ValueError, match="known policy"):
        PolicyTrustStore([updated], current_digests=(policy.digest,))
    stale = PolicySource.model_validate({**source.model_dump(), "valid_until": policy.effective_until - 1})
    with pytest.raises(ValueError, match="review intervals"):
        PilotPolicy.model_validate({**policy.model_dump(), "sources": (stale,)})
