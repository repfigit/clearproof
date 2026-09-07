"""Real signature validation for scoped quote provenance, distinct from pricing truth."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.protocol.transfer import AssetDefinition, AssetRegistry, Transfer
from src.protocol.valuation_approval import (
    SignedValuationApproval,
    ValuationApproval,
    ValuationAuthority,
    ValuationTrustError,
    ValuationTrustStore,
    sign_valuation,
)


@pytest.fixture
def case():
    root = Path(__file__).resolve().parents[2]
    fixture = json.loads((root / "specs/fixtures/transfer-v1.json").read_text())
    transfer = Transfer.model_validate(fixture["records"][0]["value"])
    registry = AssetRegistry([AssetDefinition.model_validate(a) for a in fixture["assets"]])
    key = Ed25519PrivateKey.generate()
    authority = ValuationAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id=transfer.tenant_id,
        asset_registry_digest=registry.digest,
        asset_ids=(transfer.asset_id,),
        source_ids=(transfer.valuation.source_id,),
        not_before=transfer.created_at,
        not_after=transfer.valuation.expires_at,
        max_quote_lifetime_seconds=600,
        max_observation_age_seconds=300,
    )
    approval = ValuationApproval(
        tenant_id=transfer.tenant_id,
        asset_registry_digest=registry.digest,
        valuation=transfer.valuation,
        signed_at=transfer.created_at,
        key_id=authority.key_id,
    )
    return key, authority, sign_valuation(approval, key), transfer, registry


def verify(case, **kwargs):
    _, authority, signed, transfer, registry = case
    return ValuationTrustStore([authority]).verify_for_transfer(
        signed,
        transfer,
        registry,
        tenant_id=transfer.tenant_id,
        **{"now": transfer.created_at + 10, **kwargs},
    )


def test_real_approval_and_exact_age_boundary(case):
    _, _, signed, transfer, _ = case
    assert verify(case) == signed.approval
    assert verify(case, now=transfer.created_at + 300) == signed.approval
    assert transfer.originator.wallet not in repr(signed)
    assert signed.signature not in repr(signed)


@pytest.mark.parametrize("offset", [-1, 301, 600])
def test_future_stale_and_expired_quotes_fail(case, offset):
    with pytest.raises(ValuationTrustError):
        verify(case, now=case[3].created_at + offset)


def test_future_signature_rejected_before_observation_age_check(case):
    key, authority, signed, transfer, registry = case
    approval = ValuationApproval.model_validate({**signed.approval.model_dump(), "signed_at": transfer.created_at + 20})
    with pytest.raises(ValuationTrustError):
        verify((key, authority, sign_valuation(approval, key), transfer, registry))


@pytest.mark.parametrize("scope", ["tenant", "asset", "source", "catalog", "lifetime", "age", "start", "end"])
def test_authority_scope_is_enforced(case, scope):
    key, authority, signed, transfer, registry = case
    changes = {
        "tenant": {"tenant_id": "tenant-other"},
        "asset": {"asset_ids": (transfer.asset_id.replace("31337", "31338"),)},
        "source": {"source_ids": ("unapproved-source",)},
        "catalog": {"asset_registry_digest": "aa" * 32},
        "lifetime": {"max_quote_lifetime_seconds": 599},
        "age": {"max_observation_age_seconds": 9},
        "start": {"not_before": transfer.created_at + 1},
        "end": {"not_after": transfer.valuation.expires_at - 1},
    }[scope]
    altered = ValuationAuthority.model_validate({**authority.model_dump(), **changes})
    with pytest.raises(ValuationTrustError, match="no trusted authority"):
        verify((key, altered, signed, transfer, registry))


@pytest.mark.parametrize(
    "field,value", [("numerator", "2"), ("source_evidence_digest", "ab" * 32), ("observed_at", 1788649999)]
)
def test_consistent_transfer_and_quote_forgery_still_needs_signature(case, field, value):
    key, authority, signed, transfer, registry = case
    quote = {**transfer.valuation.model_dump(), field: value}
    # The ratio must remain reduced; choose 3/10000 for the forged rate.
    if field == "numerator":
        quote[field] = "3"
    changed_transfer = Transfer.model_validate(
        {
            **transfer.model_dump(),
            "valuation": quote,
            "usd_cents": str(int(transfer.amount_base_units) * int(quote["numerator"]) // int(quote["denominator"])),
        }
    )
    forged = SignedValuationApproval.model_validate(
        {
            "approval": {**signed.approval.model_dump(), "valuation": quote},
            "signature": signed.signature,
        }
    )
    # Expand observation scope for this test so the forged signature is reached.
    authority = ValuationAuthority.model_validate(
        {**authority.model_dump(), "not_before": transfer.created_at - 1, "max_quote_lifetime_seconds": 601}
    )
    with pytest.raises(ValuationTrustError, match="signature is invalid"):
        verify((key, authority, forged, changed_transfer, registry))


def test_cannot_borrow_a_quote_for_another_transfer_value(case):
    key, authority, signed, transfer, registry = case
    quote = {**transfer.valuation.model_dump(), "source_evidence_digest": "ab" * 32}
    changed = Transfer.model_validate({**transfer.model_dump(), "valuation": quote})
    with pytest.raises(ValuationTrustError, match="does not bind"):
        verify((key, authority, signed, changed, registry))


def test_authenticated_tenant_is_independent_of_signed_payload(case):
    _, authority, signed, transfer, registry = case
    with pytest.raises(ValuationTrustError, match="does not bind"):
        ValuationTrustStore([authority]).verify_for_transfer(
            signed,
            transfer,
            registry,
            tenant_id="tenant-other",
            now=transfer.created_at + 10,
        )


def test_key_rotation_overlap_and_removal(case):
    _, old, signed, transfer, registry = case
    key = Ed25519PrivateKey.generate()
    new = ValuationAuthority.model_validate(
        {**old.model_dump(), "public_key": key.public_key().public_bytes_raw().hex()}
    )
    approval = ValuationApproval.model_validate({**signed.approval.model_dump(), "key_id": new.key_id})
    new_signed = sign_valuation(approval, key)
    args = {"tenant_id": transfer.tenant_id, "now": transfer.created_at + 10}
    overlap = ValuationTrustStore([old, new])
    assert overlap.verify_for_transfer(signed, transfer, registry, **args) == signed.approval
    assert overlap.verify_for_transfer(new_signed, transfer, registry, **args) == approval
    with pytest.raises(ValuationTrustError, match="no trusted authority"):
        ValuationTrustStore([new]).verify_for_transfer(signed, transfer, registry, **args)


def test_cross_protocol_signature_and_wrong_signing_key_rejected(case):
    key, authority, signed, transfer, registry = case
    other = SignedValuationApproval(
        approval=signed.approval,
        signature=key.sign(b"clearproof/root-approval/v1\0" + signed.approval.canonical_bytes()).hex(),
    )
    with pytest.raises(ValuationTrustError, match="signature is invalid"):
        verify((key, authority, other, transfer, registry))
    with pytest.raises(ValuationTrustError, match="Signing key"):
        sign_valuation(signed.approval, Ed25519PrivateKey.generate())


def test_historical_compromise_and_key_expiry(case):
    _, authority, signed, transfer, registry = case
    args = dict(tenant_id=transfer.tenant_id, now=transfer.created_at + 10)
    review_at = transfer.expires_at + 100
    ValuationTrustStore([authority]).verify_for_transfer(signed, transfer, registry, **args, verified_at=review_at)
    compromised = ValuationAuthority.model_validate({**authority.model_dump(), "compromised_at": args["now"] + 1})
    for authorities in ([compromised], [authority, compromised], [compromised, authority]):
        with pytest.raises(ValuationTrustError, match="compromise"):
            ValuationTrustStore(authorities).verify_for_transfer(
                signed, transfer, registry, **args, verified_at=review_at
            )
        with pytest.raises(ValuationTrustError, match="compromise"):
            ValuationTrustStore(authorities).verify_for_transfer(
                signed,
                transfer,
                registry,
                **{**args, "now": args["now"] + 2},
            )
    with pytest.raises(ValuationTrustError):
        ValuationTrustStore([authority]).verify_for_transfer(signed, transfer, registry, **args, verified_at=True)


def test_authenticated_current_cutoff_matches_age_and_compromise(case):
    _, authority, signed, transfer, registry = case
    trust = ValuationTrustStore([authority])
    args = dict(tenant_id=transfer.tenant_id, now=transfer.created_at + 10)
    cutoff = trust.current_valid_until(signed, transfer, registry, **args)
    assert cutoff == transfer.valuation.observed_at + authority.max_observation_age_seconds + 1
    assert trust.verify_for_transfer(signed, transfer, registry, **{**args, "now": cutoff - 1}) == signed.approval
    with pytest.raises(ValuationTrustError):
        trust.current_valid_until(signed, transfer, registry, **{**args, "now": cutoff})
    compromised = authority.model_copy(update={"compromised_at": args["now"] + 1})
    assert ValuationTrustStore([compromised]).current_valid_until(signed, transfer, registry, **args) == args["now"] + 1
