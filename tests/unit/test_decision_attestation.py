"""Synthetic decision signatures and independent historical key authority."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.protocol.decision_attestation import (
    DecisionAuthority,
    DecisionSignatureError,
    DecisionSigner,
    DecisionTrustError,
    DecisionTrustStore,
    SignedDecision,
)
from src.protocol.transfer import VerificationContext


@pytest.fixture
def case():
    fixture = json.loads((Path(__file__).parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    context = VerificationContext.model_validate(fixture["records"][1]["value"])
    now = context.evaluated_at
    key = Ed25519PrivateKey.generate()
    authority = DecisionAuthority(
        tenant_id=context.tenant_id,
        chain_id=int(context.deployment_chain_id),
        registry_address=context.deployment_address,
        public_key=key.public_key().public_bytes_raw().hex(),
        not_before=now,
        not_after=now + 60,
    )
    receipt = {
        "schema_version": "clearproof-local-authorization-v1",
        "tenant_id": context.tenant_id,
        "context_digest": context.digest,
        "authorized_at": now,
        "evidence_id": "ab" * 32,
        "outcome": "ALLOW",
    }
    return context, now, key, authority, receipt


def test_signature_retained_after_key_expiry(case):
    context, now, key, authority, receipt = case
    signer = DecisionSigner(authority, key)
    signed = signer.sign(receipt, context)
    DecisionTrustStore([authority]).verify(signed, receipt, context, verified_at=now + 120)
    assert key.private_bytes_raw().hex() not in repr(signer)
    assert signed.statement.clock == "operator-clock-only"


@pytest.mark.parametrize(
    "field,value", [("tenant_id", "foreign"), ("chain_id", 999), ("registry_address", "0x" + "99" * 20)]
)
def test_signer_scope_rejects(case, field, value):
    context, _, key, authority, receipt = case
    restricted = DecisionAuthority.model_validate({**authority.model_dump(), field: value})
    with pytest.raises(DecisionTrustError):
        DecisionSigner(restricted, key).sign(receipt, context)


@pytest.mark.parametrize(
    "field,value",
    [("evidence_id", "ef" * 32), ("outcome", "DENY"), ("context_digest", "ef" * 32), ("tenant_id", "foreign")],
)
def test_signed_receipt_cannot_be_rebound(case, field, value):
    context, now, key, authority, receipt = case
    signed = DecisionSigner(authority, key).sign(receipt, context)
    with pytest.raises(DecisionSignatureError):
        DecisionTrustStore([authority]).verify(signed, {**receipt, field: value}, context, verified_at=now)


def test_compromise_and_removed_key_are_not_resolved_by_claimed_time(case):
    context, now, key, authority, receipt = case
    signed = DecisionSigner(authority, key).sign(receipt, context)
    compromised = DecisionAuthority.model_validate({**authority.model_dump(), "compromised_at": now + 1})
    with pytest.raises(DecisionTrustError):
        DecisionTrustStore([compromised]).verify(signed, receipt, context, verified_at=now + 120)
    other_key = Ed25519PrivateKey.generate()
    other = DecisionAuthority.model_validate(
        {**authority.model_dump(), "public_key": other_key.public_key().public_bytes_raw().hex()}
    )
    with pytest.raises(DecisionTrustError):
        DecisionTrustStore([other]).verify(signed, receipt, context, verified_at=now + 120)
    DecisionTrustStore([authority, other]).verify(signed, receipt, context, verified_at=now + 120)


def test_purpose_and_time_checks(case):
    context, now, key, authority, receipt = case
    signed = DecisionSigner(authority, key).sign(receipt, context)
    bad = SignedDecision(
        statement=signed.statement,
        signature=key.sign(b"clearproof/information-approval/v1\0" + signed.statement.canonical_bytes()).hex(),
    )
    with pytest.raises(DecisionSignatureError):
        DecisionTrustStore([authority]).verify(bad, receipt, context, verified_at=now)
    with pytest.raises(DecisionTrustError):
        DecisionTrustStore([authority]).verify(signed, receipt, context, verified_at=now - 1)
    with pytest.raises(DecisionTrustError):
        DecisionSigner(authority, key).sign({**receipt, "authorized_at": now + 60}, context)


@pytest.mark.parametrize("offset", [0, -1])
def test_decision_authority_requires_positive_interval(case, offset):
    authority = case[3]
    with pytest.raises(ValueError, match="Invalid decision authority interval"):
        DecisionAuthority.model_validate({**authority.model_dump(), "not_after": authority.not_before + offset})


@pytest.mark.parametrize("count", [0, 2, 257])
def test_decision_inventory_rejects_missing_duplicate_and_excessive_keys(case, count):
    with pytest.raises(ValueError, match="Expected distinct independently approved decision keys"):
        DecisionTrustStore([case[3]] * count)


def test_decision_signer_rejects_mismatched_private_key(case):
    context, _, _, authority, receipt = case
    before = receipt.copy()
    with pytest.raises(DecisionTrustError, match="^Decision signing key mismatch$"):
        DecisionSigner(authority, Ed25519PrivateKey.generate()).sign(receipt, context)
    assert receipt == before
