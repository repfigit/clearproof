"""Real signatures over synthetic private information, with independent trust."""

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.protocol.information_approval import (
    InformationApproval,
    InformationAuthority,
    InformationTrustStore,
    SignedInformationApproval,
    sign_information,
)
from src.protocol.transfer import Transfer, VerificationContext


@pytest.fixture
def case():
    fixture = json.loads((Path(__file__).parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    transfer = Transfer.model_validate(fixture["records"][0]["value"])
    context = VerificationContext.model_validate(fixture["records"][1]["value"])
    now = context.evaluated_at
    key = Ed25519PrivateKey.generate()
    authority = InformationAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id=transfer.tenant_id,
        chain_id=int(context.deployment_chain_id),
        registry_address=context.deployment_address,
        source_ids=("synthetic-kyc",),
        not_before=now,
        not_after=now + 60,
        max_lifetime_seconds=60,
    )
    payload = b"synthetic-bytes-only"
    approval = InformationApproval(
        tenant_id=transfer.tenant_id,
        transfer_digest=transfer.digest,
        context_digest=context.digest,
        credential_id="ab" * 32,
        payload_digest=hashlib.sha256(payload).hexdigest(),
        source_id="synthetic-kyc",
        source_evidence_digest="cd" * 32,
        signed_at=now,
        expires_at=now + 60,
        key_id=authority.key_id,
    )
    return transfer, context, now, key, authority, payload, approval


def verify(case, signed=None, authority=None, payload=None, now=None, credential_id="ab" * 32):
    transfer, context, clock, key, trusted, original, approval = case
    return InformationTrustStore([authority or trusted]).verify(
        signed or sign_information(approval, key),
        original if payload is None else payload,
        transfer,
        context,
        credential_id=credential_id,
        now=clock if now is None else now,
    )


def test_valid_approval_and_rotation(case):
    assert verify(case) is None
    _, _, _, key, authority, _, approval = case
    replacement = Ed25519PrivateKey.generate()
    other = InformationAuthority.model_validate(
        {**authority.model_dump(), "public_key": replacement.public_key().public_bytes_raw().hex()}
    )
    trust = InformationTrustStore([authority, other])
    transfer, context, now, _, _, payload, _ = case
    trust.verify(sign_information(approval, key), payload, transfer, context, credential_id="ab" * 32, now=now)
    updated = InformationApproval.model_validate({**approval.model_dump(), "key_id": other.key_id})
    trust.verify(sign_information(updated, replacement), payload, transfer, context, credential_id="ab" * 32, now=now)
    with pytest.raises(ValueError, match="authority"):
        verify(case, authority=other)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "foreign"),
        ("transfer_digest", "ef" * 32),
        ("context_digest", "ef" * 32),
        ("credential_id", "ef" * 32),
        ("payload_digest", "ef" * 32),
        ("source_id", "untrusted-source"),
    ],
)
def test_even_valid_signatures_must_bind_scope(case, field, value):
    approval = InformationApproval.model_validate({**case[-1].model_dump(), field: value})
    with pytest.raises(ValueError, match="authority"):
        verify(case, signed=sign_information(approval, case[3]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "foreign"),
        ("chain_id", 999),
        ("registry_address", "0x" + "99" * 20),
        ("source_ids", ("other-source",)),
        ("max_lifetime_seconds", 1),
    ],
)
def test_independent_key_authority_restricts_approval(case, field, value):
    authority = InformationAuthority.model_validate({**case[4].model_dump(), field: value})
    with pytest.raises(ValueError, match="authority"):
        verify(case, authority=authority)


@pytest.mark.parametrize("offset", [-1, 60, 61])
def test_current_time_bounds(case, offset):
    with pytest.raises(ValueError, match="authority"):
        verify(case, now=case[2] + offset)


def test_payload_and_credential_substitution(case):
    for payload in (b"changed-synthetic-bytes", case[5] + b" ", b"", b"x" * 32769):
        with pytest.raises(ValueError, match="authority"):
            verify(case, payload=payload)
    with pytest.raises(ValueError, match="authority"):
        verify(case, credential_id="ef" * 32)


def test_tampering_and_purpose_separation(case):
    approval, key = case[-1], case[3]
    signed = sign_information(approval, key)
    changed = InformationApproval.model_validate({**approval.model_dump(), "source_evidence_digest": "ef" * 32})
    with pytest.raises(ValueError, match="signature"):
        verify(case, signed=SignedInformationApproval(approval=changed, signature=signed.signature))
    wrong_purpose = key.sign(b"clearproof/fact-approval/v1\0" + approval.canonical_bytes()).hex()
    with pytest.raises(ValueError, match="signature"):
        verify(case, signed=SignedInformationApproval(approval=approval, signature=wrong_purpose))
    with pytest.raises(ValueError, match="key mismatch"):
        sign_information(approval, Ed25519PrivateKey.generate())
