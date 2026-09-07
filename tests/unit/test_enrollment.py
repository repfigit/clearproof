"""Actual EOA signatures authenticate the full enrollment and its audience."""

import pytest
from eth_account import Account
from fastapi import HTTPException

from src.auth.principal import Principal
from src.protocol.credential import PilotCredential, holder_commitment
from src.protocol.enrollment import EnrollmentConsent, EnrollmentError


@pytest.fixture
def enrollment():
    wallet = Account.create()
    credential = PilotCredential(
        tenant_id="tenant-a",
        credential_nonce="a" * 64,
        issuer_did="did:web:issuer.example",
        subject_wallet=wallet.address.lower(),
        holder_commitment=holder_commitment("123456"),
        jurisdiction="US",
        kyc_tier=2,
        sanctions_clear=True,
        issued_at=100,
        expires_at=1000,
    )
    consent = EnrollmentConsent(
        credential=credential, chain_id=31337, registry_address="0x" + "1" * 40, consent_expires_at=200
    )
    principal = Principal(
        tenant_id="tenant-a",
        actor_id="issuer-operator",
        roles=("credential:issue",),
        issuer_dids=("did:web:issuer.example",),
    )
    signature = "0x" + wallet.sign_message(consent.signing_message()).signature.hex()
    return consent, principal, signature


def verify(consent, principal, signature, **kwargs):
    args = dict(principal=principal, chain_id=31337, registry_address="0x" + "1" * 40, now=150)
    consent.verify(signature, **{**args, **kwargs})


def test_valid_wallet_consent(enrollment):
    verify(*enrollment)


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_id": "tenant-b"},
        {"issuer_did": "did:web:other.example"},
        {"holder_commitment": holder_commitment("654321")},
        {"jurisdiction": "GB"},
        {"credential_nonce": "b" * 64},
        {"expires_at": 1001},
        {"kyc_tier": 3},
    ],
)
def test_changed_credential_is_not_signed(enrollment, change):
    consent, principal, signature = enrollment
    credential = PilotCredential.model_validate({**consent.credential.model_dump(), **change})
    changed = EnrollmentConsent.model_validate({**consent.model_dump(), "credential": credential})
    with pytest.raises((EnrollmentError, HTTPException)):
        verify(changed, principal, signature)


@pytest.mark.parametrize(
    "change",
    [
        {"chain_id": 1},
        {"registry_address": "0x" + "2" * 40},
        {"now": 99},
        {"now": 200},
    ],
)
def test_wrong_context_or_expired_consent(enrollment, change):
    with pytest.raises(EnrollmentError):
        verify(*enrollment, **change)


def test_signature_canonicality_and_issuer_role(enrollment):
    consent, principal, signature = enrollment
    wrong = "0x" + Account.create().sign_message(consent.signing_message()).signature.hex()
    raw = bytes.fromhex(signature[2:])
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    high_s = (order - int.from_bytes(raw[32:64], "big")).to_bytes(32, "big")
    malleated = "0x" + (raw[:32] + high_s + bytes([55 - raw[64]])).hex()
    for invalid in [wrong, signature.upper(), "0x" + "0" * 130, signature[:-2] + "00", malleated]:
        with pytest.raises(EnrollmentError):
            verify(consent, principal, invalid)
    for change in [{"roles": ("tenant:admin",)}, {"issuer_dids": ()}]:
        unauthorized = Principal.model_validate({**principal.model_dump(), **change})
        with pytest.raises(HTTPException) as err:
            verify(consent, unauthorized, signature)
        assert err.value.status_code == 403
