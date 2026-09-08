"""Independent status delegation checks over synthetic, genuinely signed receipts."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.protocol.canonical import record_digest
from src.protocol.credential import PilotCredential
from src.protocol.decision_attestation import DecisionAuthority, DecisionSigner, DecisionTrustError
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.transfer import VerificationContext
from src.prover.history_status import HistoryStatusAuthority, HistoryStatusTrust, status_registry_id


@pytest.fixture
def case():
    data = json.loads((Path(__file__).parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    context = VerificationContext.model_validate(data["records"][1]["value"])
    now = context.evaluated_at
    key = Ed25519PrivateKey.generate()
    authority = HistoryStatusAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id=context.tenant_id,
        chain_id=int(context.deployment_chain_id),
        registry_address=context.deployment_address,
        not_before=now,
        not_after=now + 60,
        registry_id=status_registry_id(context),
        issuer_did="did:web:synthetic.example",
    )
    credential = PilotCredential(
        tenant_id=context.tenant_id,
        credential_nonce="ab" * 32,
        issuer_did=authority.issuer_did,
        subject_wallet="0x" + "12" * 20,
        holder_commitment="1",
        jurisdiction="US",
        kyc_tier=2,
        sanctions_clear=True,
        issued_at=now - 1,
        expires_at=now + 60,
    )
    consent = EnrollmentConsent(
        credential=credential,
        chain_id=int(context.deployment_chain_id),
        registry_address=context.deployment_address,
        consent_expires_at=now + 30,
    )
    manifest = {
        "captured_at": now,
        "credential_status": {
            "schema_version": "clearproof-local-status-observation-v1",
            "registry_id": authority.registry_id,
            "credential_id": credential.credential_nonce,
            "issuer_did": credential.issuer_did,
            "revocation": "not-present-in-local-store",
            "observed_at": now,
        },
    }
    receipt = {
        "schema_version": "clearproof-local-authorization-v1",
        "tenant_id": context.tenant_id,
        "context_digest": context.digest,
        "authorized_at": now,
        "outcome": "ALLOW",
        "evidence_id": record_digest("clearproof/authorization-evidence/v1", manifest),
    }
    decision_authority = DecisionAuthority.model_validate(
        authority.model_dump(include=set(DecisionAuthority.model_fields))
    )
    signed = DecisionSigner(decision_authority, key).sign(receipt, context)
    bundle = {
        "proof": {
            "context": context.model_dump(mode="json"),
            "credential_id": credential.credential_nonce,
            "decision_attestation": signed.model_dump(mode="json"),
        },
        "receipt": receipt,
        "evidence_manifest": manifest,
        "records": [
            {
                "kind": "credential",
                "record_id": credential.credential_nonce,
                "value": {"consent": consent.model_dump(mode="json")},
            }
        ],
    }
    return authority, bundle, now


def test_status_delegation_verifies_real_signature_after_key_expiry(case):
    authority, bundle, now = case
    # Status verification assumes outer reconstruction already checked enrollment.
    HistoryStatusTrust([authority]).verify(bundle, verified_at=now + 120)


@pytest.mark.parametrize("inventory", ["empty", "duplicate", "oversized"])
def test_status_authority_inventory_requires_distinct_bounded_scopes(case, inventory):
    authority, _, _ = case
    authorities = [] if inventory == "empty" else [authority] * (2 if inventory == "duplicate" else 257)
    with pytest.raises(ValueError, match="distinct independently approved status authorities"):
        HistoryStatusTrust(authorities)


def test_status_authority_requires_canonical_issuer(case):
    authority, _, _ = case
    with pytest.raises(ValueError, match="Expected canonical issuer identity"):
        HistoryStatusAuthority.model_validate({**authority.model_dump(), "issuer_did": "synthetic.example"})


@pytest.mark.parametrize("duplicate", [False, True])
def test_status_requires_exact_credential_record(case, duplicate):
    authority, bundle, now = case
    bundle["records"] = bundle["records"] * 2 if duplicate else []
    with pytest.raises(ValueError, match="Required credential evidence is unavailable"):
        HistoryStatusTrust([authority]).verify(bundle, verified_at=now)


@pytest.mark.parametrize(
    "field,value", [("credential_nonce", "cd" * 32), ("issuer_did", "did:web:other.example"), ("tenant_id", "other")]
)
def test_status_rejects_credential_scope_substitution(case, field, value):
    authority, bundle, now = case
    bundle["records"][0]["value"]["consent"]["credential"][field] = value
    with pytest.raises(ValueError, match="Status observation credential scope mismatch"):
        HistoryStatusTrust([authority]).verify(bundle, verified_at=now)


def test_compromised_status_delegation_is_not_restored_by_claimed_old_time(case):
    authority, bundle, now = case
    compromised = HistoryStatusAuthority.model_validate({**authority.model_dump(), "compromised_at": now + 1})
    with pytest.raises(DecisionTrustError):
        HistoryStatusTrust([compromised]).verify(bundle, verified_at=now + 120)


def test_changed_manifest_is_not_accepted_as_original_signed_status(case):
    authority, bundle, now = case
    candidate = deepcopy(bundle)
    candidate["evidence_manifest"]["credential_status"]["revocation"] = "present"
    with pytest.raises(ValueError, match="Required historical status observation is unavailable"):
        HistoryStatusTrust([authority]).verify(candidate, verified_at=now)
    HistoryStatusTrust([authority]).verify(bundle, verified_at=now)


def test_status_authority_must_be_independently_delegated_to_registry(case):
    authority, bundle, now = case
    different = HistoryStatusAuthority.model_validate({**authority.model_dump(), "registry_id": "cd" * 32})
    with pytest.raises(ValueError, match="Historical status authority unavailable"):
        HistoryStatusTrust([different]).verify(bundle, verified_at=now)
