"""
Shared pytest fixtures for the ZK Travel Rule Compliance Bridge test suite.

Provides reusable fixtures for credentials, compliance proofs, mock provers,
and encryption keys across unit, integration, and compliance tests.
"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Auth configuration is read at import time. Establish the synthetic test
# defaults before any test module imports the API, regardless of collection order.
os.environ.setdefault("PII_MASTER_KEY", "a" * 64)
os.environ.setdefault("AUTH_MODE", "api-key")
os.environ.setdefault("API_KEY", "test-api-key-for-integration")

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload
from src.registry.credential_registry import CredentialRegistry, zkKYCCredential
from src.sar.encryption import derive_key

# ---------------------------------------------------------------------------
# Encryption fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_master_key() -> bytes:
    """32-byte random master key for encryption tests."""
    return os.urandom(32)


@pytest.fixture
def sample_derived_key(sample_master_key: bytes) -> bytes:
    """Derived AES-256 key from the sample master key."""
    return derive_key(sample_master_key, context=b"test-envelope-001")


# ---------------------------------------------------------------------------
# Credential fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_credential() -> dict:
    """A dict with credential fields for testing."""
    now = int(time.time())
    return {
        "credential_id": str(uuid.uuid4()),
        "issuer_did": "did:web:kyc-provider.example.com",
        "subject_wallet": "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
        "jurisdiction": "US",
        "kyc_tier": "retail",
        "sanctions_clear": True,
        "issued_at": now - 3600,
        "expires_at": now + 86400,
        "revoked": False,
    }


@pytest.fixture
def sample_zkkyc_credential(sample_credential: dict) -> zkKYCCredential:
    """A valid, non-revoked zkKYC credential for testing."""
    return zkKYCCredential(**sample_credential)


@pytest.fixture
def revoked_credential() -> zkKYCCredential:
    """A revoked zkKYC credential for testing rejection paths."""
    now = int(time.time())
    return zkKYCCredential(
        credential_id=str(uuid.uuid4()),
        issuer_did="did:web:kyc-provider.example.com",
        subject_wallet="0x1111111111111111111111111111111111111111",
        jurisdiction="US",
        kyc_tier="retail",
        sanctions_clear=True,
        issued_at=now - 3600,
        expires_at=now + 86400,
        revoked=True,
    )


@pytest.fixture
def expired_credential() -> zkKYCCredential:
    """An expired zkKYC credential for testing expiry paths."""
    now = int(time.time())
    return zkKYCCredential(
        credential_id=str(uuid.uuid4()),
        issuer_did="did:web:kyc-provider.example.com",
        subject_wallet="0x2222222222222222222222222222222222222222",
        jurisdiction="US",
        kyc_tier="retail",
        sanctions_clear=True,
        issued_at=now - 172800,
        expires_at=now - 3600,  # expired 1 hour ago
        revoked=False,
    )


# ---------------------------------------------------------------------------
# Compliance proof fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_compliance_proof() -> ComplianceProof:
    """A valid ComplianceProof instance for testing."""
    now = int(time.time())
    return ComplianceProof(
        proof_id=str(uuid.uuid4()),
        transfer_id=str(uuid.uuid4()),
        groth16_proof=base64.b64encode(b'{"pi_a":[],"pi_b":[],"pi_c":[]}').decode(),
        public_signals=[
            "1",
            "0",
            "0",
            "0",
            "2",
            str(now),
            "21843",
            "0",
            "25000",
            "300000",
            "1000000",
            "0",
            "0",
            "0",
            "0",
            str(now + 300),
        ],
        verification_key=base64.b64encode(b'{"vk_alpha_1":[]}').decode(),
        originator_vasp_did="did:web:originator.example.com",
        beneficiary_vasp_did="did:web:beneficiary.example.com",
        jurisdiction="US",
        amount_tier=2,
        proof_generated_at=now,
        proof_expires_at=now + 300,
        sar_review_flag=False,
    )


@pytest.fixture
def sample_hybrid_payload(
    sample_compliance_proof: ComplianceProof,
    sample_derived_key: bytes,
) -> HybridPayload:
    """A valid HybridPayload with encrypted PII for testing."""
    from src.sar.encryption import encrypt_pii

    pii_data = json.dumps(
        {
            "originator_name": "Test User",
            "originator_address": "123 Main St",
        }
    ).encode()

    envelope_id = sample_compliance_proof.transfer_id
    nonce, ciphertext = encrypt_pii(pii_data, sample_derived_key, envelope_id)

    return HybridPayload(
        compliance_proof=sample_compliance_proof,
        encrypted_pii=ciphertext,
        encryption_algorithm="AES-256-GCM",
        pii_nonce=nonce,
        pii_associated_data=envelope_id,
    )


# ---------------------------------------------------------------------------
# Mock prover fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_prover():
    """
    A mock SnarkJSProver that returns deterministic proof data
    without requiring Node.js or circuit artifacts.

    Patches subprocess calls so no external processes are spawned.
    """
    prover = MagicMock()

    # Mock fullprove to return a valid-looking proof + public signals
    mock_proof = {
        "pi_a": ["1234", "5678", "1"],
        "pi_b": [["1111", "2222"], ["3333", "4444"], ["1", "0"]],
        "pi_c": ["9999", "8888", "1"],
        "protocol": "groth16",
        "curve": "bn128",
        "_meta": {"proving_time_ms": 1500},
    }
    mock_public_signals = [
        "1",
        "0",
        "0",
        "0",
        "2",
        "1711670400",
        "21843",
        "0",
        "25000",
        "300000",
        "1000000",
        "0",
        "0",
        "0",
        "0",
        "1711670700",
    ]

    prover.fullprove = AsyncMock(return_value=(mock_proof, mock_public_signals))
    prover.verify = AsyncMock(return_value=True)

    # Also expose the raw data for test assertions
    prover._mock_proof = mock_proof
    prover._mock_public_signals = mock_public_signals

    return prover


# ---------------------------------------------------------------------------
# Registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def credential_registry() -> CredentialRegistry:
    """A fresh in-memory credential registry."""
    return CredentialRegistry()


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _set_test_env(tmp_path):
    """Set environment variables for test isolation."""
    artifacts_dir = str(tmp_path / "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)
    with patch.dict(
        os.environ,
        {
            "ZK_ARTIFACTS_DIR": artifacts_dir,
            "VASP_DID": "did:web:test-vasp.example.com",
        },
    ):
        yield


@pytest.fixture
def wallet_enrollment():
    """Synthetic EOA and enrollment shared by wallet-extension boundary tests."""
    from eth_account import Account

    from src.auth.principal import Principal
    from src.protocol.credential import PilotCredential, holder_commitment
    from src.protocol.enrollment import EnrollmentConsent

    wallet = Account.create()
    credential = PilotCredential(
        tenant_id="wallet-tenant",
        credential_nonce="ab" * 32,
        issuer_did="did:web:issuer.example",
        subject_wallet=wallet.address.lower(),
        holder_commitment=holder_commitment("123456"),
        jurisdiction="US",
        kyc_tier=2,
        sanctions_clear=True,
        issued_at=1000,
        expires_at=200000,
    )
    consent = EnrollmentConsent(
        credential=credential, chain_id=31337, registry_address="0x" + "1" * 40, consent_expires_at=1500
    )
    principal = Principal(
        tenant_id=credential.tenant_id,
        actor_id="issuer-actor",
        roles=("credential:issue", "credential:revoke", "evidence:decrypt"),
        issuer_dids=(credential.issuer_did,),
    )
    return wallet, consent, principal
