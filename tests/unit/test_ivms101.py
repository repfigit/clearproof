"""
Model validation tests for IVMS101 ZK protocol models.

Tests ComplianceProof, HybridPayload, ZKIvms101Originator, and
ZKIvms101Message creation, serialization, and validation logic.
"""

from __future__ import annotations

import base64
import time
import uuid

import pytest
from pydantic import ValidationError

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload
from src.protocol.ivms101 import ZKIvms101Originator, ZKIvms101Message


# ---------------------------------------------------------------------------
# ComplianceProof tests
# ---------------------------------------------------------------------------

class TestComplianceProof:
    def test_creation(self, sample_compliance_proof: ComplianceProof):
        """ComplianceProof can be created with valid fields."""
        assert sample_compliance_proof.proof_id is not None
        assert sample_compliance_proof.transfer_id is not None
        assert sample_compliance_proof.amount_tier == 2
        assert sample_compliance_proof.jurisdiction == "US"

    def test_serialization_roundtrip(self, sample_compliance_proof: ComplianceProof):
        """ComplianceProof can be serialized to dict and back."""
        data = sample_compliance_proof.model_dump()
        restored = ComplianceProof(**data)
        assert restored.proof_id == sample_compliance_proof.proof_id
        assert restored.transfer_id == sample_compliance_proof.transfer_id
        assert restored.public_signals == sample_compliance_proof.public_signals
        assert restored.amount_tier == sample_compliance_proof.amount_tier

    def test_json_roundtrip(self, sample_compliance_proof: ComplianceProof):
        """ComplianceProof can be serialized to JSON and back."""
        json_str = sample_compliance_proof.model_dump_json()
        restored = ComplianceProof.model_validate_json(json_str)
        assert restored.proof_id == sample_compliance_proof.proof_id

    def test_amount_tier_validation_min(self):
        """amount_tier must be >= 1."""
        with pytest.raises(ValidationError):
            ComplianceProof(
                proof_id="test",
                transfer_id="test",
                groth16_proof="dGVzdA==",
                public_signals=["1"],
                verification_key="dGVzdA==",
                originator_vasp_did="did:web:test.com",
                jurisdiction="US",
                amount_tier=0,  # invalid
                proof_generated_at=int(time.time()),
            )

    def test_amount_tier_validation_max(self):
        """amount_tier must be <= 4."""
        with pytest.raises(ValidationError):
            ComplianceProof(
                proof_id="test",
                transfer_id="test",
                groth16_proof="dGVzdA==",
                public_signals=["1"],
                verification_key="dGVzdA==",
                originator_vasp_did="did:web:test.com",
                jurisdiction="US",
                amount_tier=5,  # invalid
                proof_generated_at=int(time.time()),
            )

    def test_default_expiry(self):
        """proof_expires_at defaults to proof_generated_at + 300."""
        now = int(time.time())
        proof = ComplianceProof(
            proof_id="test",
            transfer_id="test",
            groth16_proof="dGVzdA==",
            public_signals=["1"],
            verification_key="dGVzdA==",
            originator_vasp_did="did:web:test.com",
            jurisdiction="US",
            amount_tier=2,
            proof_generated_at=now,
        )
        assert proof.proof_expires_at == now + 300

    def test_is_expired_false(self, sample_compliance_proof: ComplianceProof):
        """A freshly created proof should not be expired."""
        assert sample_compliance_proof.is_expired is False

    def test_is_expired_true(self):
        """A proof with expires_at in the past should be expired."""
        past = int(time.time()) - 600
        proof = ComplianceProof(
            proof_id="test",
            transfer_id="test",
            groth16_proof="dGVzdA==",
            public_signals=["1"],
            verification_key="dGVzdA==",
            originator_vasp_did="did:web:test.com",
            jurisdiction="US",
            amount_tier=2,
            proof_generated_at=past - 300,
            proof_expires_at=past,
        )
        assert proof.is_expired is True


# ---------------------------------------------------------------------------
# HybridPayload tests
# ---------------------------------------------------------------------------

class TestHybridPayload:
    def test_creation(self, sample_hybrid_payload: HybridPayload):
        """HybridPayload can be created with valid fields."""
        assert sample_hybrid_payload.encrypted_pii is not None
        assert sample_hybrid_payload.encryption_algorithm == "AES-256-GCM"
        assert len(sample_hybrid_payload.pii_nonce) == 12

    def test_nonce_validation(self, sample_compliance_proof: ComplianceProof):
        """pii_nonce must be exactly 12 bytes."""
        with pytest.raises(ValidationError):
            HybridPayload(
                compliance_proof=sample_compliance_proof,
                encrypted_pii=b"ciphertext",
                pii_nonce=b"short",  # not 12 bytes
                pii_associated_data="env-001",
            )

    def test_to_trp_extension(self, sample_hybrid_payload: HybridPayload):
        """to_trp_extension returns a dict with zk_travel_rule key."""
        ext = sample_hybrid_payload.to_trp_extension()
        assert "zk_travel_rule" in ext
        zk = ext["zk_travel_rule"]
        assert zk["version"] == "1.0"
        assert "compliance_proof" in zk
        assert "encrypted_pii" in zk

    def test_to_trisa_envelope(self, sample_hybrid_payload: HybridPayload):
        """to_trisa_envelope returns a dict with expected TRISA fields."""
        env = sample_hybrid_payload.to_trisa_envelope()
        assert "id" in env
        assert "payload" in env
        assert "encryption_algorithm" in env
        assert env["transfer_state"] == "PENDING"
        assert "zk_compliance_proof" in env["extensions"]


# ---------------------------------------------------------------------------
# ZKIvms101Originator tests
# ---------------------------------------------------------------------------

class TestZKIvms101Originator:
    def test_creation(self):
        """ZKIvms101Originator can be created with required fields."""
        orig = ZKIvms101Originator(
            account_number="0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            zk_proof_ref="proof-123",
            zk_verification_endpoint="https://verifier.example.com/verify",
        )
        assert orig.account_number.startswith("0x")
        assert orig.zk_proof_ref == "proof-123"
        assert orig.encrypted_natural_person is None

    def test_with_encrypted_pii(self):
        """ZKIvms101Originator can include encrypted PII."""
        orig = ZKIvms101Originator(
            account_number="0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            zk_proof_ref="proof-123",
            zk_verification_endpoint="https://verifier.example.com/verify",
            encrypted_natural_person="base64encrypteddata==",
        )
        assert orig.encrypted_natural_person is not None


# ---------------------------------------------------------------------------
# ZKIvms101Message tests
# ---------------------------------------------------------------------------

class TestZKIvms101Message:
    def test_creation(self, sample_compliance_proof: ComplianceProof):
        """ZKIvms101Message can be created with full fields."""
        originator = ZKIvms101Originator(
            account_number="0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            zk_proof_ref=sample_compliance_proof.proof_id,
            zk_verification_endpoint="https://verifier.example.com/verify",
        )
        msg = ZKIvms101Message(
            originator=originator,
            beneficiary_account_number="0x9876543210fedcba9876543210fedcba98765432",
            originating_vasp_did="did:web:originator.example.com",
            beneficiary_vasp_did="did:web:beneficiary.example.com",
            transfer_amount="1500.00",
            asset_type="USDC",
            compliance_proof=sample_compliance_proof,
        )
        assert msg.originator.zk_proof_ref == sample_compliance_proof.proof_id
        assert msg.transfer_amount == "1500.00"
        assert msg.asset_type == "USDC"
        assert msg.compliance_proof is not None

    def test_without_compliance_proof(self):
        """ZKIvms101Message can be created without a compliance proof."""
        originator = ZKIvms101Originator(
            account_number="0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            zk_proof_ref="proof-123",
            zk_verification_endpoint="https://verifier.example.com/verify",
        )
        msg = ZKIvms101Message(
            originator=originator,
            beneficiary_account_number="0x9876543210fedcba9876543210fedcba98765432",
            originating_vasp_did="did:web:originator.example.com",
            transfer_amount="500.00",
            asset_type="ETH",
        )
        assert msg.compliance_proof is None
        assert msg.beneficiary_vasp_did is None

    def test_serialization_roundtrip(self, sample_compliance_proof: ComplianceProof):
        """ZKIvms101Message can be serialized and deserialized."""
        originator = ZKIvms101Originator(
            account_number="0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            zk_proof_ref=sample_compliance_proof.proof_id,
            zk_verification_endpoint="https://verifier.example.com/verify",
        )
        msg = ZKIvms101Message(
            originator=originator,
            beneficiary_account_number="0x9876543210fedcba9876543210fedcba98765432",
            originating_vasp_did="did:web:originator.example.com",
            transfer_amount="1500.00",
            asset_type="USDC",
            compliance_proof=sample_compliance_proof,
        )
        data = msg.model_dump()
        restored = ZKIvms101Message(**data)
        assert restored.originator.zk_proof_ref == msg.originator.zk_proof_ref
        assert restored.transfer_amount == msg.transfer_amount
