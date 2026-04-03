"""
Integration tests for gRPC TRISA Bridge — verifies wire-format SecureEnvelope roundtrip.

These tests verify that the SecureEnvelopeBuilder produces valid TRISA wire format
that can be parsed and verified using the official protobuf definitions.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload
from src.protocol.bridges.grpc_trisa_bridge import (
    SecureEnvelopeBuilder,
    TRISAError,
    TRISAServer,
)
from src.protocol.bridges import trisa_api_pb2 as pb2
from src.protocol.bridges import trisa_errors_pb2 as errors_pb2


@pytest.fixture
def rsa_keypair():
    """Generate an RSA key pair for testing TRISA key wrapping."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key_der


@pytest.fixture
def originator_keypair():
    """Generate an originator signing key pair."""
    return rsa_keypair()


class TestSecureEnvelopeBuilder:
    """Tests for SecureEnvelopeBuilder wire format compliance."""

    def test_envelope_fields_match_proto(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Envelope has all required proto fields."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Verify all proto3 required fields are present
        assert envelope.id
        assert len(envelope.payload) > 0
        assert len(envelope.encryption_key) > 0
        assert envelope.encryption_algorithm == "AES-256-GCM"
        assert len(envelope.hmac) == 32  # SHA256 output
        assert len(envelope.hmac_secret) > 0
        assert envelope.hmac_algorithm == "HMAC-SHA256"
        assert envelope.sealed is True
        assert envelope.timestamp
        assert envelope.transfer_state == pb2.STARTED

    def test_envelope_roundtrip_decryption(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Encrypted envelope can be decrypted by the beneficiary."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Parse and decrypt
        payload = builder.parse_envelope(envelope, private_key)

        # Verify payload structure
        assert "zk_compliance_proof" in payload
        assert "encrypted_pii" in payload
        assert "pii_nonce" in payload
        assert payload["payload_version"] == "1.0"

        # Verify compliance proof data
        proof = payload["zk_compliance_proof"]
        assert proof["proof_id"] == sample_compliance_proof.proof_id
        assert proof["jurisdiction"] == sample_compliance_proof.jurisdiction

    def test_hmac_verification(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """HMAC is correctly computed and verifiable."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Unwrap HMAC secret
        hmac_secret = private_key.decrypt(
            envelope.hmac_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Recompute HMAC
        computed_hmac = builder.compute_hmac(envelope.payload, hmac_secret)

        assert computed_hmac == envelope.hmac

    def test_tamper_detection(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Tampered payload fails HMAC verification."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Tamper with the payload
        tampered_payload = envelope.payload[:-1] + bytes([envelope.payload[-1] ^ 0xFF])
        tampered_envelope = pb2.SecureEnvelope(
            id=envelope.id,
            payload=tampered_payload,
            encryption_key=envelope.encryption_key,
            encryption_algorithm=envelope.encryption_algorithm,
            hmac=envelope.hmac,
            hmac_secret=envelope.hmac_secret,
            hmac_algorithm=envelope.hmac_algorithm,
            sealed=envelope.sealed,
            timestamp=envelope.timestamp,
            transfer_state=envelope.transfer_state,
        )

        with pytest.raises(TRISAError) as exc_info:
            builder.parse_envelope(tampered_envelope, private_key)

        assert exc_info.value.code == errors_pb2.Error.INVALID_SIGNATURE

    def test_wrapped_key_format(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Wrapped encryption key is valid RSA-OAEP ciphertext."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Decrypt the wrapped key
        aes_key = private_key.decrypt(
            envelope.encryption_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        assert len(aes_key) == 32  # AES-256

    def test_payload_format(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Inner payload is valid JSON with required fields."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Parse the envelope
        payload = builder.parse_envelope(envelope, private_key)

        # Verify JSON structure
        assert isinstance(payload, dict)
        assert "zk_compliance_proof" in payload
        assert "encrypted_pii" in payload
        assert "pii_nonce" in payload
        assert "pii_associated_data" in payload
        assert "ivms101_version" in payload
        assert "payload_version" in payload

        # Verify base64 encoding
        decoded_pii = base64.b64decode(payload["encrypted_pii"])
        assert len(decoded_pii) > 0

    def test_transfer_state_values(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Envelope supports all valid TransferState values."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        for state in [pb2.STARTED, pb2.PENDING, pb2.ACCEPTED, pb2.COMPLETED, pb2.REJECTED]:
            envelope = builder.build_envelope(
                transfer_id=sample_compliance_proof.transfer_id,
                compliance_proof=sample_compliance_proof,
                hybrid_payload=sample_hybrid_payload,
                transfer_state=state,
            )
            assert envelope.transfer_state == state


class TestTRISAError:
    """Tests for TRISAError exception handling."""

    def test_from_pb2(self):
        """TRISAError can be created from protobuf Error."""
        error = errors_pb2.Error(
            code=errors_pb2.Error.UNKNOWN_WALLET_ADDRESS,
            message="Wallet address not found",
            retry=False,
        )

        trisa_error = TRISAError.from_pb2(error)

        assert trisa_error.code == errors_pb2.Error.UNKNOWN_WALLET_ADDRESS
        assert trisa_error.message == "Wallet address not found"
        assert trisa_error.retry is False

    def test_str_representation(self):
        """TRISAError has a useful string representation."""
        error_code = errors_pb2.Error.COMPLIANCE_CHECK_FAIL
        error = TRISAError(
            code=error_code,
            message="Sanctions match found",
            retry=False,
        )

        # String includes the integer error code and message
        assert str(error_code) in str(error)
        assert "Sanctions match found" in str(error)


class TestEnvelopeBuilderDirectUsage:
    """Tests for direct builder usage without fixtures."""

    def test_build_with_minimal_proof(self):
        """Builder works with minimal ComplianceProof."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        proof = ComplianceProof(
            proof_id=str(uuid.uuid4()),
            transfer_id=str(uuid.uuid4()),
            groth16_proof=base64.b64encode(b'{"pi_a":[],"pi_b":[],"pi_c":[]}').decode(),
            public_signals=["1", "0", "0", "0", "2", str(int(time.time())), "21843", "0", "25000", "300000", "1000000", "0", "0", "0", "0", str(int(time.time()) + 300)],
            verification_key=base64.b64encode(b'{"vk_alpha_1":[]}').decode(),
            originator_vasp_did="did:web:test.example.com",
            beneficiary_vasp_did="did:web:beneficiary.example.com",
            jurisdiction="US",
            amount_tier=2,
            proof_generated_at=int(time.time()),
            proof_expires_at=int(time.time()) + 300,
        )

        payload = HybridPayload(
            compliance_proof=proof,
            encrypted_pii=b"encrypted-pii-data",
            encryption_algorithm="AES-256-GCM",
            pii_nonce=b"123456789012",  # 12 bytes
            pii_associated_data="test-envelope",
        )

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=proof.transfer_id,
            compliance_proof=proof,
            hybrid_payload=payload,
        )

        assert envelope.id == proof.transfer_id
        assert envelope.sealed is True

        # Roundtrip
        parsed = builder.parse_envelope(envelope, private_key)
        assert "zk_compliance_proof" in parsed
