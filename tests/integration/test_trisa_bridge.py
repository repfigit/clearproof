"""
Integration tests for TRISA bridge — verifies SecureEnvelope roundtrip.

Tests that TRISABridge.build_secure_envelope produces a valid TRISA
SecureEnvelope that can be decrypted with the beneficiary's private key.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload
from src.protocol.bridges.trisa_bridge import TRISABridge


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


class TestTRISABridge:
    """Tests for TRISA SecureEnvelope building and decryption."""

    def test_envelope_structure(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """build_secure_envelope returns a dict with all required TRISA fields."""
        _, public_key_der = rsa_keypair
        bridge = TRISABridge()

        envelope = bridge.build_secure_envelope(
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
            beneficiary_public_key=public_key_der,
        )

        assert "encrypted_payload" in envelope
        assert "encryption_algorithm" in envelope
        assert "wrapped_key" in envelope
        assert "hmac_signature" in envelope
        assert "override_header" in envelope

        assert envelope["encryption_algorithm"] == "AES256_GCM"
        assert envelope["hmac_signature"] == ""  # computed by TRISA SDK
        assert envelope["override_header"]["envelope_type"] == "ZK_TRAVEL_RULE_V1"

    def test_envelope_roundtrip(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Encrypted payload can be decrypted with the beneficiary private key."""
        private_key, public_key_der = rsa_keypair
        bridge = TRISABridge()

        envelope = bridge.build_secure_envelope(
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
            beneficiary_public_key=public_key_der,
        )

        # Unwrap the AES key using the private key
        wrapped_key_bytes = bytes.fromhex(envelope["wrapped_key"])
        aes_key = private_key.decrypt(
            wrapped_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        assert len(aes_key) == 32

        # Decrypt the payload
        encrypted_payload_bytes = bytes.fromhex(envelope["encrypted_payload"])
        nonce = encrypted_payload_bytes[:12]
        ciphertext = encrypted_payload_bytes[12:]

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Parse decrypted payload
        payload_data = json.loads(plaintext)
        assert "zk_compliance_proof" in payload_data
        assert "encrypted_pii" in payload_data
        assert payload_data["encryption_algorithm"] == "AES-256-GCM"
        assert payload_data["ivms101_version"] == "101.2023"
        assert payload_data["payload_version"] == "1.0"

        # Verify proof data matches
        proof_data = payload_data["zk_compliance_proof"]
        assert proof_data["proof_id"] == sample_compliance_proof.proof_id
        assert proof_data["jurisdiction"] == sample_compliance_proof.jurisdiction

    def test_expires_at_in_header(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """The override_header.not_after matches the proof expiry time."""
        _, public_key_der = rsa_keypair
        bridge = TRISABridge()

        envelope = bridge.build_secure_envelope(
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
            beneficiary_public_key=public_key_der,
        )

        assert envelope["override_header"]["not_after"] == sample_compliance_proof.proof_expires_at
