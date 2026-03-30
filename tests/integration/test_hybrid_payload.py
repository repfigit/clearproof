"""
Integration tests for HybridPayload encryption roundtrip.

Tests that PII can be encrypted and decrypted using AES-256-GCM
with envelope binding via associated data.
"""

from __future__ import annotations

import json
import os

import pytest
from cryptography.exceptions import InvalidTag

from src.sar.encryption import derive_key, encrypt_pii, decrypt_pii


class TestEncryptionRoundtrip:
    """Test encrypt/decrypt PII roundtrip with AES-256-GCM."""

    def test_encrypt_decrypt_roundtrip(self, sample_master_key: bytes):
        """Encrypting then decrypting with the same key and envelope_id succeeds."""
        key = derive_key(sample_master_key, context=b"roundtrip-test")
        envelope_id = "envelope-001"

        plaintext = json.dumps({
            "originator_name": "Alice Nakamoto",
            "originator_address": "123 Blockchain Ave",
            "date_of_birth": "1990-01-01",
        }).encode()

        nonce, ciphertext = encrypt_pii(plaintext, key, envelope_id)

        # Decrypt
        recovered = decrypt_pii(nonce, ciphertext, key, envelope_id)
        assert recovered == plaintext

        # Verify JSON content
        recovered_data = json.loads(recovered)
        assert recovered_data["originator_name"] == "Alice Nakamoto"

    def test_wrong_key_fails(self, sample_master_key: bytes):
        """Decrypting with a wrong key raises InvalidTag."""
        key = derive_key(sample_master_key, context=b"correct-context")
        wrong_key = derive_key(sample_master_key, context=b"wrong-context")
        envelope_id = "envelope-002"

        plaintext = b"sensitive PII data"
        nonce, ciphertext = encrypt_pii(plaintext, key, envelope_id)

        with pytest.raises(InvalidTag):
            decrypt_pii(nonce, ciphertext, wrong_key, envelope_id)

    def test_wrong_envelope_id_fails(self, sample_master_key: bytes):
        """Decrypting with a wrong envelope_id raises InvalidTag (AAD mismatch)."""
        key = derive_key(sample_master_key, context=b"aad-test")
        correct_envelope = "envelope-003"
        wrong_envelope = "envelope-999"

        plaintext = b"sensitive PII data"
        nonce, ciphertext = encrypt_pii(plaintext, key, correct_envelope)

        with pytest.raises(InvalidTag):
            decrypt_pii(nonce, ciphertext, key, wrong_envelope)

    def test_tampered_ciphertext_fails(self, sample_master_key: bytes):
        """Decrypting tampered ciphertext raises InvalidTag."""
        key = derive_key(sample_master_key, context=b"tamper-test")
        envelope_id = "envelope-004"

        plaintext = b"sensitive PII data"
        nonce, ciphertext = encrypt_pii(plaintext, key, envelope_id)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            decrypt_pii(nonce, tampered, key, envelope_id)

    def test_nonce_is_12_bytes(self, sample_master_key: bytes):
        """encrypt_pii returns a 12-byte nonce (96-bit for AES-256-GCM)."""
        key = derive_key(sample_master_key, context=b"nonce-test")
        nonce, _ = encrypt_pii(b"test", key, "envelope-005")
        assert len(nonce) == 12

    def test_different_encryptions_produce_different_ciphertexts(
        self, sample_master_key: bytes
    ):
        """Two encryptions of the same plaintext produce different ciphertexts (random nonce)."""
        key = derive_key(sample_master_key, context=b"uniqueness-test")
        plaintext = b"same plaintext"
        envelope_id = "envelope-006"

        nonce1, ct1 = encrypt_pii(plaintext, key, envelope_id)
        nonce2, ct2 = encrypt_pii(plaintext, key, envelope_id)

        # Nonces should differ (random), so ciphertexts should differ
        assert nonce1 != nonce2
        assert ct1 != ct2
