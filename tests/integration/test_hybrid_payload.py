"""
Integration tests for HybridPayload encryption roundtrip.

Tests that PII can be encrypted and decrypted using AES-256-GCM
with envelope binding via associated data.
"""

from __future__ import annotations

import json

import pytest
from cryptography.exceptions import InvalidTag

from src.sar.encryption import decrypt_pii, derive_key, encrypt_pii


class TestEncryptionRoundtrip:
    """Test encrypt/decrypt PII roundtrip with AES-256-GCM."""

    def test_encrypt_decrypt_roundtrip(self, sample_master_key: bytes):
        """Encrypting then decrypting with the same key and envelope_id succeeds."""
        key = derive_key(sample_master_key, context=b"roundtrip-test")
        envelope_id = "envelope-001"

        plaintext = json.dumps(
            {
                "originator_name": "Alice Nakamoto",
                "originator_address": "123 Blockchain Ave",
                "date_of_birth": "1990-01-01",
            }
        ).encode()

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

    def test_different_encryptions_produce_different_ciphertexts(self, sample_master_key: bytes):
        """Two encryptions of the same plaintext produce different ciphertexts (random nonce)."""
        key = derive_key(sample_master_key, context=b"uniqueness-test")
        plaintext = b"same plaintext"
        envelope_id = "envelope-006"

        nonce1, ct1 = encrypt_pii(plaintext, key, envelope_id)
        nonce2, ct2 = encrypt_pii(plaintext, key, envelope_id)

        # Nonces should differ (random), so ciphertexts should differ
        assert nonce1 != nonce2
        assert ct1 != ct2


@pytest.mark.parametrize("envelope,expected", [(None, False), ({}, False), ({"v": 1}, False), ({"v": 2}, True)])
def test_hpke_version_indicator_reads_envelope_version(sample_hybrid_payload, envelope, expected):
    # This property identifies an envelope version; it does not validate HPKE.
    payload = sample_hybrid_payload.model_copy(update={"pii_envelope": envelope})
    assert payload.is_hpke_v2 is expected


class TestPIIWireFields:
    """The single wire serialization shared by every legacy bridge."""

    @pytest.mark.parametrize("fixture", ["sample_hybrid_payload", "sample_hpke_hybrid_payload"])
    def test_wire_fields_round_trip_and_decrypt(self, request, fixture, open_hybrid_pii):
        from src.protocol.hybrid_payload import HybridPayload

        payload = request.getfixturevalue(fixture)
        fields = json.loads(json.dumps(payload.pii_wire_fields()))
        restored = HybridPayload.from_pii_wire_fields(payload.compliance_proof, fields)
        assert restored == payload
        assert open_hybrid_pii(restored)["originator_name"] == "Test User"

    def test_v2_wire_fields_carry_the_hpke_envelope(self, sample_hpke_hybrid_payload):
        fields = sample_hpke_hybrid_payload.pii_wire_fields()
        assert fields["pii_nonce"] == ""
        assert fields["pii_envelope"]["v"] == 2
        assert {"enc", "kid", "ct", "aad"} <= set(fields["pii_envelope"])

    def test_v1_wire_fields_tolerate_absent_optional_keys(self, sample_hybrid_payload):
        from src.protocol.hybrid_payload import HybridPayload

        fields = sample_hybrid_payload.pii_wire_fields()
        del fields["pii_envelope"]
        del fields["encryption_algorithm"]
        restored = HybridPayload.from_pii_wire_fields(sample_hybrid_payload.compliance_proof, fields)
        assert restored == sample_hybrid_payload

    def test_trp_extension_uses_wire_fields(self, sample_hpke_hybrid_payload):
        extension = sample_hpke_hybrid_payload.to_trp_extension()["zk_travel_rule"]
        for key, value in sample_hpke_hybrid_payload.pii_wire_fields().items():
            assert extension[key] == value

    @pytest.mark.parametrize(
        "change",
        [{"encrypted_pii": "not base64!"}, {"pii_nonce": "***"}, {"pii_envelope": "not-an-object"}],
    )
    def test_malformed_wire_fields_are_rejected(self, sample_hybrid_payload, change):
        from src.protocol.hybrid_payload import HybridPayload

        fields = {**sample_hybrid_payload.pii_wire_fields(), **change}
        with pytest.raises(ValueError):
            HybridPayload.from_pii_wire_fields(sample_hybrid_payload.compliance_proof, fields)
