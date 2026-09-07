"""
Tests for the HPKE v2 envelope format (src/sar/hpke_envelope.py).

Covers the security properties the v1 shared-key model could not provide:
per-recipient key isolation, key fingerprinting for rotation, and AAD
binding of ciphertexts to their transfer envelope.
"""

from __future__ import annotations

import pytest

from src.sar.hpke_envelope import (
    ENVELOPE_VERSION,
    SUITE_IDS,
    derive_key_id,
    generate_keypair,
    open_envelope,
    seal_envelope,
)


@pytest.fixture()
def recipient_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()  # (private, public)


@pytest.fixture()
def other_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


class TestRoundTrip:
    def test_seal_open_roundtrip(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        priv, pub = recipient_keypair
        plaintext = b'{"originator": {"name": "Alice"}, "transfer_id": "tx-1"}'
        envelope = seal_envelope(plaintext, pub, "proof-001")
        assert open_envelope(envelope, priv) == plaintext

    def test_envelope_schema(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        _, pub = recipient_keypair
        envelope = seal_envelope(b"data", pub, "proof-002")
        assert envelope["v"] == ENVELOPE_VERSION
        for field, expected in SUITE_IDS.items():
            assert envelope[field] == expected
        assert set(envelope) == {"v", "kem", "kdf", "aead", "kid", "enc", "ct", "aad"}
        # X25519 enc is 32 bytes -> 44 base64url chars (with padding).
        assert len(envelope["enc"]) == 44
        assert envelope["aad"] == "proof-002"

    def test_envelope_is_json_serializable(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        import json

        _, pub = recipient_keypair
        envelope = seal_envelope(b"data", pub, "proof-003")
        assert json.loads(json.dumps(envelope)) == envelope


class TestKeyIsolation:
    def test_wrong_recipient_key_fails(
        self,
        recipient_keypair: tuple[bytes, bytes],
        other_keypair: tuple[bytes, bytes],
    ) -> None:
        """The core v2 property: one VASP's key cannot open another's envelopes."""
        _, pub = recipient_keypair
        other_priv, _ = other_keypair
        envelope = seal_envelope(b"secret pii", pub, "proof-010")
        with pytest.raises(ValueError, match="decryption failed"):
            open_envelope(envelope, other_priv)

    def test_keypairs_are_unique(self) -> None:
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_key_id_stable_and_distinct(
        self,
        recipient_keypair: tuple[bytes, bytes],
        other_keypair: tuple[bytes, bytes],
    ) -> None:
        _, pub1 = recipient_keypair
        _, pub2 = other_keypair
        assert derive_key_id(pub1) == derive_key_id(pub1)
        assert derive_key_id(pub1) != derive_key_id(pub2)

    def test_envelope_kid_matches_recipient(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        _, pub = recipient_keypair
        envelope = seal_envelope(b"data", pub, "proof-011")
        assert envelope["kid"] == derive_key_id(pub)


class TestBindingAndTamper:
    @pytest.mark.parametrize("field", ["enc", "ct"])
    @pytest.mark.parametrize("mutation", ["ignored-character", "whitespace", "padding", "pad-bits"])
    def test_noncanonical_encoding_rejected(self, recipient_keypair, field, mutation):
        import base64

        priv, pub = recipient_keypair
        envelope = seal_envelope(b"pii", pub, "proof-encoding")
        original = envelope[field]
        if mutation == "ignored-character":
            altered = "!" + original
        elif mutation == "whitespace":
            altered = original + "\n"
        elif mutation == "padding":
            altered = original + "="
        else:
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            position = len(original.rstrip("=")) - 1
            altered = original[:position] + alphabet[alphabet.index(original[position]) + 1] + original[position + 1 :]
        # These representations decode to the original bytes in the permissive
        # decoder, so they would otherwise decrypt successfully despite mutation.
        assert base64.urlsafe_b64decode(altered) == base64.urlsafe_b64decode(original)
        envelope[field] = altered
        with pytest.raises(ValueError, match="decryption failed"):
            open_envelope(envelope, priv)

    def test_aad_mismatch_fails(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        """Ciphertext cannot be replayed inside a different transfer envelope."""
        priv, pub = recipient_keypair
        envelope = seal_envelope(b"pii", pub, "proof-020")
        envelope["aad"] = "proof-999"
        with pytest.raises(ValueError, match="decryption failed"):
            open_envelope(envelope, priv)

    def test_tampered_ciphertext_fails(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        priv, pub = recipient_keypair
        envelope = seal_envelope(b"pii", pub, "proof-021")
        ct = bytearray(__import__("base64").urlsafe_b64decode(envelope["ct"]))
        ct[0] ^= 0x01
        envelope["ct"] = __import__("base64").urlsafe_b64encode(bytes(ct)).decode()
        with pytest.raises(ValueError, match="decryption failed"):
            open_envelope(envelope, priv)

    def test_tampered_enc_fails(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        priv, pub = recipient_keypair
        envelope = seal_envelope(b"pii", pub, "proof-022")
        enc = bytearray(__import__("base64").urlsafe_b64decode(envelope["enc"]))
        enc[0] ^= 0x01
        envelope["enc"] = __import__("base64").urlsafe_b64encode(bytes(enc)).decode()
        with pytest.raises(ValueError):
            open_envelope(envelope, priv)

    def test_wrong_version_rejected(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        priv, pub = recipient_keypair
        envelope = seal_envelope(b"pii", pub, "proof-023")
        envelope["v"] = 1
        with pytest.raises(ValueError, match="version"):
            open_envelope(envelope, priv)

    def test_wrong_suite_rejected(self, recipient_keypair: tuple[bytes, bytes]) -> None:
        priv, pub = recipient_keypair
        envelope = seal_envelope(b"pii", pub, "proof-024")
        envelope["aead"] = "CHACHA20_POLY1305"
        with pytest.raises(ValueError, match="aead"):
            open_envelope(envelope, priv)


class TestFreshness:
    def test_ephemeral_randomness(
        self, recipient_keypair: tuple[bytes, bytes]
    ) -> None:
        """Same plaintext + same recipient -> different enc/ct (fresh ephemeral key)."""
        _, pub = recipient_keypair
        e1 = seal_envelope(b"same plaintext", pub, "proof-030")
        e2 = seal_envelope(b"same plaintext", pub, "proof-030")
        assert e1["enc"] != e2["enc"]
        assert e1["ct"] != e2["ct"]
