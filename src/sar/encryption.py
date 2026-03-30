"""
AES-256-GCM encryption for PII and audit payloads.

v1: Software-based AES-256-GCM with HKDF key derivation.
v2: HSM integration (AWS CloudHSM, Azure Dedicated HSM, or on-prem).

Uses envelope binding via associated data to tie ciphertext to a
specific transfer envelope, preventing replay across envelopes.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

__all__ = ["derive_key", "encrypt_pii", "decrypt_pii"]

_NONCE_LENGTH = 12  # 96-bit nonce for AES-256-GCM


def derive_key(master_key: bytes, context: bytes) -> bytes:
    """
    Derive an encryption key from a master key using HKDF-SHA256.

    Args:
        master_key: 32-byte master key material.
        context: Context/info bytes for domain separation (e.g. envelope ID).

    Returns:
        32-byte derived key suitable for AES-256-GCM.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"zk-travel-rule-v1",
        info=context,
    )
    return hkdf.derive(master_key)


def encrypt_pii(
    plaintext: bytes,
    key: bytes,
    envelope_id: str,
) -> tuple[bytes, bytes]:
    """
    Encrypt PII with AES-256-GCM using associated data binding.

    The envelope_id is bound as associated data so that the ciphertext
    cannot be replayed in a different envelope context.

    Args:
        plaintext: Raw PII bytes to encrypt.
        key: 32-byte AES-256 key.
        envelope_id: Envelope identifier used as associated data.

    Returns:
        Tuple of (nonce, ciphertext) where nonce is 12 bytes.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_LENGTH)
    associated_data = envelope_id.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_pii(
    nonce: bytes,
    ciphertext: bytes,
    key: bytes,
    envelope_id: str,
) -> bytes:
    """
    Decrypt PII encrypted with AES-256-GCM.

    Args:
        nonce: 12-byte nonce used during encryption.
        ciphertext: AES-256-GCM ciphertext (includes auth tag).
        key: 32-byte AES-256 key.
        envelope_id: Envelope identifier used as associated data during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
            (wrong key, wrong envelope_id, or tampered ciphertext).
    """
    aesgcm = AESGCM(key)
    associated_data = envelope_id.encode("utf-8")
    return aesgcm.decrypt(nonce, ciphertext, associated_data)
