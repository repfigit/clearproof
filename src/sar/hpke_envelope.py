"""
HPKE (RFC 9180) envelope encryption for counterparty PII payloads — v2 format.

Replaces the shared-master-key AES-256-GCM model (``src/sar/encryption.py``,
v1) for counterparty-decryptable PII: each VASP holds an X25519 keypair and
publishes the public key; the originator seals envelopes to the beneficiary's
public key. Compromise of one VASP's key exposes only that VASP's envelopes,
and envelope key rotation is per-VASP rather than global.

Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, base mode.
(Authenticated mode — binding the originator's static key — is a documented
follow-up once VASP signing keys are standardized in the registry.)

Post-quantum note: draft-ietf-hpke-pq adds ML-KEM and hybrid suites
(e.g. X-Wing = X25519 + ML-KEM-768). The envelope format carries explicit
kem/kdf/aead identifiers so PQ-hybrid suites can be introduced as v3 without
a format break. See docs/internal/SOTA_PLAN_2026.md item #1.

Envelope JSON (``v=2``)::

    {
      "v": 2,
      "kem": "DHKEM_X25519_HKDF_SHA256",
      "kdf": "HKDF_SHA256",
      "aead": "AES_256_GCM",
      "kid": "<base64url key fingerprint, 16 bytes>",
      "enc": "<base64 KEM encapsulated key>",
      "ct":  "<base64 ciphertext incl. GCM tag>",
      "aad": "<envelope id bound as associated data>"
    }
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from pyhpke import AEADId, CipherSuite, KDFId, KEMId

__all__ = [
    "ENVELOPE_VERSION",
    "SUITE_IDS",
    "derive_key_id",
    "generate_keypair",
    "open_envelope",
    "seal_envelope",
]

ENVELOPE_VERSION = 2

# Domain-separation info string for the HPKE context.
_INFO = b"clearproof-envelope-v2"

SUITE_IDS = {
    "kem": "DHKEM_X25519_HKDF_SHA256",
    "kdf": "HKDF_SHA256",
    "aead": "AES_256_GCM",
}

_SUITE = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256,
    KDFId.HKDF_SHA256,
    AEADId.AES256_GCM,
)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    decoded = base64.b64decode(data.encode("ascii"), altchars=b"-_", validate=True)
    if _b64e(decoded) != data:
        raise ValueError("Noncanonical envelope encoding")
    return decoded


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a fresh X25519 keypair.

    Returns:
        (private_key_bytes, public_key_bytes) — 32 bytes each.
    """
    kp = _SUITE.kem.derive_key_pair(os.urandom(32))
    return kp.private_key.to_private_bytes(), kp.public_key.to_public_bytes()


def derive_key_id(public_key_bytes: bytes) -> str:
    """
    Stable recipient key fingerprint for envelope ``kid`` headers.

    First 16 bytes of SHA-256 over the raw public key, base64url-encoded.
    Lets recipients identify which of their (possibly rotated) keys an
    envelope was sealed to, and supports decrypt-audit trails.
    """
    digest = hashlib.sha256(public_key_bytes).digest()[:16]
    return _b64e(digest)


def seal_envelope(
    plaintext: bytes,
    recipient_public_key: bytes,
    envelope_id: str,
) -> dict[str, Any]:
    """
    Seal *plaintext* to the recipient's X25519 public key.

    The envelope_id is bound as HPKE associated data, so the ciphertext
    cannot be replayed inside a different transfer envelope (same binding
    model as v1).

    Args:
        plaintext: PII payload bytes.
        recipient_public_key: 32-byte X25519 public key of the beneficiary VASP.
        envelope_id: Envelope identifier (e.g. proof_id) bound as AAD.

    Returns:
        JSON-serializable v2 envelope dict.
    """
    pkr = _SUITE.kem.deserialize_public_key(recipient_public_key)
    enc, sender_ctx = _SUITE.create_sender_context(pkr, info=_INFO)
    ct = sender_ctx.seal(plaintext, aad=envelope_id.encode("utf-8"))
    return {
        "v": ENVELOPE_VERSION,
        **SUITE_IDS,
        "kid": derive_key_id(recipient_public_key),
        "enc": _b64e(enc),
        "ct": _b64e(ct),
        "aad": envelope_id,
    }


def open_envelope(
    envelope: dict[str, Any],
    recipient_private_key: bytes,
) -> bytes:
    """
    Open a v2 HPKE envelope with the recipient's X25519 private key.

    Args:
        envelope: Dict produced by :func:`seal_envelope`.
        recipient_private_key: 32-byte X25519 private key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: On wrong version, suite mismatch, tampered ciphertext,
            wrong key, or AAD (envelope_id) mismatch.
    """
    if envelope.get("v") != ENVELOPE_VERSION:
        raise ValueError(f"Unsupported envelope version: {envelope.get('v')!r}")
    for field, expected in SUITE_IDS.items():
        if envelope.get(field) != expected:
            raise ValueError(f"Unsupported {field}: {envelope.get(field)!r} (expected {expected!r})")

    skr = _SUITE.kem.deserialize_private_key(recipient_private_key)
    try:
        recipient_ctx = _SUITE.create_recipient_context(_b64d(envelope["enc"]), skr, info=_INFO)
        return recipient_ctx.open(_b64d(envelope["ct"]), aad=envelope["aad"].encode("utf-8"))
    except Exception as exc:
        # Do not leak which check failed (key vs AAD vs tag).
        raise ValueError("Envelope decryption failed") from exc
