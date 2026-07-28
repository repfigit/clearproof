"""
Well-known discovery endpoint (specs/well-known-clearproof.md).

Serves ``GET /.well-known/clearproof.json`` describing this VASP's clearproof
capabilities, including its HPKE (RFC 9180) public key for v2 PII envelopes.

Configuration (environment):
    VASP_DOMAIN               — public domain of this VASP (required to serve)
    VASP_NAME                 — display name (optional)
    VASP_DID                  — this VASP's DID (default did:web:vasp.example.com)
    VASP_JURISDICTION         — ISO 3166-1 numeric code (optional)
    VASP_HPKE_PUBLIC_KEY      — X25519 public key, base64url (32 bytes).
                                If unset, derived from VASP_HPKE_PRIVATE_KEY.
    VASP_HPKE_PRIVATE_KEY     — X25519 private key, base64url (32 bytes).
                                Used to open envelopes addressed to this VASP.
    CLEARPROOF_ENDPOINT       — proof exchange URL (default https://<domain>/clearproof/v1)
    SUPPORTED_CHAINS          — comma-separated EVM chain IDs (default "1,11155111")
    COMPLIANCE_CONTACT        — compliance email (optional)
    TECHNICAL_CONTACT         — technical email (optional)
"""

from __future__ import annotations

import base64
import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter(tags=["discovery"])

SPEC_VERSION = "0.3.0"


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def get_own_hpke_public_key() -> bytes | None:
    """
    This VASP's HPKE public key, from VASP_HPKE_PUBLIC_KEY or derived from
    VASP_HPKE_PRIVATE_KEY. Returns None if neither is configured.
    """
    pub = os.getenv("VASP_HPKE_PUBLIC_KEY")
    if pub:
        key = _b64d(pub)
        if len(key) != 32:
            raise RuntimeError("VASP_HPKE_PUBLIC_KEY must decode to 32 bytes (X25519)")
        return key

    priv = os.getenv("VASP_HPKE_PRIVATE_KEY")
    if priv:
        priv_bytes = _b64d(priv)
        if len(priv_bytes) != 32:
            raise RuntimeError("VASP_HPKE_PRIVATE_KEY must decode to 32 bytes (X25519)")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        sk = X25519PrivateKey.from_private_bytes(priv_bytes)
        return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return None


def build_discovery_document() -> dict[str, Any]:
    """Assemble the well-known discovery document from environment config."""
    domain = os.getenv("VASP_DOMAIN")
    if not domain:
        raise RuntimeError("VASP_DOMAIN is not set — cannot serve discovery document")

    endpoint = os.getenv("CLEARPROOF_ENDPOINT", f"https://{domain}/clearproof/v1")
    chains = [int(c) for c in os.getenv("SUPPORTED_CHAINS", "1,11155111").split(",") if c.strip()]

    clearproof_section: dict[str, Any] = {
        "endpoint": endpoint,
        "supportedChains": chains,
        "supportedVersions": [SPEC_VERSION],
        "proofFormat": "groth16",
    }

    hpke_pub = get_own_hpke_public_key()
    if hpke_pub is not None:
        from src.sar.hpke_envelope import SUITE_IDS, derive_key_id

        clearproof_section["hpkePublicKey"] = _b64e(hpke_pub)
        clearproof_section["hpkeKeyId"] = derive_key_id(hpke_pub)
        clearproof_section["hpkeSuites"] = [f"{SUITE_IDS['kem']}/{SUITE_IDS['kdf']}/{SUITE_IDS['aead']}"]
    else:
        logger.warning(
            "Serving discovery document without an HPKE key — counterparties "
            "cannot seal v2 envelopes to this VASP. Set VASP_HPKE_PRIVATE_KEY."
        )

    doc: dict[str, Any] = {
        "version": SPEC_VERSION,
        "vasp": {
            "did": os.getenv("VASP_DID", "did:web:vasp.example.com"),
        },
        "clearproof": clearproof_section,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }

    if name := os.getenv("VASP_NAME"):
        doc["vasp"]["name"] = name
    if jurisdiction := os.getenv("VASP_JURISDICTION"):
        doc["vasp"]["jurisdiction"] = jurisdiction

    contact: dict[str, str] = {}
    if compliance := os.getenv("COMPLIANCE_CONTACT"):
        contact["compliance"] = compliance
    if technical := os.getenv("TECHNICAL_CONTACT"):
        contact["technical"] = technical
    if contact:
        doc["contact"] = contact

    return doc


@router.get("/.well-known/clearproof.json", summary="clearproof discovery document")
async def well_known_clearproof() -> dict[str, Any]:
    return build_discovery_document()
