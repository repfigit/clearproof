"""Versioned, domain-declared discovery metadata; not a credential or licence."""

from __future__ import annotations

import base64
import copy
import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

SPEC_VERSION = "0.4.0"
HPKE_SUITE = "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM"
KEY_PURPOSE = "pii-envelope-v2"
MAX_DOCUMENT_BYTES = 65536


class DiscoveryError(Exception):
    """Discovery failed; never authorize a fallback encryption mode."""


class DiscoveryInvalid(DiscoveryError):
    """Invalid identity, metadata or destination policy."""


class DiscoveryUnsupported(DiscoveryError):
    """No document, or no compatible version/encryption capability."""


class DiscoveryUnavailable(DiscoveryError):
    """DNS, TLS, HTTP service or timeout failure. A retry may succeed."""


@dataclass(frozen=True)
class DiscoveryTarget:
    did: str
    authority: str
    host: str
    port: int

    @property
    def url(self) -> str:
        return f"https://{self.authority}/.well-known/clearproof.json"


def parse_target(value: str) -> DiscoveryTarget:
    """Conservative ASCII did:web profile. Preserve the entire requested DID."""
    if not isinstance(value, str) or len(value) > 512:
        raise DiscoveryInvalid("Expected a canonical domain or did:web identifier")
    is_did = value.startswith("did:web:")
    parts = value[8:].split(":") if is_did else [value]
    authority = parts[0].replace("%3A", ":") if is_did else parts[0]
    match = re.fullmatch(r"([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?", authority)
    if not match:
        raise DiscoveryInvalid("Expected a lowercase ASCII DNS name and optional canonical port")
    host, port_string = match.groups()
    labels = host.split(".")
    if (
        len(host) > 253
        or len(labels) < 2
        or not re.search(r"[a-z]", labels[-1])
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    ):
        raise DiscoveryInvalid("IP literals, single-label hosts and ambiguous DNS names are unsupported")
    port = int(port_string) if port_string else 443
    if port > 65535 or (port_string and port == 443):
        raise DiscoveryInvalid("Invalid or noncanonical discovery port")
    if any(not re.fullmatch(r"[A-Za-z0-9._-]+", part) or part in (".", "..") for part in parts[1:]):
        raise DiscoveryInvalid("Unsupported did:web path component")
    # Validation permits only canonical components; preserve a supplied DID exactly.
    did = value if is_did else "did:web:" + authority.replace(":", "%3A")
    return DiscoveryTarget(did, authority, host, port)


def decode_hpke_key(value: Any) -> bytes:
    """Accept canonical padded or unpadded base64url and usable X25519 points."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", value):
        raise DiscoveryInvalid("HPKE public key must be canonical base64url for 32 bytes")
    key = base64.urlsafe_b64decode(value.rstrip("=") + "=")
    if base64.urlsafe_b64encode(key).decode().rstrip("=") != value.rstrip("="):
        raise DiscoveryInvalid("HPKE public key has noncanonical encoding")
    if int.from_bytes(key, "little") >= 2**255 - 19:
        raise DiscoveryInvalid("HPKE public key is not a canonical X25519 point")
    try:
        X25519PrivateKey.from_private_bytes(bytes([42]) * 32).exchange(X25519PublicKey.from_public_bytes(key))
    except ValueError as exc:
        raise DiscoveryInvalid("HPKE public key is a low-order X25519 point") from exc
    return key


def validate_document(document: Any, target: DiscoveryTarget) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise DiscoveryInvalid("Discovery document must be an object")
    if not isinstance(document.get("version"), str):
        raise DiscoveryInvalid("Discovery version is required")
    if document["version"] != SPEC_VERSION:
        raise DiscoveryUnsupported("Unsupported discovery version; migrate to 0.4.0")
    vasp, cp = document.get("vasp"), document.get("clearproof")
    if not isinstance(vasp, dict) or vasp.get("did") != target.did:
        raise DiscoveryInvalid("Discovery DID does not match the complete requested identity")
    if not isinstance(cp, dict):
        raise DiscoveryInvalid("Missing clearproof capabilities")
    endpoint = cp.get("endpoint")
    if (
        not isinstance(endpoint, str)
        or len(endpoint) > 2048
        or not re.fullmatch(r"https://[A-Za-z0-9.:/_~%-]+", endpoint)
    ):
        raise DiscoveryInvalid("Proof endpoint must be an HTTPS URL without credentials, query or fragment")
    parsed = urlsplit(endpoint)
    if parsed.netloc != target.authority or not parsed.path.startswith("/"):
        raise DiscoveryInvalid("Proof endpoint must use the requested discovery authority")
    chains, versions, suites = cp.get("supportedChains"), cp.get("supportedVersions"), cp.get("hpkeSuites")
    if (
        not isinstance(chains, list)
        or not 1 <= len(chains) <= 64
        or any(type(chain) not in (int, float) or not 0 < chain <= 2**53 - 1 or int(chain) != chain for chain in chains)
        or len(set(chains)) != len(chains)
    ):
        raise DiscoveryInvalid("supportedChains must be unique positive safe integers")
    for values, name in ((versions, "supportedVersions"), (suites, "hpkeSuites")):
        if (
            not isinstance(values, list)
            or not 1 <= len(values) <= 16
            or any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in values)
            or len(set(values)) != len(values)
        ):
            raise DiscoveryInvalid(f"{name} must be a bounded nonempty string array")
    if SPEC_VERSION not in versions or cp.get("proofFormat") != "groth16" or HPKE_SUITE not in suites:
        raise DiscoveryUnsupported("No supported protocol, proof format or HPKE suite")
    if cp.get("hpkeKeyPurpose") != KEY_PURPOSE:
        raise DiscoveryInvalid("HPKE key purpose must be pii-envelope-v2")
    key = decode_hpke_key(cp.get("hpkePublicKey"))
    kid = base64.urlsafe_b64encode(hashlib.sha256(key).digest()[:16]).decode()
    if cp.get("hpkeKeyId") not in (kid, kid.rstrip("=")):
        raise DiscoveryInvalid("HPKE key ID does not match the advertised key")
    return copy.deepcopy(document)
