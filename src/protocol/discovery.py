"""
Counterparty VASP discovery client (specs/well-known-clearproof.md).

Resolves a beneficiary VASP's HPKE public key from its well-known
``clearproof.json`` document so PII envelopes can be sealed with HPKE v2
without manual key configuration.

Trust model: the well-known document is self-declared by the counterparty
domain over TLS. If registry-backed identity assurance is required, compare
the domain/DID against the on-chain VASPRegistry before trusting the key
(see ROADMAP Phase 1, "Registry-backed discovery verification").

Cache: in-memory, 1-hour TTL (counterparty key rotation is expected to be
rare and announced; a stale key fails open to v1 with a warning rather than
breaking transfers).
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

__all__ = ["DiscoveryError", "clear_discovery_cache", "resolve_hpke_public_key"]

_CACHE_TTL_SECONDS = 3600
_TIMEOUT_SECONDS = 10.0

# domain -> (expires_at, hpke_public_key_bytes | None)
_cache: dict[str, tuple[float, bytes | None]] = {}


class DiscoveryError(Exception):
    """Raised when a counterparty's discovery document cannot be resolved."""


def clear_discovery_cache() -> None:
    """Flush the discovery cache (tests, forced key-rotation refresh)."""
    _cache.clear()


def _domain_from_did_or_domain(value: str) -> str:
    """
    Extract the domain from a did:web DID or pass a bare domain through.

    did:web:example.com            -> example.com
    did:web:example.com:path:vasp  -> example.com (path segments ignored for
                                     the well-known location; the document
                                     itself carries the full DID)
    """
    value = value.strip()
    if value.startswith("did:web:"):
        parts = value[len("did:web:"):].split(":")
        return parts[0]
    return value.removeprefix("https://").removeprefix("http://").split("/")[0]


async def _fetch_well_known(domain: str, http_client: httpx.AsyncClient | None) -> dict[str, Any]:
    url = f"https://{domain}/.well-known/clearproof.json"
    try:
        if http_client is not None:
            resp = await http_client.get(url)
        else:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"Failed to fetch {url}: {exc}") from exc
    if resp.status_code != 200:
        raise DiscoveryError(f"{url} returned HTTP {resp.status_code}")
    try:
        doc = resp.json()
    except ValueError as exc:
        raise DiscoveryError(f"{url} did not return valid JSON") from exc
    if "clearproof" not in doc:
        raise DiscoveryError(f"{url} is not a clearproof discovery document")
    return doc


async def resolve_hpke_public_key(
    vasp_did_or_domain: str,
    http_client: httpx.AsyncClient | None = None,
) -> bytes | None:
    """
    Resolve the counterparty's HPKE (X25519) public key.

    Args:
        vasp_did_or_domain: Beneficiary ``did:web:`` DID or bare domain.
        http_client: Optional injected client (testing).

    Returns:
        32-byte X25519 public key, or None if the counterparty does not
        advertise one (caller should fall back per migration policy).

    Raises:
        DiscoveryError: On fetch/parse failure (callers decide fail-open vs
            fail-closed; the proof route currently fails open to v1).
    """
    domain = _domain_from_did_or_domain(vasp_did_or_domain)

    if domain in _cache:
        expires_at, cached = _cache[domain]
        if time.time() < expires_at:
            return cached
        del _cache[domain]

    doc = await _fetch_well_known(domain, http_client)
    clearproof = doc["clearproof"]

    key_b64 = clearproof.get("hpkePublicKey")
    result: bytes | None = None
    if key_b64:
        try:
            key = base64.urlsafe_b64decode(key_b64.encode("ascii"))
        except Exception as exc:
            raise DiscoveryError(f"{domain}: hpkePublicKey is not valid base64url") from exc
        if len(key) != 32:
            raise DiscoveryError(f"{domain}: hpkePublicKey must be 32 bytes (X25519)")
        result = key

    _cache[domain] = (time.time() + _CACHE_TTL_SECONDS, result)
    return result
