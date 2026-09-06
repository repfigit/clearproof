"""Constrained, versioned counterparty discovery. Never permits a downgrade."""

from __future__ import annotations

import copy
import json
import math
import os
import ssl
import time
from collections import OrderedDict

from src.protocol.discovery_profile import (
    DiscoveryError,
    DiscoveryInvalid,
    DiscoveryUnavailable,
    DiscoveryUnsupported,
    decode_hpke_key,
    parse_target,
    validate_document,
)
from src.protocol.discovery_transport import EgressPolicy, Resolver, fetch_document, resolve_addresses

__all__ = [
    "DiscoveryClient",
    "DiscoveryError",
    "DiscoveryInvalid",
    "DiscoveryUnavailable",
    "DiscoveryUnsupported",
    "EgressPolicy",
    "clear_discovery_cache",
    "resolve_hpke_public_key",
]


class DiscoveryClient:
    """One transport policy and bounded cache per client instance.

    Resolver and TLS context are operator dependencies, never request fields.
    Domain ownership is self-declared; this does not check a VASP registry.
    """

    def __init__(
        self,
        *,
        policy: EgressPolicy | None = None,
        resolver: Resolver = resolve_addresses,
        ssl_context: ssl.SSLContext | None = None,
        cache_ttl: float = 300,
        timeout: float = 10,
    ):
        if not math.isfinite(cache_ttl) or not 0 <= cache_ttl <= 3600:
            raise ValueError("cache_ttl must be finite and between 0 and 3600 seconds")
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("timeout must be finite and between 0 and 60 seconds")
        self._policy, self._resolver, self._ssl_context = policy or EgressPolicy(), resolver, ssl_context
        self._ttl, self._timeout = cache_ttl, timeout
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._generation = 0

    def clear_cache(self) -> None:
        self._generation += 1
        self._cache.clear()

    async def discover(self, identity: str) -> dict:
        target = parse_target(identity)
        now, generation = time.monotonic(), self._generation
        cached = self._cache.pop(target.did, None)
        if cached and cached[0] > now:
            self._cache[target.did] = cached
            return copy.deepcopy(cached[1])
        document = validate_document(
            await fetch_document(target, self._policy, self._resolver, self._timeout, self._ssl_context),
            target,
        )
        # TTL starts before the fetch. Clearing the cache fences in-flight replies.
        if self._ttl and now + self._ttl > time.monotonic() and generation == self._generation:
            self._cache[target.did] = (now + self._ttl, copy.deepcopy(document))
            while len(self._cache) > 128:
                self._cache.popitem(last=False)
        return document

    async def resolve_hpke_public_key(self, identity: str) -> bytes:
        doc = await self.discover(identity)
        return decode_hpke_key(doc["clearproof"]["hpkePublicKey"])


_default_client = DiscoveryClient()
_default_settings = ("{}", None, None)


def clear_discovery_cache() -> None:
    _default_client.clear_cache()


async def resolve_hpke_public_key(vasp_did_or_domain: str) -> bytes:
    global _default_client, _default_settings
    settings = (
        os.getenv("DISCOVERY_PRIVATE_DESTINATIONS", "{}"),
        os.getenv("SSL_CERT_FILE"),
        os.getenv("SSL_CERT_DIR"),
    )
    if settings != _default_settings:
        try:
            if len(settings[0]) > 16384:
                raise ValueError("Oversized policy")
            destinations = json.loads(settings[0])
            if not isinstance(destinations, dict):
                raise ValueError("Expected an authority-to-CIDRs map")
            replacement = DiscoveryClient(policy=EgressPolicy(destinations))
        except (ValueError, TypeError, DiscoveryError) as exc:
            raise DiscoveryInvalid("Invalid operator discovery egress configuration") from exc
        _default_client.clear_cache()
        _default_client, _default_settings = replacement, settings
    return await _default_client.resolve_hpke_public_key(vasp_did_or_domain)
