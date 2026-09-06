"""HTTPS discovery with DNS policy applied to the actual connected address."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
from collections.abc import Awaitable, Callable, Mapping, Sequence
from types import MappingProxyType

import httpcore

from src.protocol.discovery_profile import (
    MAX_DOCUMENT_BYTES,
    DiscoveryInvalid,
    DiscoveryTarget,
    DiscoveryUnavailable,
    DiscoveryUnsupported,
    parse_target,
)

# Conservative and stable across Python/Node versions. Keep the Node list and
# shared network vectors in sync when changing this policy.
_V4_DENY = tuple(
    map(
        ipaddress.ip_network,
        (
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/3",
        ),
    )
)
_V6_PUBLIC = ipaddress.ip_network("2000::/3")
_V6_DENY = tuple(map(ipaddress.ip_network, ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")))
Resolver = Callable[[str, int], Awaitable[Sequence[str]]]


async def resolve_addresses(host: str, port: int) -> Sequence[str]:
    answers = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(answer[4][0] for answer in answers))


class EgressPolicy:
    """Operator-only exceptions map exact DNS authorities to permitted CIDRs."""

    def __init__(self, private_destinations: Mapping[str, Sequence[str]] | None = None):
        exceptions = {}
        for authority, ranges in (private_destinations or {}).items():
            if parse_target(authority).authority != authority or not isinstance(ranges, (list, tuple)) or not ranges:
                raise ValueError("Private destinations require exact authorities and nonempty CIDR lists")
            exceptions[authority] = tuple(ipaddress.ip_network(cidr, strict=False) for cidr in ranges)
        self._exceptions = MappingProxyType(exceptions)

    def permits(self, authority: str, address: str) -> bool:
        try:
            if "%" in address:
                return False
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if any(ip in network for network in self._exceptions.get(authority, ())):
            return True
        if ip.version == 4:
            return not any(ip in network for network in _V4_DENY)
        return ip in _V6_PUBLIC and not any(ip in network for network in _V6_DENY)


class PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, target: DiscoveryTarget, policy: EgressPolicy, resolver: Resolver):
        self.target, self.policy, self.resolver = target, policy, resolver
        self.backend = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != self.target.host or port != self.target.port:
            raise DiscoveryInvalid("Unexpected discovery connection destination")
        addresses = tuple(await self.resolver(host, port))
        if not addresses or any(not self.policy.permits(self.target.authority, ip) for ip in addresses):
            raise DiscoveryInvalid("Discovery DNS answer contains a disallowed address")
        # No second hostname lookup. HTTPcore retains the original TLS SNI and
        # certificate hostname; the socket connects only to this vetted IP.
        return await self.backend.connect_tcp(
            str(ipaddress.ip_address(addresses[0])),
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


async def fetch_document(
    target: DiscoveryTarget,
    policy: EgressPolicy,
    resolver: Resolver,
    timeout: float,
    ssl_context: ssl.SSLContext | None = None,
) -> dict:
    if ssl_context is None:
        context = ssl.create_default_context()
        # OpenSSL builds differ in whether system defaults are reflected in
        # this property. Set an explicit floor on the context we own.
        context.minimum_version = max(context.minimum_version, ssl.TLSVersion.TLSv1_2)
    else:
        context = ssl_context
    if (
        context.verify_mode != ssl.CERT_REQUIRED
        or not context.check_hostname
        or context.minimum_version < ssl.TLSVersion.TLSv1_2
    ):
        raise DiscoveryInvalid("Discovery requires TLS 1.2+, certificate and hostname verification")
    try:
        async with asyncio.timeout(timeout):
            # Fresh pool: no proxy environment, redirects or connections that
            # outlive the DNS/policy check for this fetch.
            async with httpcore.AsyncConnectionPool(
                ssl_context=context,
                network_backend=PinnedBackend(target, policy, resolver),
                max_connections=1,
                max_keepalive_connections=0,
            ) as pool:
                async with pool.stream(
                    "GET",
                    target.url,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                    extensions={"timeout": dict.fromkeys(("connect", "read", "write", "pool"), timeout)},
                ) as response:
                    if response.status == 404:
                        raise DiscoveryUnsupported("Discovery document returned HTTP 404")
                    if 300 <= response.status < 400:
                        raise DiscoveryInvalid("Discovery redirects are forbidden")
                    if response.status != 200:
                        raise DiscoveryUnavailable(f"Discovery service returned HTTP {response.status}")
                    headers = {key.lower(): value.lower() for key, value in response.headers}
                    if headers.get(b"content-type", b"").split(b";")[0].strip() != b"application/json":
                        raise DiscoveryInvalid("Discovery requires application/json")
                    if headers.get(b"content-encoding", b"identity") != b"identity":
                        raise DiscoveryInvalid("Compressed discovery responses are unsupported")
                    body = bytearray()
                    async for chunk in response.aiter_stream():
                        if len(body) + len(chunk) > MAX_DOCUMENT_BYTES:
                            raise DiscoveryInvalid("Discovery document exceeds 64 KiB")
                        body.extend(chunk)

        def reject_constant(value):
            raise ValueError("Non-JSON numeric constant")

        return json.loads(body.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DiscoveryInvalid("Discovery response is not valid UTF-8 JSON") from exc
    except (httpcore.NetworkError, httpcore.TimeoutException, httpcore.ProtocolError, OSError, TimeoutError) as exc:
        raise DiscoveryUnavailable("Discovery DNS, TLS, connection or timeout failure") from exc
