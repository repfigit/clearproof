"""
PostgreSQL-backed rate limiter with trusted-proxy client IP extraction and
in-memory fallback when ``DATABASE_URL`` is absent.

Usage as a FastAPI dependency::

    from src.api.middleware.rate_limit import PrincipalRateLimiter, RateLimiter

    _nonce_limiter = RateLimiter(max_requests=60, window_seconds=60)          # unauthenticated routes
    _proof_limiter = PrincipalRateLimiter(max_requests=30, window_seconds=60)  # authenticated routes

    @router.post("/generate")
    async def generate_proof(
        request: ProofGenerateRequest,
        _rl: None = Depends(_proof_limiter),
    ):
        ...

Client IP & proxy trust model
-----------------------------

``trusted_client_ip(request)`` returns the direct peer IP (``request.client.host``)
by default and **ignores** ``X-Forwarded-For`` unless the immediate peer IP falls
within a CIDR/IP explicitly configured in ``RATE_LIMIT_TRUSTED_PROXIES``
(comma-separated IPs/CIDRs, e.g. ``127.0.0.1/32,10.0.0.0/8``).

When the immediate peer IS a trusted proxy, ``X-Forwarded-For`` is parsed right-
to-left, stripping trailing entries that also belong to trusted proxies and
selecting the rightmost untrusted IP — the standard defense against caller-
prepended spoofed ``X-Forwarded-For`` headers. Malformed entries fail closed to
the peer IP so attackers cannot craft arbitrary bucket keys.

Client identity, strongest first:

1. ``PrincipalRateLimiter``: the authenticated principal (``sub`` claim from
   ``JWTAuthDependency``), hashed.
2. In ``api-key`` auth mode, a header that matches the configured key:
   SHA-256 of the key combined with the trusted client IP. Raw keys are never
   stored.
3. Otherwise the trusted client IP. An unauthenticated caller cannot mint fresh
   buckets by sending random ``X-API-Key`` or spoofed ``X-Forwarded-For`` values.

PostgreSQL-backed store & in-memory fallback
--------------------------------------------

When ``app.state.rate_limit_store`` (or a connected ``app.state.db``) is
available — i.e., when ``DATABASE_URL`` is configured — rate-limit buckets are
persisted in PostgreSQL (``api_rate_limit_buckets``) via an atomic
``INSERT ... ON CONFLICT DO UPDATE`` using PostgreSQL's ``clock_timestamp()``
for window expiry and bounded periodic on-write cleanup. All Uvicorn workers
and API replicas enforce a single shared limit.

**In-memory fallback (when ``DATABASE_URL`` is absent):** when no PostgreSQL
store is attached (e.g., local demos or unit tests without ``DATABASE_URL``),
each ``RateLimiter`` falls back to a process-local ``OrderedDict`` capped at
``max_clients`` active buckets (LRU eviction after sweeping expired windows).
In that fallback mode, limits are per Python process; set ``DATABASE_URL`` for
multi-worker/multi-replica correctness.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import time
from collections import OrderedDict, deque
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request

from src.api.config import resolve_auth_config
from src.api.middleware.auth import JWTAuthDependency
from src.storage.api_state import PostgresRateLimitStore
from src.storage.database import Database

DEFAULT_MAX_CLIENTS = 10_000

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_TRUSTED_PROXIES_CACHE: tuple[str, tuple[IPNetwork, ...]] = ("", ())


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


def _parse_ip(raw: str) -> IPAddress | None:
    text = raw.strip()
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def parse_trusted_proxies(raw: str | None = None) -> tuple[IPNetwork, ...]:
    """Parse ``RATE_LIMIT_TRUSTED_PROXIES`` (comma-separated IPs/CIDRs).

    Invalid entries raise ``ValueError`` so misconfigured proxy trust fails
    closed rather than silently trusting or ignoring ranges.
    """
    global _TRUSTED_PROXIES_CACHE
    value = os.getenv("RATE_LIMIT_TRUSTED_PROXIES", "") if raw is None else raw
    if value == _TRUSTED_PROXIES_CACHE[0]:
        return _TRUSTED_PROXIES_CACHE[1]
    networks: list[IPNetwork] = []
    for item in value.split(","):
        entry = item.strip()
        if not entry:
            continue
        networks.append(ipaddress.ip_network(entry, strict=False))
    parsed = tuple(networks)
    if raw is None:
        _TRUSTED_PROXIES_CACHE = (value, parsed)
    return parsed


def _is_trusted(addr: IPAddress, trusted_proxies: tuple[IPNetwork, ...]) -> bool:
    return any(addr in network for network in trusted_proxies)


def trusted_client_ip(request: Request, *, trusted_proxies: tuple[IPNetwork, ...] | None = None) -> str:
    """Resolve the client IP without blindly trusting ``X-Forwarded-For``.

    - If ``request.client`` is absent, returns ``"unknown"``.
    - If no trusted proxies are configured, or the immediate peer IP is not in
      ``trusted_proxies``, ``X-Forwarded-For`` is ignored and the peer host is
      returned verbatim.
    - If the immediate peer IS a trusted proxy and ``X-Forwarded-For`` is
      present, walks the comma-separated header from right to left and returns
      the first valid IP address not in ``trusted_proxies``. If every entry is
      a trusted proxy or any encountered entry is malformed, falls back to the
      immediate peer IP.
    """
    peer_raw = request.client.host if request.client and request.client.host else ""
    if not peer_raw:
        return "unknown"

    proxies = parse_trusted_proxies() if trusted_proxies is None else trusted_proxies
    if not proxies:
        return peer_raw

    peer_ip = _parse_ip(peer_raw)
    if peer_ip is None or not _is_trusted(peer_ip, proxies):
        return peer_raw

    xff = request.headers.get("X-Forwarded-For") or request.headers.get("x-forwarded-for") or ""
    if not xff:
        return str(peer_ip)

    # Walk right-to-left: trusted proxies append to the right, while untrusted
    # callers can only spoof values on the left.
    for part in reversed(xff.split(",")):
        candidate = _parse_ip(part)
        if candidate is None:
            return str(peer_ip)
        if not _is_trusted(candidate, proxies):
            return str(candidate)
    return str(peer_ip)


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _positive_float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


class RateLimiter:
    """
    Rate limiter backed by PostgreSQL when configured, with bounded in-memory
    OrderedDict fallback when ``DATABASE_URL`` is absent.

    When the limit is exceeded the dependency raises HTTP 429 with a
    ``Retry-After`` header and stable error body.

    Parameters
    ----------
    max_requests : int
        Default maximum requests allowed within *window_seconds*.
    window_seconds : float
        Default length of the rate-limit window in seconds.
    env_prefix : str | None
        Optional environment variable prefix (e.g. ``"RATE_LIMIT_AUTH_VERIFY"``).
        When set, ``{env_prefix}_MAX_REQUESTS`` and ``{env_prefix}_WINDOW_SECONDS``
        override the defaults dynamically (with ``RATE_LIMIT_MAX_CLIENTS``
        overriding *max_clients*).
    max_clients : int
        Hard cap on tracked client buckets (LRU eviction when full).
    bucket_namespace : str | None
        Namespace prefix for PostgreSQL bucket keys so distinct route tiers
        remain independent in ``api_rate_limit_buckets``. Defaults to
        ``env_prefix`` when provided, else ``"default"``.
    store : PostgresRateLimitStore | None
        Optional explicit PostgreSQL store (primarily for direct/test injection).
        When omitted, ``__call__`` checks ``request.app.state.rate_limit_store``
        (or lazily binds a store from a connected ``request.app.state.db``) and
        falls back to the bounded in-memory ``OrderedDict`` when absent.
    """

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        *,
        env_prefix: str | None = None,
        max_clients: int = DEFAULT_MAX_CLIENTS,
        bucket_namespace: str | None = None,
        store: PostgresRateLimitStore | None = None,
    ) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_clients <= 0:
            raise ValueError("max_clients must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.env_prefix = env_prefix
        self.max_clients = max_clients
        self.bucket_namespace = bucket_namespace or env_prefix or "default"
        self._store = store
        # Fallback in-memory store (used only when no PostgreSQL store is configured):
        # client_key -> request timestamps (oldest first), ordered by recency
        self._requests: OrderedDict[str, deque[float]] = OrderedDict()
        self._last_sweep = time.monotonic()

    def _effective_limits(self) -> tuple[int, float, int]:
        max_req = self.max_requests
        window = self.window_seconds
        max_clients = self.max_clients
        if self.env_prefix is not None:
            max_req = _positive_int_env(f"{self.env_prefix}_MAX_REQUESTS", max_req)
            window = _positive_float_env(f"{self.env_prefix}_WINDOW_SECONDS", window)
            max_clients = _positive_int_env("RATE_LIMIT_MAX_CLIENTS", max_clients)
        return max_req, window, max_clients

    def reset(self) -> None:
        """Clear all in-memory tracked client buckets (intended for tests)."""
        self._requests.clear()
        self._last_sweep = time.monotonic()

    def _resolve_pg_store(self, request: Request) -> PostgresRateLimitStore | None:
        if self._store is not None:
            return self._store
        try:
            app = getattr(request, "app", None)
        except KeyError:
            return None
        state = getattr(app, "state", None) if app is not None else None
        if state is None:
            return None
        store = getattr(state, "rate_limit_store", None)
        if isinstance(store, PostgresRateLimitStore):
            if getattr(store._db, "is_ready", True):
                return store
            state.rate_limit_store = None
        db = getattr(state, "db", None)
        if isinstance(db, Database) and db.is_ready:
            store = PostgresRateLimitStore(db)
            state.rate_limit_store = store
            return store
        return None

    # ------------------------------------------------------------------
    # FastAPI dependency interface
    # ------------------------------------------------------------------

    async def __call__(self, request: Request) -> None:
        await self._check(request, self._identify_client(request))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _check(self, request: Request, client_key: str) -> None:
        store = self._resolve_pg_store(request)
        if store is not None:
            max_requests, window_seconds, max_clients = self._effective_limits()
            bucket_key = f"{self.bucket_namespace}:{client_key}"
            decision = await store.check_and_increment(
                bucket_key,
                max_requests=max_requests,
                window_seconds=window_seconds,
                max_clients=max_clients,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(decision.retry_after)},
                )
            return
        self._hit(client_key)

    def _hit(self, client_key: str) -> None:
        max_requests, window_seconds, max_clients = self._effective_limits()
        now = time.monotonic()
        window_start = now - window_seconds
        self._sweep(now, window_start, window_seconds)

        timestamps = self._requests.get(client_key)
        if timestamps is None:
            if len(self._requests) >= max_clients:
                self._evict(window_start, max_clients)
            timestamps = self._requests[client_key] = deque()
        else:
            self._requests.move_to_end(client_key)

        while timestamps and timestamps[0] <= window_start:
            timestamps.popleft()

        if len(timestamps) >= max_requests:
            retry_after = max(1, int(window_seconds - (now - timestamps[0])) + 1)
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(now)

    def _sweep(self, now: float, window_start: float, window_seconds: float) -> None:
        """Drop clients whose newest request is outside the window (at most once per window)."""
        if now - self._last_sweep < window_seconds:
            return
        self._last_sweep = now
        for client_key in [key for key, stamps in self._requests.items() if not stamps or stamps[-1] <= window_start]:
            del self._requests[client_key]

    def _evict(self, window_start: float, max_clients: int) -> None:
        """Sweep expired entries first; if still at capacity, evict least-recently-seen buckets."""
        for client_key in [key for key, stamps in self._requests.items() if not stamps or stamps[-1] <= window_start]:
            del self._requests[client_key]
        while len(self._requests) >= max_clients:
            self._requests.popitem(last=False)

    @staticmethod
    def _identify_client(request: Request, principal: Optional[str] = None) -> str:
        """Derive a rate-limit key without retaining raw credentials."""
        if principal:
            return f"principal:{_digest(principal)}"

        host = trusted_client_ip(request)
        api_key = request.headers.get("X-API-Key") or ""
        config = resolve_auth_config(request)
        configured = config.api_key
        if (
            api_key
            and configured
            and config.auth_mode.lower() == "api-key"
            and hmac.compare_digest(api_key.encode(), configured.encode())
        ):
            return f"key:{_digest(api_key, host)}"
        return f"ip:{host}"


class PrincipalRateLimiter(RateLimiter):
    """Rate limiter for authenticated routes, keyed on the verified principal.

    It depends on ``JWTAuthDependency``; FastAPI evaluates that dependency
    once per request, so routes that also declare it do not authenticate twice.
    """

    async def __call__(self, request: Request, claims: Any = Depends(JWTAuthDependency)) -> None:
        subject = claims.get("sub") if isinstance(claims, dict) else None
        principal = subject if isinstance(subject, str) and subject else None
        await self._check(request, self._identify_client(request, principal))


# ---------------------------------------------------------------------------
# Route-tier rate limiters (config-driven with sane defaults & env overrides)
# ---------------------------------------------------------------------------
#
# All limiters are registered in ALL_LIMITERS so test fixtures can reset state
# cleanly and operators can inspect configured tiers.

# Unauthenticated SIWE endpoints (tighter on /auth/verify)
auth_nonce_limiter = RateLimiter(max_requests=60, window_seconds=60, env_prefix="RATE_LIMIT_AUTH_NONCE")
auth_verify_limiter = RateLimiter(max_requests=30, window_seconds=60, env_prefix="RATE_LIMIT_AUTH_VERIFY")

# Pilot routes (default 120/min per tier; operators can tighten via env overrides)
pilot_proof_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_PROOF")
pilot_authorization_limiter = RateLimiter(
    max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_AUTHORIZATION"
)
pilot_proof_jobs_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_PROOF_JOBS")
pilot_credential_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_CREDENTIAL")
pilot_policy_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_POLICY")
pilot_events_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_EVENTS")
pilot_fireblocks_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_FIREBLOCKS")
pilot_readiness_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_READINESS")
pilot_usage_limiter = RateLimiter(max_requests=120, window_seconds=60, env_prefix="RATE_LIMIT_PILOT_USAGE")

# Wallet ownership routes (challenge/verify/recheck invoke crypto + optional RPC)
wallet_ownership_limiter = RateLimiter(max_requests=60, window_seconds=60, env_prefix="RATE_LIMIT_WALLET_OWNERSHIP")

ALL_LIMITERS: tuple[RateLimiter, ...] = (
    auth_nonce_limiter,
    auth_verify_limiter,
    pilot_proof_limiter,
    pilot_authorization_limiter,
    pilot_proof_jobs_limiter,
    pilot_credential_limiter,
    pilot_policy_limiter,
    pilot_events_limiter,
    pilot_fireblocks_limiter,
    pilot_readiness_limiter,
    pilot_usage_limiter,
    wallet_ownership_limiter,
)


def reset_all_limiters() -> None:
    """Reset all shared route rate limiters (intended for test isolation)."""
    for limiter in ALL_LIMITERS:
        limiter.reset()
