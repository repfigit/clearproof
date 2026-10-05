"""
In-memory sliding-window rate limiter.

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

Client identity, strongest first:

1. ``PrincipalRateLimiter``: the authenticated principal (``sub`` claim from
   ``JWTAuthDependency``), hashed.
2. In ``api-key`` auth mode, a header that matches the configured key:
   SHA-256 of the key combined with the client IP. Raw keys are never stored.
3. Otherwise the client IP. An unauthenticated caller cannot mint fresh
   buckets by sending random ``X-API-Key`` values.

Windows that have gone idle are evicted, so memory is bounded by the number
of clients active within one window.
"""

import hashlib
import hmac
import time
from collections import deque
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request

from src.api.middleware import auth as _auth
from src.api.middleware.auth import JWTAuthDependency


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


class RateLimiter:
    """
    Sliding-window rate limiter backed by an in-memory dict.

    When the limit is exceeded the dependency raises HTTP 429.

    Parameters
    ----------
    max_requests : int
        Maximum number of requests allowed within *window_seconds*.
    window_seconds : float
        Length of the sliding window in seconds.
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # client_key -> request timestamps (oldest first)
        self._requests: dict[str, deque[float]] = {}
        self._last_sweep = time.monotonic()

    # ------------------------------------------------------------------
    # FastAPI dependency interface
    # ------------------------------------------------------------------

    async def __call__(self, request: Request) -> None:
        self._hit(self._identify_client(request))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _hit(self, client_key: str) -> None:
        now = time.monotonic()
        window_start = now - self.window_seconds
        self._sweep(now, window_start)

        timestamps = self._requests.get(client_key)
        if timestamps is None:
            timestamps = self._requests[client_key] = deque()
        while timestamps and timestamps[0] <= window_start:
            timestamps.popleft()

        if len(timestamps) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - timestamps[0])) + 1
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(now)

    def _sweep(self, now: float, window_start: float) -> None:
        """Drop clients whose newest request is outside the window (at most once per window)."""
        if now - self._last_sweep < self.window_seconds:
            return
        self._last_sweep = now
        for client_key in [key for key, stamps in self._requests.items() if not stamps or stamps[-1] <= window_start]:
            del self._requests[client_key]

    @staticmethod
    def _identify_client(request: Request, principal: Optional[str] = None) -> str:
        """Derive a rate-limit key without retaining raw credentials."""
        if principal:
            return f"principal:{_digest(principal)}"

        # request.client can be None behind certain proxies
        host = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key") or ""
        configured = _auth.API_KEY
        if (
            api_key
            and configured
            and _auth.AUTH_MODE.lower() == "api-key"
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
        self._hit(self._identify_client(request, principal))
