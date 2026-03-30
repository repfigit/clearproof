"""
In-memory sliding-window rate limiter.

Usage as a FastAPI dependency::

    from src.api.middleware.rate_limit import RateLimiter

    _proof_limiter = RateLimiter(max_requests=30, window_seconds=60)

    @router.post("/generate")
    async def generate_proof(
        request: ProofGenerateRequest,
        _rl: None = Depends(_proof_limiter),
    ):
        ...
"""

import time
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, Request


class RateLimiter:
    """
    Sliding-window rate limiter backed by an in-memory dict.

    Each unique client (identified by IP or ``X-API-Key``) gets its own
    window.  When the limit is exceeded the dependency raises HTTP 429.

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
        # client_key -> list of request timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)

    # ------------------------------------------------------------------
    # FastAPI dependency interface
    # ------------------------------------------------------------------

    async def __call__(self, request: Request) -> None:
        client_key = self._identify_client(request)
        now = time.monotonic()
        window_start = now - self.window_seconds

        # Prune expired entries
        timestamps = self._requests[client_key]
        self._requests[client_key] = [t for t in timestamps if t > window_start]

        if len(self._requests[client_key]) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - self._requests[client_key][0])) + 1
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )

        self._requests[client_key].append(now)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _identify_client(request: Request) -> str:
        """
        Derive a rate-limit key from the request.

        Prefer the ``X-API-Key`` header (deterministic per caller) and
        fall back to the client IP.
        """
        api_key: Optional[str] = request.headers.get("X-API-Key")
        if api_key:
            return f"key:{api_key}"

        # request.client can be None behind certain proxies
        host = request.client.host if request.client else "unknown"
        return f"ip:{host}"
