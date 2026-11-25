"""Sign In With Ethereum (SIWE) authentication.

Flow:
1. Client calls GET /auth/nonce -> receives random nonce
2. Client signs EIP-4361 message with wallet
3. Client calls POST /auth/verify with {message, signature}
4. Server verifies signature + nonce -> returns session token
5. Subsequent requests use session token in Authorization header

Nonces and sessions are stored in bounded in-memory OrderedDicts (with TTL
sweep on read/write and LRU eviction) when Redis is not configured.
When Redis is available, nonces and sessions are stored there instead.
"""

import logging
import os
import secrets
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from siwe import SiweMessage

logger = logging.getLogger(__name__)

_NONCE_TTL_SECONDS = int(os.getenv("SIWE_NONCE_TTL", "300"))  # 5 minutes
_SESSION_TTL_SECONDS = int(os.getenv("SIWE_SESSION_TTL", "86400"))  # 24 hours
DEFAULT_MAX_SESSIONS = 10_000


def siwe_max_sessions() -> int:
    """Parse ``SIWE_MAX_SESSIONS`` (default 10000, positive integer)."""
    raw = os.getenv("SIWE_MAX_SESSIONS")
    if raw is None or not raw.strip():
        return DEFAULT_MAX_SESSIONS
    value = int(raw.strip())
    if value <= 0:
        raise ValueError("SIWE_MAX_SESSIONS must be a positive integer")
    return value


class BoundedSessionStore:
    """Bounded LRU session store with TTL expiry sweep on read and write."""

    def __init__(self, max_entries: int = DEFAULT_MAX_SESSIONS) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        self._max_entries = max_entries
        self._entries: OrderedDict[str, dict[str, Any]] = OrderedDict()

    @property
    def max_entries(self) -> int:
        return self._max_entries

    def size(self) -> int:
        """Return the current number of stored sessions (test/diagnostic hook)."""
        return len(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, token: object) -> bool:
        return token in self._entries

    def __getitem__(self, token: str) -> dict[str, Any]:
        return self._entries[token]

    def sweep_expired(self, now: datetime | None = None) -> int:
        """Remove all entries whose ``expires_at`` is at or before ``now``."""
        current = datetime.now(timezone.utc) if now is None else now
        expired = [k for k, v in self._entries.items() if current >= datetime.fromisoformat(v["expires_at"])]
        for k in expired:
            del self._entries[k]
        return len(expired)

    def set(self, token: str, session_data: dict[str, Any]) -> None:
        """Store or refresh ``token``, sweeping expired entries and evicting LRU if full."""
        self.sweep_expired()
        if token in self._entries:
            self._entries.move_to_end(token)
            self._entries[token] = session_data
            return
        while len(self._entries) >= self._max_entries:
            self._entries.popitem(last=False)
        self._entries[token] = session_data

    def get(self, token: str) -> dict[str, Any] | None:
        """Return live session data for ``token`` (marking it MRU) or ``None``."""
        self.sweep_expired()
        session = self._entries.get(token)
        if session is None:
            return None
        self._entries.move_to_end(token)
        return session


# In-memory nonce store (used when Redis is not configured)
_nonce_store: dict[str, float] = {}  # nonce -> created_at


class SIWEAuth:
    """SIWE authentication handler.

    Supports both bounded in-memory and Redis-backed storage for nonces and sessions.
    """

    def __init__(
        self,
        domain: str,
        redis_client: Any | None = None,
        *,
        max_sessions: int | None = None,
    ) -> None:
        """
        Args:
            domain: The expected domain in SIWE messages (e.g. "app.clearproof.io").
            redis_client: Optional async Redis client. Falls back to in-memory stores.
            max_sessions: Optional cap on in-memory sessions (defaults to ``SIWE_MAX_SESSIONS``).
        """
        self.domain = domain
        self.redis = redis_client
        cap = siwe_max_sessions() if max_sessions is None else max_sessions
        self._sessions = BoundedSessionStore(max_entries=cap)

    def session_count(self) -> int:
        """Return the number of in-memory sessions currently retained (test hook)."""
        return self._sessions.size()

    # -- nonce management ------------------------------------------------------

    async def generate_nonce(self) -> str:
        """Generate and store a random nonce with TTL."""
        # EIP-4361 requires at least eight ASCII alphanumeric characters.
        nonce = secrets.token_hex(32)

        if self.redis is not None:
            await self.redis.setex(f"siwe:nonce:{nonce}", _NONCE_TTL_SECONDS, "1")
        else:
            self._purge_expired_nonces()
            _nonce_store[nonce] = time.time()

        return nonce

    async def _consume_nonce(self, nonce: str) -> bool:
        """Check that a nonce exists and has not expired, then delete it.

        Returns True if the nonce was valid.
        """
        if self.redis is not None:
            result = await self.redis.delete(f"siwe:nonce:{nonce}")
            return result > 0

        created_at = _nonce_store.pop(nonce, None)
        if created_at is None:
            return False
        if time.time() - created_at >= _NONCE_TTL_SECONDS:
            return False
        return True

    @staticmethod
    def _purge_expired_nonces() -> None:
        """Remove expired nonces from the in-memory store."""
        now = time.time()
        expired = [k for k, v in _nonce_store.items() if now - v >= _NONCE_TTL_SECONDS]
        for k in expired:
            del _nonce_store[k]

    # -- verification ----------------------------------------------------------

    async def verify(self, message: str, signature: str) -> dict:
        """Verify a SIWE message and return session data.

        Args:
            message: The EIP-4361 message string.
            signature: The Ethereum signature (hex, 0x-prefixed).

        Returns:
            {"address": "0x...", "chain_id": <int>, "session_token": "..."}

        Raises:
            ValueError: If the message is invalid, signature fails, nonce is
                expired/unknown, or the domain does not match.
        """
        try:
            siwe_msg = SiweMessage.from_message(message)
        except Exception as exc:
            raise ValueError(f"Malformed SIWE message: {exc}") from exc

        # Domain check
        if siwe_msg.domain != self.domain:
            raise ValueError(f"Domain mismatch: expected {self.domain}, got {siwe_msg.domain}")

        # Nonce check (consume before verification so replayed messages fail)
        if not await self._consume_nonce(siwe_msg.nonce):
            raise ValueError("Invalid or expired nonce")

        # Cryptographic signature verification
        try:
            siwe_msg.verify(signature)
        except Exception as exc:
            raise ValueError(f"Signature verification failed: {exc}") from exc

        # Build session
        session_token = secrets.token_urlsafe(48)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=_SESSION_TTL_SECONDS)

        session_data = {
            "address": siwe_msg.address,
            "chain_id": siwe_msg.chain_id,
            "session_token": session_token,
            "expires_at": expires_at.isoformat(),
            "created_at": now.isoformat(),
        }

        # Store session
        if self.redis is not None:
            import json

            await self.redis.setex(
                f"siwe:session:{session_token}",
                _SESSION_TTL_SECONDS,
                json.dumps(session_data),
            )
        else:
            self._sessions.set(session_token, session_data)

        return session_data

    # -- session validation ----------------------------------------------------

    async def validate_session(self, token: str) -> dict | None:
        """Validate a session token.

        Args:
            token: The session token from the Authorization header.

        Returns:
            Session data dict, or None if the token is invalid/expired.
        """
        if self.redis is not None:
            import json

            raw = await self.redis.get(f"siwe:session:{token}")
            if raw is None:
                return None
            return json.loads(raw)

        return self._sessions.get(token)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_siwe_auth_instance: SIWEAuth | None = None


def _get_siwe_auth() -> SIWEAuth:
    """Return a module-level SIWEAuth configured from env vars."""
    global _siwe_auth_instance
    if _siwe_auth_instance is None:
        domain = os.environ.get("SIWE_DOMAIN", "localhost")
        _siwe_auth_instance = SIWEAuth(domain=domain)
    return _siwe_auth_instance


async def verify_siwe(message: str, signature: str) -> dict:
    """Convenience wrapper around SIWEAuth.verify()."""
    auth = _get_siwe_auth()
    return await auth.verify(message, signature)
