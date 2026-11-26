"""Sign In With Ethereum (SIWE) authentication.

Flow:
1. Client calls GET /auth/nonce -> receives random nonce
2. Client signs EIP-4361 message with wallet
3. Client calls POST /auth/verify with {message, signature}
4. Server verifies signature + nonce -> returns session token
5. Subsequent requests use session token in Authorization header

Session persistence
-------------------
- When PostgreSQL is configured (``DATABASE_URL`` set and ``db`` passed to
  ``SIWEAuth``), sessions are persisted in ``siwe_sessions`` keyed by the
  SHA-256 hash of the session token with DB-clock TTL expiry and bounded LRU
  eviction, allowing any API worker or replica to validate any issued session.
- When Redis is explicitly supplied (``redis_client``), nonces and sessions
  are stored in Redis.
- **In-memory fallback (when ``DATABASE_URL`` and Redis are absent):** sessions
  are stored in a process-local bounded ``OrderedDict`` (``BoundedSessionStore``)
  with TTL sweep on read/write and LRU eviction. This fallback is single-process
  only; configure ``DATABASE_URL`` (or Redis) for multi-worker deployments.
"""

import logging
import os
import secrets
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from siwe import SiweMessage

from src.storage.api_state import PostgresSIWENonceStore, PostgresSIWESessionStore
from src.storage.database import Database

logger = logging.getLogger(__name__)

_NONCE_TTL_SECONDS = int(os.getenv("SIWE_NONCE_TTL", "300"))  # 5 minutes
_SESSION_TTL_SECONDS = int(os.getenv("SIWE_SESSION_TTL", "86400"))  # 24 hours
DEFAULT_MAX_SESSIONS = 10_000
DEFAULT_MAX_NONCES = 10_000


def siwe_max_sessions() -> int:
    """Parse ``SIWE_MAX_SESSIONS`` (default 10000, positive integer)."""
    raw = os.getenv("SIWE_MAX_SESSIONS")
    if raw is None or not raw.strip():
        return DEFAULT_MAX_SESSIONS
    value = int(raw.strip())
    if value <= 0:
        raise ValueError("SIWE_MAX_SESSIONS must be a positive integer")
    return value


def siwe_max_nonces() -> int:
    """Parse ``SIWE_MAX_NONCES`` (default 10000, positive integer)."""
    raw = os.getenv("SIWE_MAX_NONCES")
    if raw is None or not raw.strip():
        return DEFAULT_MAX_NONCES
    value = int(raw.strip())
    if value <= 0:
        raise ValueError("SIWE_MAX_NONCES must be a positive integer")
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


# Bounded in-memory nonce store (fallback when neither PostgreSQL nor Redis is configured)
_nonce_store: OrderedDict[str, float] = OrderedDict()  # nonce -> created_at


class SIWEAuth:
    """SIWE authentication handler.

    Supports PostgreSQL-backed (``db`` / ``session_store`` / ``nonce_store``),
    Redis-backed, and bounded in-memory (fallback when ``DATABASE_URL`` is
    absent) nonce and session storage.
    """

    def __init__(
        self,
        domain: str,
        redis_client: Any | None = None,
        *,
        db: Database | None = None,
        session_store: PostgresSIWESessionStore | None = None,
        nonce_store: PostgresSIWENonceStore | None = None,
        max_sessions: int | None = None,
        max_nonces: int | None = None,
    ) -> None:
        """
        Args:
            domain: The expected domain in SIWE messages (e.g. "app.clearproof.io").
            redis_client: Optional async Redis client.
            db: Optional connected PostgreSQL ``Database`` for multi-worker nonce and session persistence.
            session_store: Optional explicit ``PostgresSIWESessionStore`` (overrides ``db``).
            nonce_store: Optional explicit ``PostgresSIWENonceStore`` (overrides ``db``).
            max_sessions: Optional cap on stored sessions (defaults to ``SIWE_MAX_SESSIONS``).
            max_nonces: Optional cap on stored nonces (defaults to ``SIWE_MAX_NONCES``).
        """
        self.domain = domain
        self.redis = redis_client
        cap = siwe_max_sessions() if max_sessions is None else max_sessions
        nonce_cap = siwe_max_nonces() if max_nonces is None else max_nonces
        if nonce_cap <= 0:
            raise ValueError("max_nonces must be a positive integer")
        self._max_nonces = nonce_cap
        self._sessions = BoundedSessionStore(max_entries=cap)
        if session_store is not None:
            self._pg_sessions: PostgresSIWESessionStore | None = session_store
        elif db is not None:
            self._pg_sessions = PostgresSIWESessionStore(db, max_entries=cap)
        else:
            self._pg_sessions = None
        if nonce_store is not None:
            self._pg_nonces: PostgresSIWENonceStore | None = nonce_store
        elif db is not None:
            self._pg_nonces = PostgresSIWENonceStore(db, max_entries=nonce_cap)
        else:
            self._pg_nonces = None

    def bind_database(self, db: Database) -> None:
        """Attach a connected PostgreSQL ``Database`` for multi-worker nonce and session persistence."""
        self._pg_sessions = PostgresSIWESessionStore(db, max_entries=self._sessions.max_entries)
        self._pg_nonces = PostgresSIWENonceStore(db, max_entries=self._max_nonces)

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
        elif self._pg_nonces is not None:
            await self._pg_nonces.create(nonce, ttl_seconds=_NONCE_TTL_SECONDS)
        else:
            self._purge_expired_nonces()
            while len(_nonce_store) >= self._max_nonces:
                del _nonce_store[next(iter(_nonce_store))]
            _nonce_store[nonce] = time.time()

        return nonce

    async def _consume_nonce(self, nonce: str) -> bool:
        """Check that a nonce exists and has not expired, then delete it.

        Returns True if the nonce was valid.
        """
        if self.redis is not None:
            result = await self.redis.delete(f"siwe:nonce:{nonce}")
            return result > 0

        if self._pg_nonces is not None:
            return await self._pg_nonces.consume(nonce)

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

        # Build and store session
        session_token = secrets.token_urlsafe(48)

        if self.redis is not None:
            import json

            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=_SESSION_TTL_SECONDS)
            session_data = {
                "address": siwe_msg.address,
                "chain_id": siwe_msg.chain_id,
                "session_token": session_token,
                "expires_at": expires_at.isoformat(),
                "created_at": now.isoformat(),
            }
            await self.redis.setex(
                f"siwe:session:{session_token}",
                _SESSION_TTL_SECONDS,
                json.dumps(session_data),
            )
            return session_data

        if self._pg_sessions is not None:
            return await self._pg_sessions.set(
                session_token,
                address=siwe_msg.address,
                chain_id=siwe_msg.chain_id,
                ttl_seconds=_SESSION_TTL_SECONDS,
            )

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=_SESSION_TTL_SECONDS)
        session_data = {
            "address": siwe_msg.address,
            "chain_id": siwe_msg.chain_id,
            "session_token": session_token,
            "expires_at": expires_at.isoformat(),
            "created_at": now.isoformat(),
        }
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

        if self._pg_sessions is not None:
            return await self._pg_sessions.get(token)

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
