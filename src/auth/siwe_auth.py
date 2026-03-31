"""Sign In With Ethereum (SIWE) authentication.

Flow:
1. Client calls GET /auth/nonce -> receives random nonce
2. Client signs EIP-4361 message with wallet
3. Client calls POST /auth/verify with {message, signature}
4. Server verifies signature + nonce -> returns session token
5. Subsequent requests use session token in Authorization header

Nonces stored in an in-memory dict with 5-minute TTL to prevent replay.
When Redis is available, nonces and sessions are stored there instead.
"""

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from siwe import SiweMessage

logger = logging.getLogger(__name__)

_NONCE_TTL_SECONDS = int(os.getenv("SIWE_NONCE_TTL", "300"))  # 5 minutes
_SESSION_TTL_SECONDS = int(os.getenv("SIWE_SESSION_TTL", "86400"))  # 24 hours

# In-memory stores (used when Redis is not configured)
_nonce_store: dict[str, float] = {}  # nonce -> created_at
_session_store: dict[str, dict[str, Any]] = {}  # token -> session_data


class SIWEAuth:
    """SIWE authentication handler.

    Supports both in-memory and Redis-backed storage for nonces and sessions.
    """

    def __init__(self, domain: str, redis_client: Any | None = None) -> None:
        """
        Args:
            domain: The expected domain in SIWE messages (e.g. "app.clearproof.io").
            redis_client: Optional async Redis client. Falls back to in-memory dicts.
        """
        self.domain = domain
        self.redis = redis_client

    # -- nonce management ------------------------------------------------------

    async def generate_nonce(self) -> str:
        """Generate and store a random nonce with TTL."""
        nonce = secrets.token_urlsafe(32)

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
        if time.time() - created_at > _NONCE_TTL_SECONDS:
            return False
        return True

    @staticmethod
    def _purge_expired_nonces() -> None:
        """Remove expired nonces from the in-memory store."""
        now = time.time()
        expired = [k for k, v in _nonce_store.items() if now - v > _NONCE_TTL_SECONDS]
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
            raise ValueError(
                f"Domain mismatch: expected {self.domain}, got {siwe_msg.domain}"
            )

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
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=_SESSION_TTL_SECONDS)

        session_data = {
            "address": siwe_msg.address,
            "chain_id": siwe_msg.chain_id,
            "session_token": session_token,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
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
            _session_store[session_token] = session_data

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

        session = _session_store.get(token)
        if session is None:
            return None

        # Check expiry
        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            del _session_store[token]
            return None

        return session


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
