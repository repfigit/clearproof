"""
JWT, API-key, and SIWE session authentication middleware.

AUTH_MODE env var controls the active scheme:
  - "siwe"    — Verify session tokens from SIWE (Sign In With Ethereum) flow.
  - "jwt"     — Verify ES256 JWT Bearer tokens (production).
  - "api-key" — Verify a static API key via X-API-Key header (MVP / dev).

JWTAuthDependency is a FastAPI dependency injected into protected routes.
"""

import hashlib
import hmac
import logging
import os
import time
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_MODE: str = os.getenv("AUTH_MODE", "api-key")  # "siwe", "jwt", or "api-key"
API_KEY: str = os.getenv("API_KEY", "")  # required when AUTH_MODE=api-key
JWT_PUBLIC_KEY: Optional[str] = os.getenv("JWT_PUBLIC_KEY")  # PEM-encoded ES256 public key
JWT_ISSUER: str = os.getenv("JWT_ISSUER", "zk-travel-rule")
JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "zk-travel-rule-api")

_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# JWT verification
# ---------------------------------------------------------------------------

def verify_jwt_token(token: str) -> dict:
    """
    Verify an ES256 JWT and return its decoded claims.

    Raises HTTPException(401) on any verification failure.

    Requires the ``PyJWT`` and ``cryptography`` packages at runtime
    (imported lazily so the rest of the app can start without them
    when running in api-key mode).
    """
    try:
        import jwt  # PyJWT
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail="JWT verification unavailable — PyJWT not installed",
        ) from exc

    if not JWT_PUBLIC_KEY:
        raise HTTPException(
            status_code=500,
            detail="JWT_PUBLIC_KEY environment variable not set",
        )

    try:
        claims = jwt.decode(
            token,
            JWT_PUBLIC_KEY,
            algorithms=["ES256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")

    return claims


# ---------------------------------------------------------------------------
# API-key verification
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SIWE session verification
# ---------------------------------------------------------------------------

async def _verify_siwe_session(token: str) -> dict:
    """
    Validate a SIWE session token and return its session data as claims.

    Raises HTTPException(401) if the token is invalid or expired.
    """
    from src.auth.siwe_auth import SIWEAuth

    domain = os.environ.get("SIWE_DOMAIN", "localhost")
    siwe_auth = SIWEAuth(domain=domain)
    session = await siwe_auth.validate_session(token)

    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired SIWE session")

    return {
        "sub": session["address"],
        "chain_id": session.get("chain_id"),
        "iat": int(time.time()),
        "auth_mode": "siwe",
    }


# ---------------------------------------------------------------------------
# API-key verification
# ---------------------------------------------------------------------------

def _verify_api_key(provided: str) -> dict:
    """
    Constant-time comparison of the provided key against the stored key.

    Returns a minimal claims dict on success.
    """
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="API_KEY environment variable not set",
        )

    if not hmac.compare_digest(provided, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {"sub": "api-key-user", "iat": int(time.time())}


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

async def JWTAuthDependency(request: Request) -> dict:  # noqa: N802 — uppercase to match task spec naming
    """
    FastAPI dependency that validates the caller's credentials.

    In **jwt** mode the caller must supply a ``Bearer <token>`` header.
    In **api-key** mode the caller must supply an ``X-API-Key`` header.

    Returns the decoded claims dict on success; raises 401 otherwise.
    """
    mode = AUTH_MODE.lower()

    if mode == "siwe":
        credentials: Optional[HTTPAuthorizationCredentials] = await _bearer_scheme(request)
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Missing Bearer token (SIWE session)")
        return await _verify_siwe_session(credentials.credentials)

    if mode == "jwt":
        credentials = await _bearer_scheme(request)
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Missing Bearer token")
        return verify_jwt_token(credentials.credentials)

    if mode == "api-key":
        api_key = request.headers.get("X-API-Key", "")
        if not api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        return _verify_api_key(api_key)

    # Unknown mode — fail closed.
    raise HTTPException(status_code=500, detail=f"Unknown AUTH_MODE: {mode}")
