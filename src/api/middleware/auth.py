"""
JWT, API-key, and SIWE session authentication middleware.

AUTH_MODE env var controls the active scheme:
  - "siwe"    — Verify session tokens from SIWE (Sign In With Ethereum) flow.
  - "jwt"     — Verify ES256 JWT Bearer tokens (production).
  - "api-key" — Verify a static API key via X-API-Key header (MVP / dev).

JWTAuthDependency is a FastAPI dependency injected into protected routes.
"""

import hmac
import logging
import os
import time
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.api.config import AuthConfig, get_siwe_auth, resolve_auth_config

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


def verify_jwt_token(token: str, *, config: Optional[AuthConfig] = None) -> dict:
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

    public_key = JWT_PUBLIC_KEY if config is None else config.jwt_public_key
    issuer = JWT_ISSUER if config is None else config.jwt_issuer
    audience = JWT_AUDIENCE if config is None else config.jwt_audience

    if not public_key:
        raise HTTPException(
            status_code=500,
            detail="JWT_PUBLIC_KEY environment variable not set",
        )

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")

    return claims


# ---------------------------------------------------------------------------
# SIWE session verification
# ---------------------------------------------------------------------------


async def _verify_siwe_session(token: str, *, config: Optional[AuthConfig] = None, siwe_auth=None) -> dict:
    """
    Validate a SIWE session token and return its session data as claims.

    Raises HTTPException(401) if the token is invalid or expired.
    """
    from src.auth.siwe_auth import SIWEAuth

    if siwe_auth is None:
        domain = os.environ.get("SIWE_DOMAIN", "localhost") if config is None else config.siwe_domain
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


def _verify_api_key(provided: str, *, config: Optional[AuthConfig] = None) -> dict:
    """
    Constant-time comparison of the provided key against the stored key.

    Returns a minimal claims dict on success.
    """
    expected_key = API_KEY if config is None else config.api_key
    if not expected_key:
        raise HTTPException(
            status_code=500,
            detail="API_KEY environment variable not set",
        )

    if not hmac.compare_digest(provided, expected_key):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {"sub": "api-key-user", "iat": int(time.time())}


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def JWTAuthDependency(request: Request) -> dict:  # noqa: N802 — uppercase to match task spec naming
    """
    FastAPI dependency that validates the caller's credentials.

    Reads ``app.state.auth_config`` populated during FastAPI lifespan startup
    (falling back to module defaults when a test constructs a bare app without
    running lifespan).

    In **jwt** mode the caller must supply a ``Bearer <token>`` header.
    In **api-key** mode the caller must supply an ``X-API-Key`` header.

    Returns the decoded claims dict on success; raises 401 otherwise.
    """
    config = resolve_auth_config(request)
    mode = config.auth_mode.lower()

    if mode == "siwe":
        credentials: Optional[HTTPAuthorizationCredentials] = await _bearer_scheme(request)
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Missing Bearer token (SIWE session)")
        return await _verify_siwe_session(credentials.credentials, config=config, siwe_auth=get_siwe_auth(request))

    if mode == "jwt":
        credentials = await _bearer_scheme(request)
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Missing Bearer token")
        return verify_jwt_token(credentials.credentials, config=config)

    if mode == "api-key":
        api_key = request.headers.get("X-API-Key", "")
        if not api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        return _verify_api_key(api_key, config=config)

    # Unknown mode — fail closed.
    raise HTTPException(status_code=500, detail=f"Unknown AUTH_MODE: {mode}")
