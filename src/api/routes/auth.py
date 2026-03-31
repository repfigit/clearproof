"""
SIWE (Sign In With Ethereum) authentication routes.

GET  /auth/nonce  — Generate a random nonce for SIWE message construction.
POST /auth/verify — Verify a signed SIWE message and return a session token.
"""

import logging
import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.auth.siwe_auth import SIWEAuth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Module-level SIWE handler (lazy init)
_siwe: SIWEAuth | None = None


def _get_siwe() -> SIWEAuth:
    global _siwe
    if _siwe is None:
        domain = os.environ.get("SIWE_DOMAIN", "localhost")
        _siwe = SIWEAuth(domain=domain)
    return _siwe


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class NonceResponse(BaseModel):
    nonce: str = Field(..., description="Random nonce to include in the SIWE message")


class VerifyRequest(BaseModel):
    message: str = Field(..., description="The full EIP-4361 SIWE message string")
    signature: str = Field(..., description="Ethereum signature of the message (0x-prefixed hex)")


class VerifyResponse(BaseModel):
    session_token: str = Field(..., description="Bearer token for subsequent API calls")
    address: str = Field(..., description="Verified Ethereum address")
    chain_id: int = Field(..., description="Chain ID from the SIWE message")
    expires_at: str = Field(..., description="ISO-8601 session expiry timestamp")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/nonce", response_model=NonceResponse, summary="Generate SIWE nonce")
async def get_nonce():
    """Generate a random nonce for constructing a SIWE message.

    The nonce is valid for 5 minutes and can only be used once.
    """
    siwe = _get_siwe()
    nonce = await siwe.generate_nonce()
    return NonceResponse(nonce=nonce)


@router.post("/verify", response_model=VerifyResponse, summary="Verify SIWE signature")
async def verify_signature(body: VerifyRequest):
    """Verify a signed SIWE message and issue a session token.

    The client must:
    1. Request a nonce via GET /auth/nonce
    2. Build an EIP-4361 message including that nonce
    3. Sign the message with their Ethereum wallet
    4. Submit the message + signature here

    On success, returns a session token usable as a Bearer token.
    """
    siwe = _get_siwe()
    try:
        session = await siwe.verify(body.message, body.signature)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    return VerifyResponse(
        session_token=session["session_token"],
        address=session["address"],
        chain_id=session["chain_id"],
        expires_at=session["expires_at"],
    )
