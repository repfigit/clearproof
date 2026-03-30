"""
Credential issuance, revocation, and status endpoints.

POST /credential/issue              — Issue a new zkKYC credential.
POST /credential/revoke             — Revoke an existing credential.
GET  /credential/{credential_id}    — Retrieve credential status (not full data).
"""

import logging
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from src.api.middleware.auth import JWTAuthDependency

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credential", tags=["credential"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CredentialIssueRequest(BaseModel):
    """Request body for POST /credential/issue."""

    issuer_did: str = Field(..., description="DID of the credential issuer (VASP / KYC provider)")
    subject_wallet: str = Field(..., description="Wallet address of the credentialed subject")
    jurisdiction: str = Field(..., min_length=2, max_length=2, description="ISO 3166-1 alpha-2")
    kyc_tier: str = Field(
        ...,
        description="KYC verification tier: basic, standard, or enhanced",
        pattern=r"^(basic|standard|enhanced)$",
    )
    expires_in_seconds: int = Field(
        default=31536000,
        gt=0,
        description="Credential TTL in seconds (default: 1 year)",
    )


class CredentialIssueResponse(BaseModel):
    """Response body for POST /credential/issue."""

    credential_id: str
    commitment: str
    issuer_did: str
    subject_wallet: str
    jurisdiction: str
    kyc_tier: str
    issued_at: int
    expires_at: int


class CredentialRevokeRequest(BaseModel):
    """Request body for POST /credential/revoke."""

    credential_id: str
    reason: Optional[str] = Field(None, description="Human-readable revocation reason")


class CredentialRevokeResponse(BaseModel):
    """Response body for POST /credential/revoke."""

    revoked: bool
    credential_id: str
    revoked_at: int


class CredentialStatusResponse(BaseModel):
    """Response body for GET /credential/{credential_id}."""

    credential_id: str
    status: str  # "active", "revoked", "expired"
    issuer_did: str
    jurisdiction: str
    kyc_tier: str
    issued_at: int
    expires_at: int
    revoked: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/issue", response_model=CredentialIssueResponse, summary="Issue zkKYC credential")
async def issue_credential(
    request: CredentialIssueRequest,
    _auth: dict = Depends(JWTAuthDependency),
):
    """
    Issue a new zkKYC credential and register it in the credential registry.

    The returned commitment is a Poseidon hash of the credential fields,
    suitable for inclusion in Merkle trees and ZK circuit inputs.
    """
    from src.registry.credential_registry import create_credential, register_credential

    now = int(time.time())
    expires_at = now + request.expires_in_seconds

    credential = create_credential(
        issuer_did=request.issuer_did,
        subject_wallet=request.subject_wallet,
        jurisdiction=request.jurisdiction,
        kyc_tier=request.kyc_tier,
        issued_at=now,
        expires_at=expires_at,
    )

    register_credential(credential)

    logger.info(
        "Credential issued: id=%s issuer=%s subject=%s jurisdiction=%s",
        credential.credential_id,
        request.issuer_did,
        request.subject_wallet,
        request.jurisdiction,
    )

    return CredentialIssueResponse(
        credential_id=credential.credential_id,
        commitment=credential.commitment(),
        issuer_did=credential.issuer_did,
        subject_wallet=request.subject_wallet,
        jurisdiction=credential.jurisdiction,
        kyc_tier=credential.kyc_tier,
        issued_at=credential.issued_at,
        expires_at=credential.expires_at,
    )


@router.post("/revoke", response_model=CredentialRevokeResponse, summary="Revoke credential")
async def revoke_credential(
    request: CredentialRevokeRequest,
    _auth: dict = Depends(JWTAuthDependency),
):
    """
    Revoke a previously-issued zkKYC credential.

    Revoked credentials will fail any subsequent proof generation attempt.
    """
    from src.registry.credential_registry import get_credential, revoke_credential as do_revoke

    credential = get_credential(request.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    if credential.revoked:
        raise HTTPException(status_code=400, detail="Credential already revoked")

    do_revoke(request.credential_id, reason=request.reason)

    logger.info(
        "Credential revoked: id=%s reason=%s",
        request.credential_id,
        request.reason,
    )

    return CredentialRevokeResponse(
        revoked=True,
        credential_id=request.credential_id,
        revoked_at=int(time.time()),
    )


@router.get(
    "/{credential_id}",
    response_model=CredentialStatusResponse,
    summary="Get credential status",
)
async def get_credential_status(
    credential_id: str,
    _auth: dict = Depends(JWTAuthDependency),
):
    """
    Retrieve the status of a credential (active / revoked / expired).

    Does **not** return the full credential data or PII — only metadata
    sufficient for the caller to decide whether to proceed with proof generation.
    """
    from src.registry.credential_registry import get_credential

    credential = get_credential(credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    now = int(time.time())
    if credential.revoked:
        status = "revoked"
    elif credential.expires_at < now:
        status = "expired"
    else:
        status = "active"

    return CredentialStatusResponse(
        credential_id=credential_id,
        status=status,
        issuer_did=credential.issuer_did,
        jurisdiction=credential.jurisdiction,
        kyc_tier=credential.kyc_tier,
        issued_at=credential.issued_at,
        expires_at=credential.expires_at,
        revoked=credential.revoked,
    )
