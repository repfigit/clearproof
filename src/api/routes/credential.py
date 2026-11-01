"""
Credential issuance, revocation, and status endpoints.

POST /credential/issue              — Issue a new zkKYC credential.
POST /credential/revoke             — Revoke an existing credential.
GET  /credential/{credential_id}    — Retrieve credential status (not full data).
"""

import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.api.dependencies import get_credential_registry
from src.api.middleware.auth import JWTAuthDependency
from src.auth.principal import Principal, TenantPrincipalDependency
from src.registry.credential_registry import CredentialRegistry, zkKYCCredential
from src.services.enrollment import EnrollmentIneligible, EnrollmentIntegrityError, EnrollmentNotFound
from src.services.wallet_ownership import WalletOwnershipError, WalletOwnershipService
from src.storage.keyring import load_keyring
from src.storage.pilot_cipher import RecordCipher

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
        description="KYC verification tier: retail, professional, or institutional",
        pattern=r"^(retail|professional|institutional)$",
    )
    expires_in_seconds: int = Field(
        default=31536000,
        gt=0,
        description="Credential TTL in seconds (default: 1 year)",
    )
    wallet_ownership_attestation_id: Optional[str] = Field(
        None,
        description=(
            "Optional wallet-ownership attestation identifier (from POST /wallet/ownership/verify). "
            "When present, the attestation must currently be active and belong to subject_wallet; "
            "the issued credential then records wallet_ownership_verified=true. Evidence-based "
            "proof-level commitments remain governed by the staged wallet-ownership profile."
        ),
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
    wallet_ownership_verified: bool = False
    wallet_ownership_attestation_id: Optional[str] = None


def _wallet_ownership_service(request: Request, principal: Principal) -> WalletOwnershipService:
    """Build the wallet-ownership service in this request's tenant scope (fail closed)."""
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Wallet evidence database unavailable")
    try:
        return WalletOwnershipService(
            db,
            RecordCipher(load_keyring()),
            principal,
            chain_id=int(os.environ["PILOT_CHAIN_ID"]),
            registry_address=os.environ["PILOT_REGISTRY_ADDRESS"],
        )
    except (KeyError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Wallet evidence configuration unavailable") from exc


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
    http: Request,
    _auth: dict = Depends(JWTAuthDependency),
    principal: Principal = Depends(TenantPrincipalDependency),
    _registry: CredentialRegistry = Depends(get_credential_registry),
):
    """
    Issue a new zkKYC credential and register it in the credential registry.

    The returned commitment is a Poseidon hash of the credential fields,
    suitable for inclusion in Merkle trees and ZK circuit inputs.

    When wallet_ownership_attestation_id is supplied, the wallet-ownership
    attestation must currently be active (unexpired, unrevoked, no delegation
    review) and must belong to subject_wallet; the issued credential then
    carries wallet_ownership_verified=true with the attestation identifier
    recorded. The Poseidon commitment is unchanged: the legacy credential
    preimage has no circuit counterpart for this field, and evidence-level
    commitments live in the staged wallet-ownership extension profile.
    """
    now = int(time.time())
    expires_at = now + request.expires_in_seconds

    if request.wallet_ownership_attestation_id is not None:
        service = _wallet_ownership_service(http, principal)
        try:
            await service.assert_active(
                request.wallet_ownership_attestation_id,
                subject_wallet=request.subject_wallet,
                now=now,
            )
        except WalletOwnershipError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Wallet ownership attestation is not eligible: {exc}",
            ) from exc
        except (EnrollmentNotFound, EnrollmentIntegrityError, EnrollmentIneligible) as exc:
            raise HTTPException(
                status_code=422, detail="Wallet ownership attestation enrollment is not eligible"
            ) from exc

    credential = zkKYCCredential(
        issuer_did=request.issuer_did,
        subject_wallet=request.subject_wallet,
        jurisdiction=request.jurisdiction,
        kyc_tier=request.kyc_tier,
        sanctions_clear=True,
        issued_at=now,
        expires_at=expires_at,
        wallet_ownership_verified=request.wallet_ownership_attestation_id is not None,
        wallet_ownership_attestation_id=request.wallet_ownership_attestation_id,
    )

    commitment = await _registry.issue(credential)

    logger.info(
        "Credential issued: id=%s wallet_ownership_verified=%s",
        credential.credential_id,
        credential.wallet_ownership_verified,
    )

    return CredentialIssueResponse(
        credential_id=credential.credential_id,
        commitment=commitment,
        issuer_did=credential.issuer_did,
        subject_wallet=request.subject_wallet,
        jurisdiction=credential.jurisdiction,
        kyc_tier=credential.kyc_tier,
        issued_at=credential.issued_at,
        expires_at=credential.expires_at,
        wallet_ownership_verified=credential.wallet_ownership_verified,
        wallet_ownership_attestation_id=credential.wallet_ownership_attestation_id,
    )


@router.post("/revoke", response_model=CredentialRevokeResponse, summary="Revoke credential")
async def revoke_credential(
    request: CredentialRevokeRequest,
    _auth: dict = Depends(JWTAuthDependency),
    _registry: CredentialRegistry = Depends(get_credential_registry),
):
    """
    Revoke a previously-issued zkKYC credential.

    Revoked credentials will fail any subsequent proof generation attempt.
    """
    credential = _registry.get(request.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    if credential.revoked:
        raise HTTPException(status_code=400, detail="Credential already revoked")

    _registry.revoke(request.credential_id)

    logger.info("Credential revoked: id=%s", request.credential_id)

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
    _registry: CredentialRegistry = Depends(get_credential_registry),
):
    """
    Retrieve the status of a credential (active / revoked / expired).

    Does **not** return the full credential data or PII — only metadata
    sufficient for the caller to decide whether to proceed with proof generation.
    """
    credential = _registry.get(credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    now = int(time.time())
    if credential.revoked:
        status = "revoked"
    elif credential.expires_at <= now:
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
