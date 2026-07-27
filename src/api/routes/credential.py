"""
Credential issuance, revocation, and status endpoints.

POST /credential/issue              — Issue a new zkKYC credential.
POST /credential/revoke             — Revoke an existing credential.
GET  /credential/{credential_id}    — Retrieve credential status (not full data).
POST /credential/wallet/challenge   — Issue wallet ownership challenge (EU TFR).
POST /credential/wallet/verify      — Verify wallet ownership signature (EU TFR).
"""

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from web3 import Web3

from src.api.middleware.auth import JWTAuthDependency
from src.api.wallet_ownership import _verifier
from src.registry.credential_registry import CredentialRegistry, zkKYCCredential

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credential", tags=["credential"])

# Module-level singleton (C-3 fix: use CredentialRegistry class, not missing functions)
_registry = CredentialRegistry()


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
    attestation_id: str = Field(
        ...,
        description="Wallet ownership attestation ID from POST /credential/wallet/verify",
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
# Wallet Ownership Verification (EU TFR)
# ---------------------------------------------------------------------------


class WalletChallengeRequest(BaseModel):
    """Request body for POST /credential/wallet/challenge."""

    wallet_address: str = Field(..., description="Ethereum wallet address (0x-prefixed)")
    vasp_did: str = Field(..., description="VASP DID requesting verification")


class WalletChallengeResponse(BaseModel):
    """Response body for POST /credential/wallet/challenge."""

    wallet_address: str
    vasp_did: str
    timestamp: int
    nonce: str
    expires_at: int
    message: str  # Human-readable message to sign


class WalletVerifyRequest(BaseModel):
    """Request body for POST /credential/wallet/verify."""

    nonce: str = Field(..., description="Nonce from the challenge")
    signature: str = Field(..., description="EIP-191 signature (0x-prefixed hex)")


class WalletVerifyResponse(BaseModel):
    """Response body for POST /credential/wallet/verify."""

    attestation_id: str
    wallet_address: str
    vasp_did: str
    timestamp: int
    expires_at: int
    wallet_ownership_verified: bool = True


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
    if not _verifier.is_attestation_valid(request.attestation_id):
        raise HTTPException(status_code=400, detail="Invalid or expired wallet ownership attestation")

    attestation = _verifier.get_attestation(request.attestation_id)
    if attestation is None:
        raise HTTPException(status_code=400, detail="Invalid or expired wallet ownership attestation")

    subject_wallet = Web3.to_checksum_address(request.subject_wallet)
    if Web3.to_checksum_address(attestation.wallet_address) != subject_wallet:
        raise HTTPException(status_code=400, detail="Attestation wallet does not match subject wallet")

    now = int(time.time())
    expires_at = now + request.expires_in_seconds

    credential = zkKYCCredential(
        issuer_did=request.issuer_did,
        subject_wallet=subject_wallet,
        jurisdiction=request.jurisdiction,
        kyc_tier=request.kyc_tier,
        sanctions_clear=True,
        wallet_ownership_verified=True,
        issued_at=now,
        expires_at=expires_at,
    )

    commitment = await _registry.issue(credential)

    logger.info(
        "Credential issued: id=%s issuer=%s subject=%s jurisdiction=%s",
        credential.credential_id,
        request.issuer_did,
        request.subject_wallet,
        request.jurisdiction,
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
    credential = _registry.get(request.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    if credential.revoked:
        raise HTTPException(status_code=400, detail="Credential already revoked")

    _registry.revoke(request.credential_id)

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
    credential = _registry.get(credential_id)
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


# ---------------------------------------------------------------------------
# Wallet Ownership Verification Endpoints (EU TFR)
# ---------------------------------------------------------------------------


@router.post(
    "/wallet/challenge",
    response_model=WalletChallengeResponse,
    summary="Issue wallet ownership challenge (EU TFR)",
)
async def issue_wallet_challenge(
    request: WalletChallengeRequest,
    _auth: dict = Depends(JWTAuthDependency),
):
    """
    Issue a challenge for wallet ownership verification per EU TFR.

    The caller must sign the returned message with EIP-191 personal_sign
    and submit the signature to /wallet/verify.
    """
    challenge = _verifier.create_challenge(request.wallet_address, request.vasp_did)

    # Construct the message the user must sign
    message = (
        f"ClearProof Wallet Ownership Verification\n"
        f"Wallet: {challenge.wallet_address}\n"
        f"VASP: {challenge.vasp_did}\n"
        f"Timestamp: {challenge.timestamp}\n"
        f"Nonce: {challenge.nonce}"
    )

    logger.info(
        "Wallet ownership challenge issued: wallet=%s vasp=%s nonce=%s",
        challenge.wallet_address,
        request.vasp_did,
        challenge.nonce[:8] + "...",
    )

    return WalletChallengeResponse(
        wallet_address=challenge.wallet_address,
        vasp_did=challenge.vasp_did,
        timestamp=challenge.timestamp,
        nonce=challenge.nonce,
        expires_at=challenge.expires_at,
        message=message,
    )


@router.post(
    "/wallet/verify",
    response_model=WalletVerifyResponse,
    summary="Verify wallet ownership signature (EU TFR)",
)
async def verify_wallet_ownership(
    request: WalletVerifyRequest,
    _auth: dict = Depends(JWTAuthDependency),
):
    """
    Verify an EIP-191 signature against a pending wallet ownership challenge.

    On success, creates an attestation record that can be referenced by
    credential proof generation.
    """
    # Look up the pending challenge
    challenge = _verifier.get_pending_challenge(request.nonce)
    if challenge is None:
        raise HTTPException(status_code=400, detail="Challenge not found or expired")

    # Verify the signature
    signer = _verifier.verify_signature(challenge, request.signature)
    if signer is None:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Create attestation
    attestation = _verifier.create_attestation(challenge, request.signature)

    logger.info(
        "Wallet ownership verified: wallet=%s vasp=%s attestation=%s",
        attestation.wallet_address,
        attestation.vasp_did,
        attestation.attestation_id,
    )

    return WalletVerifyResponse(
        attestation_id=attestation.attestation_id,
        wallet_address=attestation.wallet_address,
        vasp_did=attestation.vasp_did,
        timestamp=attestation.timestamp,
        expires_at=attestation.expires_at,
        wallet_ownership_verified=True,
    )
