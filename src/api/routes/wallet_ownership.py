"""EOA wallet challenge/attestation extension, separate from legacy proof issuance."""

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field, ValidationError

from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.transfer import Hex32, Record
from src.protocol.wallet_ownership import WalletOwnershipError
from src.services.enrollment import EnrollmentIneligible, EnrollmentIntegrityError, EnrollmentNotFound
from src.services.wallet_ownership import WalletChallengeLimit, WalletEvidenceNotFound, WalletOwnershipService
from src.storage.keyring import load_keyring
from src.storage.pilot import RecordConflict
from src.storage.pilot_cipher import RecordCipher

router = APIRouter(prefix="/wallet/ownership", tags=["wallet-ownership"])


class ChallengeRequest(Record):
    credential_id: Hex32


class VerifyRequest(Record):
    nonce: Hex32
    signature: str = Field(pattern=r"^0x[0-9a-f]{130}$", min_length=132, max_length=132)


class AttestationRequest(Record):
    attestation_id: Hex32


def wallet_service(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
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


async def invoke(operation):
    try:
        return await operation
    except (EnrollmentNotFound, WalletEvidenceNotFound) as exc:
        raise HTTPException(status_code=404, detail="Wallet evidence or enrollment not found") from exc
    except WalletChallengeLimit as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except RecordConflict as exc:
        raise HTTPException(status_code=409, detail="Wallet challenge or evidence already exists") from exc
    except EnrollmentIntegrityError as exc:
        raise HTTPException(status_code=503, detail="Retained enrollment integrity failed") from exc
    except (WalletOwnershipError, EnrollmentIneligible, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="Wallet evidence is invalid, expired or revoked") from exc


@router.post("/challenge", summary="Prepare a five-minute EOA signature challenge")
async def challenge(request: ChallengeRequest, service=Depends(wallet_service)):
    value = await invoke(service.challenge(request.credential_id))
    return {
        "challenge": value.model_dump(mode="json"),
        "message": value.message(),
        "wallet_address": value.credential.subject_wallet,
        "vasp_did": value.credential.issuer_did,
        "timestamp": value.timestamp,
        "nonce": value.nonce,
        "expires_at": value.expires_at,
    }


@router.post("/verify", summary="Consume a challenge and retain a 24-hour attestation")
async def verify(request: VerifyRequest, service=Depends(wallet_service)):
    value = await invoke(service.verify(request.nonce, request.signature))
    return {
        "attestation_id": value.attestation_id,
        "issued_at": value.issued_at,
        "expires_at": value.expires_at,
        "wallet_ownership_verified": True,
    }


@router.get("/attestations/{attestation_id}", summary="Check current wallet evidence eligibility")
async def status(attestation_id: Hex32, service=Depends(wallet_service)):
    return await invoke(service.status(attestation_id))


@router.post("/revoke", summary="Revoke an attestation within its authenticated issuer scope")
async def revoke(request: AttestationRequest, service=Depends(wallet_service)):
    return await invoke(service.revoke(request.attestation_id))


@router.post("/credential", summary="Issue a versioned wallet-ownership credential extension")
async def credential(request: AttestationRequest, service=Depends(wallet_service)):
    value = await invoke(service.issue_extension(request.attestation_id))
    return {
        "extension": value.model_dump(mode="json"),
        "commitment": value.commitment,
        "proof_support": "staged-witness-only",
    }
