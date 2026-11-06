"""Wallet ownership challenge/attestation endpoints (SIWE/EIP-4361 profile)."""

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field, ValidationError

from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.transfer import Hex32, Record
from src.protocol.wallet_ownership import WalletOwnershipError
from src.services.enrollment import EnrollmentIneligible, EnrollmentIntegrityError, EnrollmentNotFound
from src.services.wallet_ownership import (
    WalletChallengeLimit,
    WalletEvidenceNotFound,
    WalletOwnershipService,
)
from src.storage.keyring import load_keyring
from src.storage.pilot import RecordConflict
from src.storage.pilot_cipher import RecordCipher

router = APIRouter(prefix="/wallet/ownership", tags=["wallet-ownership"])


class ChallengeRequest(Record):
    credential_id: Hex32


class VerifyRequest(Record):
    nonce: Hex32
    # v2 smart-account signatures may be ERC-1271/ERC-6492 blobs; the service
    # enforces the 65-byte requirement on the EOA path.
    signature: str = Field(pattern=r"^0x[0-9a-fA-F]+$", min_length=4, max_length=8192)


class AttestationRequest(Record):
    attestation_id: Hex32


def wallet_chain(w3_module):
    """Shared AsyncWeb3 for the wallet-ownership chain integrations (or None)."""
    rpc_url = os.environ.get("WALLET_OWNERSHIP_RPC_URL")
    if not rpc_url:
        return None
    return w3_module.AsyncWeb3(w3_module.AsyncHTTPProvider(rpc_url))


def account_probe():
    """Delegation probe from WALLET_OWNERSHIP_RPC_URL, or None when unconfigured.

    The probe runs eth_getCode per address and classifies the EIP-7702
    delegation indicator. Unconfigured is a supported deployment posture:
    attestation records record the check as not performed instead of guessing.
    """
    from web3 import AsyncWeb3

    from src.chain.wallet_account import account_code, delegation_indicator

    w3 = wallet_chain(AsyncWeb3)
    if w3 is None:
        return None

    async def probe(address: str) -> dict:
        code = await account_code(w3, address)
        result = delegation_indicator(code)
        result["has_code"] = len(code) > 2
        return result

    return probe


def chain_verifier():
    """ERC-1271/ERC-6492 verifier over WALLET_OWNERSHIP_RPC_URL, or None."""
    from eth_account.messages import defunct_hash_message
    from web3 import AsyncWeb3

    from src.chain.wallet_account import verify_signature as verify_on_chain

    w3 = wallet_chain(AsyncWeb3)
    if w3 is None:
        return None

    async def verify(address: str, message: str, signature: str) -> tuple[bool, str]:
        # Smart wallets sign the SIWE message as personal_sign; ERC-1271
        # validators therefore receive the EIP-191 prehash of that message.
        digest = defunct_hash_message(text=message)
        return await verify_on_chain(w3, address, digest, signature)

    return verify


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
            account_probe=account_probe(),
            chain_verifier=chain_verifier(),
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


@router.post("/challenge", summary="Prepare a five-minute signature challenge (SIWE when PILOT_SIWE_DOMAIN is set)")
async def challenge(request: ChallengeRequest, service=Depends(wallet_service)):
    value = await invoke(service.challenge(request.credential_id, siwe_domain=os.environ.get("PILOT_SIWE_DOMAIN")))
    return {
        "challenge": value.model_dump(mode="json"),
        "message": value.message(),
        "message_format": "eip-4361" if hasattr(value, "siwe_domain") else "clearproof-canonical-v1",
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
        "method": getattr(value, "method", "eoa"),
        "message_format": "eip-4361" if hasattr(value.challenge, "siwe_domain") else "clearproof-canonical-v1",
    }


@router.get("/attestations/{attestation_id}", summary="Check current wallet evidence eligibility")
async def status(attestation_id: Hex32, service=Depends(wallet_service)):
    return await invoke(service.status(attestation_id))


@router.post("/revoke", summary="Revoke an attestation within its authenticated issuer scope")
async def revoke(request: AttestationRequest, service=Depends(wallet_service)):
    return await invoke(service.revoke(request.attestation_id))


@router.post("/delegation-check", summary="Force an immediate EIP-7702 delegation re-check (scheduler entry point)")
async def delegation_check(request: AttestationRequest, service=Depends(wallet_service)):
    return await invoke(service.recheck_delegation(request.attestation_id))


@router.get("/evidence/{attestation_id}", summary="Supervisor-readable evidence export for one verification")
async def evidence(attestation_id: Hex32, service=Depends(wallet_service)):
    from src.services.wallet_evidence_export import export_evidence

    inputs = await invoke(service.delegation_evidence(attestation_id))
    exported = export_evidence(
        inputs["attestation_record"],
        delegation_history=inputs["rechecks"],
        credential_ref={"credential_nonce": inputs["credential_nonce"], "subject_wallet": inputs["subject_wallet"]},
    )
    if inputs["message_format"] == "eip-4361":
        # The exact signed EIP-4361 text is part of the supervisor record.
        exported["challenge_message"] = inputs["message"]
    return exported


@router.post("/credential", summary="Issue a versioned wallet-ownership credential extension")
async def credential(request: AttestationRequest, service=Depends(wallet_service)):
    value = await invoke(service.issue_extension(request.attestation_id))
    return {
        "extension": value.model_dump(mode="json"),
        "commitment": value.commitment,
        "proof_support": "staged-witness-only",
    }
