"""
Proof generation and verification endpoints.

POST /proof/generate — Generate a ZK compliance proof + hybrid payload.
POST /proof/verify   — Verify a ZK compliance proof from a counterparty VASP.
"""

import hashlib
import json
import logging
import time
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from src.api.middleware.auth import JWTAuthDependency

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proof", tags=["proof"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ProofGenerateRequest(BaseModel):
    """Request body for POST /proof/generate."""

    credential_id: str = Field(..., description="Credential ID held by user's wallet")
    wallet_address: str = Field(..., description="Originator wallet address")
    amount_usd: float = Field(..., gt=0, description="Transfer amount in USD")
    asset: str = Field(..., description="Asset symbol, e.g. USDC")
    destination_wallet: str = Field(..., description="Beneficiary wallet address")
    destination_vasp_did: Optional[str] = Field(None, description="Beneficiary VASP DID")
    jurisdiction: str = Field(
        ..., min_length=2, max_length=2, description="ISO 3166-1 alpha-2 of originating jurisdiction"
    )
    idempotency_key: str = Field(..., description="Client-supplied idempotency key for retries")

    # Optional PII for hybrid payload (encrypted before transmission)
    originator_name: Optional[str] = None
    originator_address: Optional[str] = None
    originator_account: Optional[str] = None


class ProofVerifyRequest(BaseModel):
    """Request body for POST /proof/verify."""

    proof_id: str
    groth16_proof: dict = Field(..., description="Groth16 proof object")
    public_signals: list[str] = Field(..., description="Public signals array from prover")
    expected_amount_tier: int = Field(..., ge=1, le=4, description="Tier the verifier expects")
    originator_vasp_did: str
    transfer_timestamp: int


class ProofVerifyResponse(BaseModel):
    """Response body for POST /proof/verify."""

    valid: bool
    proof_id: str
    compliance_attestations: dict
    verified_at: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_wallet(address: str) -> str:
    """Deterministic hash of a wallet address for circuit input."""
    return hashlib.sha256(address.encode()).hexdigest()


def _hash_transfer(request: ProofGenerateRequest) -> str:
    """Deterministic hash of transfer parameters."""
    payload = f"{request.wallet_address}:{request.destination_wallet}:{request.amount_usd}:{request.asset}"
    return hashlib.sha256(payload.encode()).hexdigest()


# BN128 scalar field order
_BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _encode_jurisdiction(code: str) -> int:
    """Encode ISO-3166-1 alpha-2 to an integer for the circuit."""
    val = int.from_bytes(code.upper().encode("ascii"), byteorder="big")
    if val >= _BN128_R:
        raise ValueError(f"Jurisdiction encoding {val} overflows BN128 scalar field")
    return val


def _encode_did(did: str) -> int:
    """Encode a DID string to a field-compatible integer (truncated hash)."""
    h = hashlib.sha256(did.encode()).digest()
    return int.from_bytes(h[:16], byteorder="big")


def _encode_kyc_tier(tier: str) -> int:
    """Map a KYC tier label to an integer."""
    mapping = {"basic": 1, "standard": 2, "enhanced": 3}
    return mapping.get(tier.lower(), 1)


def _get_vasp_did() -> str:
    """Return this VASP's own DID (from config / env)."""
    import os

    return os.getenv("VASP_DID", "did:web:vasp.example.com")


def _load_vk() -> dict:
    """Load the Groth16 verification key from disk."""
    import os

    vk_path = os.path.join(
        os.getenv("CIRCUIT_ARTIFACTS_DIR", "./artifacts"),
        "verification_key.json",
    )
    try:
        with open(vk_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("Verification key not found at %s — using empty stub", vk_path)
        return {}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/generate", response_model=dict, summary="Generate ZK compliance proof")
async def generate_proof(
    request: ProofGenerateRequest,
    _auth: dict = Depends(JWTAuthDependency),
):
    """
    Generate a ZK compliance proof + hybrid payload for a travel rule transfer.

    Proof generation is VASP-local via SnarkJS — no external network required.
    Returns hybrid payload: ComplianceProof + encrypted PII.

    Latency target: <5 s for tier 1-2, <10 s for tier 3-4.
    """
    from src.prover.tier_mapping import compute_tier
    from src.prover.snarkjs_prover import SnarkJSProver
    from src.registry.sanctions_list import SanctionsMerkleTree
    from src.registry.credential_registry import CredentialRegistry
    from src.registry.issuer_registry import IssuerRegistry
    from src.sar.sar_review import evaluate_sar_flags
    from src.sar.encryption import derive_key, encrypt_pii
    from src.sar.audit_log import AuditLog
    from src.protocol.compliance_proof import ComplianceProof
    from src.protocol.hybrid_payload import HybridPayload

    # 1. Compute tier from amount + jurisdiction --------------------------------
    tier = compute_tier(request.amount_usd, request.jurisdiction)

    # 1b. IVMS101 validation — originator name is mandatory above Travel Rule threshold
    if tier >= 3 and not request.originator_name:
        raise HTTPException(
            status_code=422,
            detail=(
                "IVMS101 requires originator_name for Travel Rule transfers "
                f"(tier {tier}, amount ${request.amount_usd:.2f})"
            ),
        )

    # 2. Look up credential -----------------------------------------------------
    cred_registry = CredentialRegistry()
    credential = cred_registry.get(request.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    if credential.revoked:
        raise HTTPException(status_code=400, detail="Credential revoked")

    # 3. Build circuit inputs ----------------------------------------------------
    sanctions_tree = SanctionsMerkleTree.load()
    nonmembership_witness = await sanctions_tree.generate_nonmembership_witness(
        wallet_address=request.wallet_address,
    )

    issuer_registry = IssuerRegistry()
    input_signals = {
        "sanctions_tree_root": sanctions_tree.root,
        "issuer_tree_root": issuer_registry.get_root(),
        "amount_tier": tier,
        "transfer_timestamp": int(time.time()),
        "jurisdiction_code": _encode_jurisdiction(request.jurisdiction),
        "credential_commitment": await cred_registry.get_commitment(request.credential_id),
        # Private inputs
        "issuer_did": _encode_did(credential.issuer_did),
        "kyc_tier": _encode_kyc_tier(credential.kyc_tier),
        "issued_at": credential.issued_at,
        "expires_at": credential.expires_at,
        "wallet_address_hash": _hash_wallet(request.wallet_address),
        # Merkle proof data from gap proof
        "left_key": nonmembership_witness["left_neighbor"],
        "right_key": nonmembership_witness["right_neighbor"],
    }

    # 4. Generate proof via SnarkJS ----------------------------------------------
    prover = SnarkJSProver()
    try:
        proof_json, public_signals = await prover.fullprove(input_signals)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Proof generation failed: {exc}")

    proof_id = str(uuid.uuid4())
    now = int(time.time())

    # 5. Evaluate SAR review flags -----------------------------------------------
    sar_result = evaluate_sar_flags(
        amount_tier=tier,
        jurisdiction=request.jurisdiction,
    )

    # 6. Encrypt PII for hybrid payload -----------------------------------------
    import os
    raw_key = os.environ.get("PII_MASTER_KEY", "")
    if not raw_key:
        raise HTTPException(
            status_code=500,
            detail="PII_MASTER_KEY environment variable is required but not set",
        )
    master_key = raw_key.encode()
    envelope_id = request.idempotency_key
    pii_key = derive_key(master_key, envelope_id.encode())
    pii_plaintext = json.dumps({
        "originator_name": request.originator_name,
        "originator_address": request.originator_address,
        "originator_account": request.originator_account or request.wallet_address,
        "transfer_amount": str(request.amount_usd),
        "asset": request.asset,
    }).encode()
    pii_nonce, pii_ciphertext = encrypt_pii(pii_plaintext, pii_key, envelope_id)

    # 7. Build ComplianceProof ---------------------------------------------------
    proof_obj = ComplianceProof(
        proof_id=proof_id,
        transfer_id=request.idempotency_key,
        groth16_proof=json.dumps(proof_json),
        public_signals=[str(s) for s in public_signals],
        verification_key=json.dumps(_load_vk()),
        originator_vasp_did=_get_vasp_did(),
        beneficiary_vasp_did=request.destination_vasp_did,
        jurisdiction=request.jurisdiction,
        amount_tier=tier,
        proof_generated_at=now,
        proof_expires_at=now + 300,
        sar_review_flag=sar_result.requires_human_review,
        encrypted_sar_payload=None,
    )

    # 8. Build hybrid payload ----------------------------------------------------
    hybrid = HybridPayload(
        compliance_proof=proof_obj,
        encrypted_pii=pii_ciphertext,
        pii_nonce=pii_nonce,
        pii_associated_data=envelope_id,
    )

    # 9. Persist audit record ----------------------------------------------------
    audit_log = AuditLog()
    audit_log.append(
        entry_type="proof_generated",
        actor=_get_vasp_did(),
        transaction_ref=request.idempotency_key,
        data={
            "proof_id": proof_id,
            "sar_review": sar_result.model_dump(),
            "request_hash": _hash_transfer(request),
        },
    )

    return hybrid.model_dump()


@router.post("/verify", response_model=ProofVerifyResponse, summary="Verify ZK compliance proof")
async def verify_proof(
    request: ProofVerifyRequest,
    _auth: dict = Depends(JWTAuthDependency),
):
    """
    Verify a ZK compliance proof received from a counterparty VASP.

    Deterministic verification — no network call required.
    Latency target: <50 ms (Groth16 verification is O(1)).
    """
    from src.prover.snarkjs_prover import SnarkJSProver

    prover = SnarkJSProver()

    try:
        valid = await prover.verify(request.groth16_proof, request.public_signals)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Proof verification unavailable: {exc}")

    # Decode public signals
    signals = request.public_signals
    if len(signals) < 4:
        raise HTTPException(status_code=400, detail="Insufficient public signals (expected >= 4)")

    attestations = {
        "credential_valid": int(signals[0]) == 1,
        "sanctions_clear": int(signals[1]) == 1,
        "amount_tier": int(signals[2]),
        "jurisdiction_match": int(signals[3]) == 1,
    }

    # Check expected tier matches
    if attestations["amount_tier"] != request.expected_amount_tier:
        valid = False

    return ProofVerifyResponse(
        valid=valid,
        proof_id=request.proof_id,
        compliance_attestations=attestations,
        verified_at=int(time.time()),
    )
