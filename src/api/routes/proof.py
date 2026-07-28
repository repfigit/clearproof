"""
Proof generation and verification endpoints.

POST /proof/generate — Generate a ZK compliance proof + hybrid payload.
POST /proof/verify   — Verify a ZK compliance proof from a counterparty VASP.

Wired to durable storage via app.state.db (PostgreSQL) when DATABASE_URL
is configured. Falls back to in-memory registries when not.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.api.middleware.auth import JWTAuthDependency
from src.api.middleware.rate_limit import RateLimiter
from src.prover.snarkjs_prover import SnarkJSProver
from src.registry.credential_registry import CredentialRegistry
from src.registry.issuer_registry import IssuerRegistry
from src.registry.sanctions_list import SanctionsMerkleTree, _address_to_int, _poseidon_hash
from src.sar.audit_log import AuditLog
from src.storage.audit import PersistentAuditLog
from src.storage.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proof", tags=["proof"])

_cred_registry = CredentialRegistry()
_issuer_registry = IssuerRegistry()
_prover = SnarkJSProver()
_audit_log = AuditLog()

_proof_generate_limiter = RateLimiter(max_requests=30, window_seconds=60)
_proof_verify_limiter = RateLimiter(max_requests=30, window_seconds=60)


class ProofGenerateRequest(BaseModel):
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

    originator_name: Optional[str] = None
    originator_address: Optional[str] = None
    originator_account: Optional[str] = None


class ProofVerifyRequest(BaseModel):
    proof_id: str
    groth16_proof: dict = Field(..., description="Groth16 proof object")
    public_signals: list[str] = Field(..., description="Public signals array from prover")
    expected_amount_tier: int = Field(..., ge=1, le=4, description="Tier the verifier expects")
    originator_vasp_did: str
    transfer_timestamp: int


class ProofVerifyResponse(BaseModel):
    valid: bool
    proof_id: str
    compliance_attestations: dict
    verified_at: int


async def _hash_wallet(address: str) -> str:
    return await _poseidon_hash([1, _address_to_int(address)])


def _hash_transfer(request: ProofGenerateRequest) -> str:
    payload = f"{request.wallet_address}:{request.destination_wallet}:{request.amount_usd}:{request.asset}"
    return hashlib.sha256(payload.encode()).hexdigest()


_BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _encode_jurisdiction(code: str) -> int:
    val = int.from_bytes(code.upper().encode("ascii"), byteorder="big")
    if val >= _BN128_R:
        raise ValueError(f"Jurisdiction encoding {val} overflows BN128 scalar field")
    return val


def _encode_did(did: str) -> int:
    return int.from_bytes(hashlib.sha256(did.encode()).digest()[:16], byteorder="big")


def _encode_kyc_tier(tier: str) -> int:
    mapping = {"retail": 1, "professional": 2, "institutional": 3}
    return mapping.get(tier.lower(), 1)


def _get_vasp_did() -> str:
    return os.getenv("VASP_DID", "did:web:vasp.example.com")


def _load_vk() -> dict:
    vk_path = os.path.join(
        os.getenv("CIRCUIT_ARTIFACTS_DIR", "./artifacts"),
        "verification_key.json",
    )
    try:
        with open(vk_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(
            f"Verification key not found at {vk_path}. Circuit artifacts must be compiled before starting the service."
        )


# ---------------------------------------------------------------------------
# Storage accessors (durable or in-memory fallback)
# ---------------------------------------------------------------------------


def _get_db(app) -> Optional[Database]:
    return getattr(getattr(app, "state", None), "db", None)


def _get_db_from_app() -> Optional[Database]:
    from src.api.main import app as _app

    return _get_db(_app)


def _check_sanctions_staleness(db: Optional[Database]) -> None:
    if db is None:
        return
    from src.storage.sanctions import SanctionsStore

    store = SanctionsStore(db)
    current = asyncio.get_event_loop().run_until_complete(store.get_current())
    if current is None:
        raise RuntimeError("No sanctions root loaded — cannot generate proof")
    staleness = time.time() - current.updated_at
    max_age = int(os.getenv("SANCTIONS_MAX_AGE_SECONDS", "86400"))
    if staleness > max_age:
        logger.warning("Sanctions root is %.1fh old (threshold %.1fh)", staleness / 3600, max_age / 3600)


@router.post("/generate", response_model=dict, summary="Generate ZK compliance proof")
async def generate_proof(
    request: ProofGenerateRequest,
    _auth: dict = Depends(JWTAuthDependency),
    _rl: None = Depends(_proof_generate_limiter),
):
    from src.protocol.compliance_proof import ComplianceProof
    from src.protocol.hybrid_payload import HybridPayload
    from src.prover.tier_mapping import JURISDICTION_TIERS, compute_tier
    from src.sar.encryption import derive_key, encrypt_pii
    from src.sar.sar_review import evaluate_sar_flags
    from src.storage.keyring import load_keyring

    tier = compute_tier(request.amount_usd, request.jurisdiction)

    if tier >= 3 and not request.originator_name:
        raise HTTPException(
            status_code=422,
            detail=(
                "IVMS101 requires originator_name for Travel Rule transfers "
                f"(tier {tier}, amount ${request.amount_usd:.2f})"
            ),
        )

    db = _get_db_from_app()
    _check_sanctions_staleness(db)

    if db is not None:
        from src.storage.proofs import ProofStore

        proof_store = ProofStore(db)
        cached = await proof_store.check_idempotency(request.idempotency_key)
        if cached is not None:
            logger.info("Idempotent hit for key %s", request.idempotency_key[:8])
            return {"status": "already_generated", "result_hash": cached}

    # 4. Look up credential
    credential = _cred_registry.get(request.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    if credential.revoked:
        raise HTTPException(status_code=403, detail="Credential revoked")

    # 4b. Check credential expiry
    if int(time.time()) > credential.expires_at:
        raise HTTPException(status_code=410, detail="Credential expired")

    # 4c. Evaluate SAR flags
    sar_result = evaluate_sar_flags(
        tier,
        request.jurisdiction,
        additional_signals={"transfers_last_24h": 0},
    )

    # 5. Build circuit inputs
    issuer_registry = IssuerRegistry()
    issuer_did_int = _encode_did(credential.issuer_did)
    commitment = _cred_registry.get_commitment(request.credential_id)
    commitment_int = int(commitment, 16) if commitment.startswith("0x") else int(commitment)

    sanctions_tree = SanctionsMerkleTree.load()
    wallet_hash = await _hash_wallet(request.wallet_address)

    sanctions_root = sanctions_tree.root
    if sanctions_root is None:
        raise RuntimeError("Sanctions tree not built — run build_sanctions_tree.py first")

    issuer_root = issuer_registry.root
    if issuer_root is None:
        issuer_root = "0" * 64

    transfer_id_hash = hashlib.sha256(
        f"{request.wallet_address}:{request.destination_wallet}:{request.amount_usd}".encode()
    ).hexdigest()
    credential_nullifier = await _poseidon_hash(
        [int(commitment, 16) if commitment.startswith("0x") else int(commitment), int(transfer_id_hash[:16], 16)]
    )

    domain_contract_hash = os.getenv("DOMAIN_CONTRACT_HASH", "0")
    if domain_contract_hash:
        domain_contract_hash = int(domain_contract_hash[:16], 16)
    else:
        domain_contract_hash = 0

    circuit_inputs = {
        "issuer_did": [issuer_did_int],
        "kyc_tier": [_encode_kyc_tier(credential.kyc_tier)],
        "sanctions_clear": [1 if credential.sanctions_clear else 0],
        "issued_at": [credential.issued_at],
        "expires_at": [credential.expires_at],
        "wallet_ownership_verified": [1 if credential.wallet_ownership_verified else 0],
        "wallet_address_hash": [int(wallet_hash, 16)],
        "amount_usd": [int(request.amount_usd)],
        "tier2_threshold": [JURISDICTION_TIERS.get(request.jurisdiction, {}).get("tier2", 10000)],
        "tier3_threshold": [JURISDICTION_TIERS.get(request.jurisdiction, {}).get("tier3", 100000)],
        "tier4_threshold": [JURISDICTION_TIERS.get(request.jurisdiction, {}).get("tier4", 1000000)],
        "transfer_timestamp": [int(time.time())],
        "jurisdiction_code": [_encode_jurisdiction(request.jurisdiction)],
        "credential_commitment": [commitment_int],
        "sanctions_root": [int(sanctions_root, 16) if isinstance(sanctions_root, str) else sanctions_root],
        "issuer_root": [int(issuer_root, 16) if isinstance(issuer_root, str) else issuer_root],
        "domain_chain_id": [int(os.getenv("DOMAIN_CHAIN_ID", "11155111"))],
        "domain_contract_hash": [domain_contract_hash],
        "transfer_id_hash": [int(transfer_id_hash[:16], 16)],
        "credential_nullifier": [
            int(credential_nullifier, 16) if isinstance(credential_nullifier, str) else credential_nullifier
        ],
        "proof_expires_at": [int(time.time()) + 3600],
        "amount_tier": [tier],
        "sar_review_flag": [1 if sar_result.review_flagged else 0],
        "is_compliant": [1 if credential.sanctions_clear else 0],
    }

    # 9. Generate proof
    proof_result, public_signals = await _prover.fullprove(circuit_inputs)

    # 10. Build compliance proof
    proof_id = str(uuid.uuid4())
    transfer_id = hashlib.sha256(f"{request.idempotency_key}:{proof_id}".encode()).hexdigest()

    compliance_proof = ComplianceProof(
        proof_id=proof_id,
        transfer_id=transfer_id,
        groth16_proof=json.dumps(proof_result),
        public_signals=[str(s) for s in public_signals],
        verification_key=json.dumps(_load_vk()),
        originator_vasp_did=_get_vasp_did(),
        beneficiary_vasp_did=request.destination_vasp_did,
        jurisdiction=request.jurisdiction,
        amount_tier=tier,
        proof_generated_at=int(time.time()),
        proof_expires_at=int(time.time()) + 3600,
    )

    # 11. Encrypt PII
    keyring = load_keyring()
    active_key = keyring.active_key
    derived_key = derive_key(active_key.key_bytes, f"clearproof-pii-{proof_id}".encode())

    pii_payload = json.dumps(
        {
            "originator": {
                "name": request.originator_name,
                "address": request.originator_address,
                "account": request.originator_account,
            },
            "transfer_id": transfer_id,
            "proof_id": proof_id,
        }
    ).encode()

    nonce, ciphertext = encrypt_pii(pii_payload, derived_key, proof_id)

    hybrid_payload = HybridPayload(
        compliance_proof=compliance_proof,
        encrypted_pii=ciphertext,
        encryption_algorithm="AES-256-GCM",
        pii_nonce=nonce,
        pii_associated_data=proof_id,
    )

    # 12. Record to durable storage
    if db is not None:
        from src.storage.credentials import CredentialStore
        from src.storage.models import StoredCredential, StoredNullifier, StoredProof
        from src.storage.proofs import ProofStore

        cred_store = CredentialStore(db)
        await cred_store.upsert(
            StoredCredential(
                credential_id=request.credential_id,
                issuer_did=credential.issuer_did,
                subject_wallet=request.wallet_address,
                jurisdiction=request.jurisdiction,
                kyc_tier=credential.kyc_tier,
                sanctions_clear=credential.sanctions_clear,
                issued_at=credential.issued_at,
                expires_at=credential.expires_at,
                revoked=credential.revoked,
                commitment=commitment,
            )
        )

        proof_store = ProofStore(db)
        await proof_store.store(
            StoredProof(
                proof_id=proof_id,
                transfer_id=transfer_id,
                groth16_proof=json.dumps(proof_result),
                public_signals=[str(s) for s in public_signals],
                verification_key=json.dumps(_load_vk()),
                originator_vasp_did=_get_vasp_did(),
                beneficiary_vasp_did=request.destination_vasp_did,
                jurisdiction=request.jurisdiction,
                amount_tier=tier,
                proof_generated_at=int(time.time()),
                proof_expires_at=int(time.time()) + 3600,
                is_expired=False,
            )
        )

        nullifier = StoredNullifier(
            nullifier_hash=credential_nullifier,
            credential_commitment=commitment,
            transfer_id=transfer_id,
            proof_id=proof_id,
        )
        await proof_store.add_nullifier(nullifier)

        await proof_store.record_idempotency(
            request.idempotency_key,
            request.wallet_address,
            hashlib.sha256(json.dumps(hybrid_payload.model_dump()).encode()).hexdigest(),
        )

        audit = PersistentAuditLog(db)
        await audit.append(
            "proof_generated",
            _get_vasp_did(),
            transfer_id,
            json.dumps({"proof_id": proof_id, "tier": tier}).encode(),
        )

    # 13. Log to in-memory audit
    _audit_log.append(
        "proof_generated",
        _get_vasp_did(),
        transfer_id,
        json.dumps({"proof_id": proof_id, "tier": tier}).encode(),
    )

    return {
        "status": "generated",
        "proof_id": proof_id,
        "transfer_id": transfer_id,
        "compliance_proof": compliance_proof.model_dump(),
        "encrypted_pii": hybrid_payload.encrypted_pii,
        "encryption_algorithm": hybrid_payload.encryption_algorithm,
        "pii_nonce": base64.b64encode(hybrid_payload.pii_nonce).decode(),
        "pii_associated_data": hybrid_payload.pii_associated_data,
        "sar_review_flagged": sar_result.review_flagged,
        "sar_reasons": sar_result.flag_reasons,
    }


@router.post("/verify", response_model=ProofVerifyResponse, summary="Verify ZK compliance proof")
async def verify_proof(
    request: ProofVerifyRequest,
    _auth: dict = Depends(JWTAuthDependency),
    _rl: None = Depends(_proof_verify_limiter),
):
    try:
        valid = await _prover.verify(request.groth16_proof, request.public_signals)
    except Exception:
        logger.exception("Proof verification failed")
        raise HTTPException(status_code=503, detail="Proof verification temporarily unavailable")

    signals = request.public_signals
    if len(signals) < 16:
        raise HTTPException(status_code=400, detail="Insufficient public signals (expected 16)")

    attestations = {
        "is_compliant": int(signals[0]) == 1,
        "sar_review_flag": int(signals[1]) == 1,
        "amount_tier": int(signals[4]),
    }

    if attestations["amount_tier"] != request.expected_amount_tier:
        valid = False

    return ProofVerifyResponse(
        valid=valid,
        proof_id=request.proof_id,
        compliance_attestations=attestations,
        verified_at=int(time.time()),
    )
