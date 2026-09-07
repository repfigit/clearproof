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

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.api.dependencies import get_credential_registry
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
    beneficiary_hpke_public_key: Optional[str] = Field(
        None,
        description=(
            "Beneficiary VASP's X25519 public key (base64url, 32 bytes) for HPKE v2 "
            "envelope encryption (RFC 9180). When omitted, use operator configuration "
            "or strict counterparty discovery. Lookup failures reject the request."
        ),
    )


async def _resolve_recipient_key(request: ProofGenerateRequest) -> bytes | None:
    """Choose encryption before proving; failures cannot select legacy encryption."""
    from src.protocol.discovery import (
        DiscoveryError,
        DiscoveryUnavailable,
        resolve_hpke_public_key,
    )
    from src.protocol.discovery_profile import decode_hpke_key

    mode = os.getenv("PII_ENVELOPE_MODE", "hpke-v2")
    configured_key = os.getenv("BENEFICIARY_HPKE_PUBLIC_KEY")
    if mode == "legacy-v1":
        if request.beneficiary_hpke_public_key is not None or configured_key:
            raise HTTPException(status_code=422, detail="HPKE key conflicts with operator-selected legacy-v1 mode")
        return None
    if mode != "hpke-v2":
        raise HTTPException(status_code=503, detail="Invalid PII_ENVELOPE_MODE configuration")
    key = request.beneficiary_hpke_public_key
    if key is None:
        key = configured_key
    if key is not None:
        try:
            return decode_hpke_key(key)
        except DiscoveryError as exc:
            raise HTTPException(status_code=422, detail="Invalid beneficiary HPKE public key") from exc
    if not request.destination_vasp_did or os.getenv("HPKE_DISCOVERY_ENABLED", "1") == "0":
        raise HTTPException(status_code=422, detail="HPKE v2 requires a beneficiary key or enabled DID discovery")
    try:
        resolved = await resolve_hpke_public_key(request.destination_vasp_did)
        if resolved is None:
            raise DiscoveryError("Discovery supplied no HPKE key")
        return resolved
    except DiscoveryUnavailable as exc:
        raise HTTPException(
            status_code=503, detail="Counterparty discovery unavailable; retry without changing encryption"
        ) from exc
    except DiscoveryError as exc:
        raise HTTPException(
            status_code=422, detail="Counterparty discovery invalid or unsupported; HPKE key required"
        ) from exc


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
    rejection_reasons: list[str] = Field(
        default_factory=list,
        description="Why the proof was rejected. Empty when valid is true.",
    )


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


async def _check_sanctions_staleness(db: Optional[Database]) -> None:
    if db is None:
        return
    from src.storage.sanctions import SanctionsStore

    store = SanctionsStore(db)
    current = await store.get_current()
    if current is None:
        raise RuntimeError("No sanctions root loaded — cannot generate proof")
    staleness = time.time() - current.updated_at
    max_age = int(os.getenv("SANCTIONS_MAX_AGE_SECONDS", "86400"))
    if staleness > max_age:
        logger.warning("Sanctions root is %.1fh old (threshold %.1fh)", staleness / 3600, max_age / 3600)


@router.post("/generate", response_model=dict, summary="Generate ZK compliance proof")
async def generate_proof(
    request: ProofGenerateRequest,
    http_request: Request,
    _auth: dict = Depends(JWTAuthDependency),
    _rl: None = Depends(_proof_generate_limiter),
    _cred_registry: CredentialRegistry = Depends(get_credential_registry),
):
    from src.protocol.compliance_proof import ComplianceProof
    from src.protocol.hybrid_payload import HybridPayload
    from src.prover.tier_mapping import compute_tier, get_thresholds
    from src.sar.encryption import derive_key, encrypt_pii
    from src.sar.sar_review import evaluate_sar_flags
    from src.storage.keyring import load_keyring

    tier = compute_tier(request.amount_usd, request.jurisdiction)
    _thresholds = get_thresholds(request.jurisdiction)

    if tier >= 3 and not request.originator_name:
        raise HTTPException(
            status_code=422,
            detail=(
                "IVMS101 requires originator_name for Travel Rule transfers "
                f"(tier {tier}, amount ${request.amount_usd:.2f})"
            ),
        )

    db = _get_db(http_request.app)
    await _check_sanctions_staleness(db)

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
    if int(time.time()) >= credential.expires_at:
        raise HTTPException(status_code=410, detail="Credential expired")

    recipient_pubkey = await _resolve_recipient_key(request)

    # 4c. Evaluate SAR flags
    sar_result = evaluate_sar_flags(
        tier,
        request.jurisdiction,
        additional_signals={"transfers_last_24h": 0},
    )

    # 5. Build circuit inputs
    issuer_registry = _issuer_registry
    issuer_did_int = _encode_did(credential.issuer_did)
    commitment = _cred_registry.get_commitment(request.credential_id)
    commitment_int = int(commitment, 16) if commitment.startswith("0x") else int(commitment)

    sanctions_tree = SanctionsMerkleTree.load()
    wallet_hash = await _hash_wallet(request.wallet_address)

    sanctions_root = sanctions_tree.root
    if sanctions_root is None:
        raise RuntimeError("Sanctions tree not built — run build_sanctions_tree.py first")

    issuer_root = issuer_registry.get_root()
    issuer_witness = await issuer_registry.generate_membership_witness(credential.issuer_did)
    sanctions_witness = await sanctions_tree.generate_nonmembership_witness(request.wallet_address)

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

    generated_at = int(time.time())
    expires_at = generated_at + 3600
    circuit_inputs = {
        "issuer_did": issuer_did_int,
        "kyc_tier": _encode_kyc_tier(credential.kyc_tier),
        "sanctions_clear": int(credential.sanctions_clear),
        "issued_at": credential.issued_at,
        "expires_at": credential.expires_at,
        "wallet_address_hash": int(wallet_hash),
        "actual_amount": int(request.amount_usd),
        "tier2_threshold": _thresholds["tier2"],
        "tier3_threshold": _thresholds["tier3"],
        "tier4_threshold": _thresholds["tier4"],
        "transfer_timestamp": generated_at,
        "jurisdiction_code": _encode_jurisdiction(request.jurisdiction),
        "credential_commitment": commitment_int,
        "sanctions_tree_root": int(sanctions_root),
        "issuer_tree_root": int(issuer_root),
        "domain_chain_id": int(os.getenv("DOMAIN_CHAIN_ID", "11155111")),
        "domain_contract_hash": domain_contract_hash,
        "transfer_id_hash": int(transfer_id_hash[:16], 16),
        "credential_nullifier": int(credential_nullifier),
        "proof_expires_at": expires_at,
        "amount_tier": tier,
        "issuer_path_elements": issuer_witness["siblings"],
        "issuer_path_indices": issuer_witness["indices"],
        "left_key": sanctions_witness["left_neighbor"],
        "right_key": sanctions_witness["right_neighbor"],
        "left_path_elements": sanctions_witness["left_path"]["siblings"],
        "left_path_indices": sanctions_witness["left_path"]["indices"],
        "right_path_elements": sanctions_witness["right_path"]["siblings"],
        "right_path_indices": sanctions_witness["right_path"]["indices"],
    }

    # Preserve field integers across JSON/JavaScript without Number rounding.
    circuit_inputs = {name: str(value) if isinstance(value, int) else value for name, value in circuit_inputs.items()}

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
        proof_generated_at=generated_at,
        proof_expires_at=expires_at,
    )

    # 11. Encrypt PII
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

    pii_envelope: dict | None = None
    if recipient_pubkey is not None:
        from src.sar.hpke_envelope import seal_envelope

        pii_envelope = seal_envelope(pii_payload, recipient_pubkey, proof_id)
        ciphertext = base64.urlsafe_b64decode(pii_envelope["ct"])
        nonce = b""
        encryption_algorithm = "HPKE-X25519-HKDF-SHA256-AES-256-GCM"
    else:
        keyring = load_keyring()
        active_key = keyring.active_key
        derived_key = derive_key(active_key.key_bytes, f"clearproof-pii-{proof_id}".encode())
        nonce, ciphertext = encrypt_pii(pii_payload, derived_key, proof_id)
        encryption_algorithm = "AES-256-GCM"

    hybrid_payload = HybridPayload(
        compliance_proof=compliance_proof,
        encrypted_pii=ciphertext,
        encryption_algorithm=encryption_algorithm,
        pii_nonce=nonce,
        pii_associated_data=proof_id,
        pii_envelope=pii_envelope,
    )

    # 12. Record to durable storage
    if db is not None:
        from src.storage.credentials import CredentialStore
        from src.storage.models import StoredCredential, StoredNullifier, StoredProof
        from src.storage.proofs import ProofStore

        async with db.transaction() as transaction:
            async with transaction.connection() as conn:
                # Serialize retries for this key, including requests that proved concurrently.
                lock_id = int.from_bytes(
                    hashlib.sha256(request.idempotency_key.encode()).digest()[:8], "big", signed=True
                )
                await conn.execute("SELECT pg_advisory_xact_lock(%s)", (lock_id,))
            cached = await ProofStore(transaction).check_idempotency(request.idempotency_key)
            if cached is not None:
                return {"status": "already_generated", "result_hash": cached}
            cred_store = CredentialStore(transaction)
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

            proof_store = ProofStore(transaction)
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
                    proof_generated_at=generated_at,
                    proof_expires_at=expires_at,
                    is_expired=False,
                )
            )

            nullifier = StoredNullifier(
                nullifier_hash=credential_nullifier,
                credential_commitment=commitment,
                transfer_id=transfer_id,
                proof_id=proof_id,
            )
            if not await proof_store.add_nullifier(nullifier):
                raise HTTPException(status_code=409, detail="Proof nullifier already recorded")

            await proof_store.record_idempotency(
                request.idempotency_key,
                request.wallet_address,
                hashlib.sha256(
                    json.dumps(
                        {
                            **hybrid_payload.model_dump(exclude={"encrypted_pii", "pii_nonce"}),
                            "encrypted_pii": base64.b64encode(hybrid_payload.encrypted_pii).decode("ascii"),
                            "pii_nonce": base64.b64encode(hybrid_payload.pii_nonce).decode("ascii"),
                        },
                        sort_keys=True,
                    ).encode()
                ).hexdigest(),
            )

            audit = PersistentAuditLog(transaction)
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
        # base64: raw ciphertext bytes are not JSON-safe (this previously only
        # worked in tests because the mocked ciphertext was valid UTF-8)
        "encrypted_pii": base64.b64encode(hybrid_payload.encrypted_pii).decode("ascii"),
        "encryption_algorithm": hybrid_payload.encryption_algorithm,
        "pii_nonce": base64.b64encode(hybrid_payload.pii_nonce).decode(),
        "pii_associated_data": hybrid_payload.pii_associated_data,
        "pii_envelope": hybrid_payload.pii_envelope,
        "sar_review_flagged": sar_result.review_flagged,
        "sar_reasons": sar_result.flag_reasons,
    }


@router.post("/verify", response_model=ProofVerifyResponse, summary="Verify ZK compliance proof")
async def verify_proof(
    request: ProofVerifyRequest,
    http_request: Request,
    _auth: dict = Depends(JWTAuthDependency),
    _rl: None = Depends(_proof_verify_limiter),
):
    try:
        valid = await _prover.verify(request.groth16_proof, request.public_signals)
    except Exception:
        logger.error("Proof verification failed")
        raise HTTPException(status_code=503, detail="Proof verification temporarily unavailable")

    signals = request.public_signals
    if len(signals) < 16:
        raise HTTPException(status_code=400, detail="Insufficient public signals (expected 16)")

    rejection_reasons: list[str] = []
    if not valid:
        rejection_reasons.append("groth16_invalid")

    from src.prover.tier_mapping import decode_jurisdiction, jurisdiction_matches_vasp, thresholds_match_jurisdiction

    # Public signals arrive from a counterparty VASP: treat every element as
    # untrusted input, not as a well-formed integer.
    try:
        attestations = {
            "is_compliant": int(signals[0]) == 1,
            "sar_review_flag": int(signals[1]) == 1,
            "amount_tier": int(signals[4]),
            "jurisdiction": decode_jurisdiction(int(signals[6])),
        }
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Malformed public signals (expected decimal integers)")

    # Threshold binding. tier2/3/4_threshold (signals 8-10) are unconstrained
    # public inputs — the prover chooses them. A prover that submits an
    # arbitrarily high tier2_threshold lands any amount in tier 1, defeating
    # both the tier attestation and the SAR review flag. Mirrors the on-chain
    # check in ComplianceRegistry.verifyAndRecord.
    thresholds_ok = thresholds_match_jurisdiction(signals)
    attestations["thresholds_bound"] = thresholds_ok
    if not thresholds_ok:
        valid = False
        rejection_reasons.append("threshold_mismatch")

    # Optional read-only observation from an operator-selected chain reader.
    # The requested VASP identity is caller supplied, not a proved credential claim.
    chain_reader = getattr(http_request.app.state, "chain_reader", None)
    jurisdiction_matches = None
    if chain_reader is not None:
        try:
            vasp_info = await asyncio.wait_for(chain_reader.get_vasp_info(request.originator_vasp_did), timeout=5)
            if len(vasp_info) == 5 and vasp_info[3] is True and vasp_info[4] > 0:
                expected = vasp_info[1]
                if isinstance(expected, str) and len(expected) == 2 and all("A" <= char <= "Z" for char in expected):
                    jurisdiction_matches = jurisdiction_matches_vasp(signals, expected)
        except Exception:
            # Missing/failed lookup is unverified, never a successful match.
            pass
    attestations["jurisdiction_matches_vasp"] = jurisdiction_matches
    attestations["jurisdiction_observation"] = (
        "unverified" if jurisdiction_matches is None else "match" if jurisdiction_matches else "mismatch"
    )
    # AIF-98 is observational. It does not alter legacy proof acceptance.

    if attestations["amount_tier"] != request.expected_amount_tier:
        valid = False
        rejection_reasons.append("amount_tier_mismatch")

    return ProofVerifyResponse(
        valid=valid,
        proof_id=request.proof_id,
        compliance_attestations=attestations,
        verified_at=int(time.time()),
        rejection_reasons=rejection_reasons,
    )
