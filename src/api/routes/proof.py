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
import hmac
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.api.dependencies import get_credential_registry
from src.api.middleware.auth import JWTAuthDependency
from src.api.middleware.rate_limit import PrincipalRateLimiter
from src.prover.snarkjs_prover import ProverError, SnarkJSProver
from src.registry.credential_registry import CredentialRegistry
from src.registry.issuer_registry import IssuerRegistry
from src.registry.sanctions_list import SanctionsMerkleTree, _address_to_int, _poseidon_hash
from src.sar.audit_log import AuditLog
from src.storage.audit import PersistentAuditLog
from src.storage.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proof", tags=["proof"])

# Fallback only: this registry starts empty. Operators inject the trusted
# issuer set as ``app.state.issuer_registry`` (see ``_get_issuer_registry``).
_issuer_registry = IssuerRegistry(depth=10)
_prover = SnarkJSProver()
_audit_log = AuditLog()

_proof_generate_limiter = PrincipalRateLimiter(max_requests=30, window_seconds=60)
_proof_verify_limiter = PrincipalRateLimiter(max_requests=30, window_seconds=60)

LEGACY_SIGNAL_COUNT = 16
_DECIMAL = re.compile(r"[0-9]{1,78}")
_HEX = re.compile(r"0[xX][0-9a-fA-F]{1,64}")


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
    transfer_nonce: Optional[str] = Field(
        None,
        min_length=1,
        max_length=128,
        description=(
            "Optional per-transfer nonce or transfer ID. When set it is bound into the transfer hash and "
            "nullifier, so repeated transfers with the same wallets and amount get distinct nullifiers."
        ),
    )

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


def _artifact_path(name: str) -> str:
    return os.path.join(os.getenv("CIRCUIT_ARTIFACTS_DIR", "./artifacts"), name)


def _artifact_stamp(path: str) -> Optional[tuple[int, int]]:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


# path -> ((mtime_ns, size), parsed artifact). Reloaded when the file changes.
_artifact_cache: dict[str, tuple[tuple[int, int], Any]] = {}


def _cached_artifact(path: str, load):
    stamp = _artifact_stamp(path)
    cached = _artifact_cache.get(path)
    if stamp is not None and cached is not None and cached[0] == stamp:
        return cached[1]
    value = load()
    if stamp is not None:
        _artifact_cache[path] = (stamp, value)
    return value


def _read_vk(vk_path: str) -> dict:
    try:
        with open(vk_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(
            f"Verification key not found at {vk_path}. Circuit artifacts must be compiled before starting the service."
        )


def _load_vk() -> dict:
    """Return the verification key, re-reading the file only when it changes."""
    vk_path = _artifact_path("verification_key.json")
    return _cached_artifact(vk_path, lambda: _read_vk(vk_path))


def _load_sanctions_tree() -> SanctionsMerkleTree:
    """Return the sanctions tree, rebuilding it only when the artifact file changes.

    A missing file is never cached, so ``SanctionsMerkleTree.load`` reports it.
    """
    return _cached_artifact(_artifact_path("sanctions_tree.json"), SanctionsMerkleTree.load)


def _get_issuer_registry(app) -> IssuerRegistry:
    """Operator-injected trusted issuer registry, else the (empty) module default."""
    injected = getattr(getattr(app, "state", None), "issuer_registry", None)
    return injected if injected is not None else _issuer_registry


def _parse_field_setting(name: str, default: str) -> int:
    """Parse a decimal or 0x-hex BN128 field element from configuration, without truncation."""
    raw = os.getenv(name, default).strip()
    if not raw:
        return 0
    if _DECIMAL.fullmatch(raw):
        value = int(raw)
    elif _HEX.fullmatch(raw):
        value = int(raw, 16)
    else:
        value = _BN128_R
    if value >= _BN128_R:
        raise HTTPException(
            status_code=503,
            detail=f"Invalid {name} configuration: expected a decimal or 0x-hex BN128 field element",
        )
    return value


def _domain_binding() -> tuple[int, int]:
    """Domain signals checked by ComplianceRegistry, not by the circuit.

    ``DOMAIN_CONTRACT_HASH`` must equal the contract's own computation,
    ``uint256(keccak256(abi.encodePacked(registry))) % BN128_R``, supplied in
    full as decimal or 0x-hex. Empty means unbound (0), which the deployed
    registry rejects. Malformed values fail closed instead of being truncated.
    """
    return _parse_field_setting("DOMAIN_CHAIN_ID", "11155111"), _parse_field_setting("DOMAIN_CONTRACT_HASH", "")


def _same_wallet(left: str, right: str) -> bool:
    return left.strip().lower() == right.strip().lower()


def _principal_id(auth: Any) -> str:
    subject = auth.get("sub") if isinstance(auth, dict) else None
    return subject if isinstance(subject, str) and subject else "unauthenticated"


def _scoped_idempotency_key(principal: str, client_key: str) -> str:
    """Idempotency keys are private to the authenticated principal."""
    digest = hashlib.sha256(f"{principal}\x00{client_key}".encode()).hexdigest()
    return f"proof-idem-v2:{digest}"


def _request_fingerprint(request: "ProofGenerateRequest") -> str:
    """Hash of the fields that define the transfer. Originator PII is excluded."""
    salient = {
        "credential_id": request.credential_id,
        "wallet_address": request.wallet_address.strip().lower(),
        "amount_usd": request.amount_usd,
        "asset": request.asset,
        "destination_wallet": request.destination_wallet.strip().lower(),
        "destination_vasp_did": request.destination_vasp_did,
        "jurisdiction": request.jurisdiction.upper(),
        "transfer_nonce": request.transfer_nonce,
        "beneficiary_hpke_public_key": request.beneficiary_hpke_public_key,
    }
    return hashlib.sha256(json.dumps(salient, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _replayed_result(stored: str, fingerprint: str) -> str:
    """Return the cached result digest, or 409 when the key was used for another request."""
    recorded, separator, result_hash = stored.partition(":")
    if not separator or not hmac.compare_digest(recorded, fingerprint):
        raise HTTPException(status_code=409, detail="Idempotency key already used for a different request")
    return result_hash


def _root_int(value: Any) -> Optional[int]:
    try:
        text = str(value)
        return int(text, 16) if text[:2].lower() == "0x" else int(text)
    except (TypeError, ValueError):
        return None


async def _current_roots(app) -> tuple[Optional[int], Optional[int]]:
    """Current sanctions and issuer roots, or None when no source is available."""
    try:
        tree = await asyncio.to_thread(_load_sanctions_tree)
        sanctions_root = _root_int(tree.root)
    except Exception:
        sanctions_root = None
    try:
        issuer_root = _root_int(_get_issuer_registry(app).get_root())
    except Exception:
        issuer_root = None
    return sanctions_root, issuer_root


def _parse_public_signals(signals: list[str]) -> list[int]:
    """Untrusted counterparty input: exactly 16 canonical field elements."""
    if len(signals) != LEGACY_SIGNAL_COUNT:
        raise HTTPException(status_code=400, detail=f"Expected exactly {LEGACY_SIGNAL_COUNT} public signals")
    values = [int(signal) if _DECIMAL.fullmatch(signal) else _BN128_R for signal in signals]
    if any(value >= _BN128_R for value in values):
        raise HTTPException(status_code=400, detail="Malformed public signals (expected decimal field elements)")
    return values


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

    domain_chain_id, domain_contract_hash = _domain_binding()

    db = _get_db(http_request.app)
    await _check_sanctions_staleness(db)

    idempotency_key = _scoped_idempotency_key(_principal_id(_auth), request.idempotency_key)
    fingerprint = _request_fingerprint(request)
    if db is not None:
        from src.storage.proofs import ProofStore

        cached = await ProofStore(db).check_idempotency(idempotency_key)
        if cached is not None:
            result_hash = _replayed_result(cached, fingerprint)
            logger.info("Idempotent hit for scoped key %s", idempotency_key[14:22])
            return {"status": "already_generated", "result_hash": result_hash}

    # 4. Look up credential
    credential = _cred_registry.get(request.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    if credential.revoked:
        raise HTTPException(status_code=403, detail="Credential revoked")

    # 4b. Check credential expiry
    if int(time.time()) >= credential.expires_at:
        raise HTTPException(status_code=410, detail="Credential expired")

    # 4c. The credential must belong to the wallet and jurisdiction being proved.
    if not _same_wallet(request.wallet_address, credential.subject_wallet):
        raise HTTPException(status_code=403, detail="Wallet address does not match credential subject")
    if request.jurisdiction.upper() != credential.jurisdiction.upper():
        raise HTTPException(status_code=403, detail="Jurisdiction does not match credential")
    subject_wallet = credential.subject_wallet

    recipient_pubkey = await _resolve_recipient_key(request)

    # 4d. Evaluate SAR flags
    sar_result = evaluate_sar_flags(
        tier,
        request.jurisdiction,
        additional_signals={"transfers_last_24h": 0},
    )

    # 5. Build circuit inputs
    issuer_registry = _get_issuer_registry(http_request.app)
    issuer_did_int = _encode_did(credential.issuer_did)
    commitment = _cred_registry.get_commitment(request.credential_id)
    commitment_int = int(commitment, 16) if commitment.startswith("0x") else int(commitment)

    sanctions_tree = await asyncio.to_thread(_load_sanctions_tree)
    wallet_hash = await _hash_wallet(subject_wallet)

    sanctions_root = sanctions_tree.root
    if sanctions_root is None:
        raise RuntimeError("Sanctions tree not built — run build_sanctions_tree.py first")

    try:
        issuer_witness = await issuer_registry.generate_membership_witness(credential.issuer_did)
    except KeyError:
        raise HTTPException(status_code=422, detail="Credential issuer not authorized")
    issuer_root = issuer_registry.get_root()
    sanctions_witness = await sanctions_tree.generate_nonmembership_witness(subject_wallet)

    transfer_preimage = f"{request.wallet_address}:{request.destination_wallet}:{request.amount_usd}"
    if request.transfer_nonce is not None:
        transfer_preimage += f":{request.transfer_nonce}"
    transfer_id_hash = hashlib.sha256(transfer_preimage.encode()).hexdigest()
    credential_nullifier = await _poseidon_hash([commitment_int, int(transfer_id_hash[:16], 16)])

    # Fail fast on a spent nullifier; the insert below still guards concurrent requests.
    if db is not None and await ProofStore(db).nullifier_exists(credential_nullifier):
        raise HTTPException(status_code=409, detail="Proof nullifier already recorded")

    verification_key = json.dumps(await asyncio.to_thread(_load_vk))

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
        "domain_chain_id": domain_chain_id,
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
    try:
        proof_result, public_signals = await _prover.fullprove(circuit_inputs)
    except (ProverError, FileNotFoundError, RuntimeError) as exc:
        logger.error("Proof generation failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Proof generation temporarily unavailable") from exc

    # 10. Build compliance proof
    proof_id = str(uuid.uuid4())
    transfer_id = hashlib.sha256(f"{request.idempotency_key}:{proof_id}".encode()).hexdigest()

    compliance_proof = ComplianceProof(
        proof_id=proof_id,
        transfer_id=transfer_id,
        groth16_proof=json.dumps(proof_result),
        public_signals=[str(s) for s in public_signals],
        verification_key=verification_key,
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

        async with db.transaction() as transaction:
            async with transaction.connection() as conn:
                # Serialize retries for this key, including requests that proved concurrently.
                lock_id = int.from_bytes(hashlib.sha256(idempotency_key.encode()).digest()[:8], "big", signed=True)
                await conn.execute("SELECT pg_advisory_xact_lock(%s)", (lock_id,))
            cached = await ProofStore(transaction).check_idempotency(idempotency_key)
            if cached is not None:
                return {"status": "already_generated", "result_hash": _replayed_result(cached, fingerprint)}
            cred_store = CredentialStore(transaction)
            await cred_store.upsert(
                StoredCredential(
                    credential_id=request.credential_id,
                    issuer_did=credential.issuer_did,
                    subject_wallet=subject_wallet,
                    jurisdiction=credential.jurisdiction,
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
                    verification_key=verification_key,
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

            result_hash = hashlib.sha256(
                json.dumps(
                    {
                        **hybrid_payload.model_dump(exclude={"encrypted_pii", "pii_nonce"}),
                        "encrypted_pii": base64.b64encode(hybrid_payload.encrypted_pii).decode("ascii"),
                        "pii_nonce": base64.b64encode(hybrid_payload.pii_nonce).decode("ascii"),
                    },
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            # The stored value binds the result to the request fingerprint ("fingerprint:result").
            await proof_store.record_idempotency(idempotency_key, subject_wallet, f"{fingerprint}:{result_hash}")

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


def _root_status(signal: int, current: Optional[int]) -> str:
    if current is None:
        return "unverified"
    return "current" if signal == current else "stale"


@router.post("/verify", response_model=ProofVerifyResponse, summary="Verify ZK compliance proof")
async def verify_proof(
    request: ProofVerifyRequest,
    http_request: Request,
    _auth: dict = Depends(JWTAuthDependency),
    _rl: None = Depends(_proof_verify_limiter),
):
    # Public signals arrive from a counterparty VASP: validate their shape and
    # encoding before spending a snarkjs subprocess on them.
    signals = request.public_signals
    values = _parse_public_signals(signals)

    try:
        valid = await _prover.verify(request.groth16_proof, signals)
    except Exception as exc:
        logger.error("Proof verification failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Proof verification temporarily unavailable")

    rejection_reasons: list[str] = []
    if not valid:
        rejection_reasons.append("groth16_invalid")

    from src.prover.tier_mapping import decode_jurisdiction, jurisdiction_matches_vasp, thresholds_match_jurisdiction

    attestations = {
        "is_compliant": values[0] == 1,
        "sar_review_flag": values[1] == 1,
        "amount_tier": values[4],
        "jurisdiction": decode_jurisdiction(values[6]),
        "proof_expires_at": values[15],
    }

    if not attestations["is_compliant"]:
        valid = False
        rejection_reasons.append("not_compliant")

    # Expiry is judged on the verifier's clock. transfer_timestamp is caller
    # supplied and would let a caller revive an expired proof.
    if values[15] <= int(time.time()):
        valid = False
        rejection_reasons.append("proof_expired")

    # Roots must be the ones this verifier currently trusts. Without a
    # current-root source the check is reported as unverified, not passed.
    current_sanctions_root, current_issuer_root = await _current_roots(http_request.app)
    attestations["sanctions_root_status"] = _root_status(values[2], current_sanctions_root)
    attestations["issuer_root_status"] = _root_status(values[3], current_issuer_root)
    if attestations["sanctions_root_status"] == "stale":
        valid = False
        rejection_reasons.append("sanctions_root_stale")
    if attestations["issuer_root_status"] == "stale":
        valid = False
        rejection_reasons.append("issuer_root_stale")

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
