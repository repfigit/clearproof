from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class StoredCredential(BaseModel):
    credential_id: str
    issuer_did: str
    subject_wallet: str
    jurisdiction: str
    kyc_tier: str
    sanctions_clear: bool
    issued_at: int
    expires_at: int
    revoked: bool = False
    commitment: str


class StoredProof(BaseModel):
    proof_id: str
    transfer_id: str
    groth16_proof: str
    public_signals: list[str]
    verification_key: str
    originator_vasp_did: str
    beneficiary_vasp_did: Optional[str] = None
    jurisdiction: str
    amount_tier: int
    proof_generated_at: int
    proof_expires_at: int
    is_expired: bool = False


class StoredNullifier(BaseModel):
    nullifier_hash: str
    credential_commitment: str
    transfer_id: str
    proof_id: str


class StoredSanctionsRoot(BaseModel):
    root_id: int
    root_hash: str
    leaf_count: int
    source: str
    updated_at: int
    is_current: bool = False


class StoredAuditEntry(BaseModel):
    sequence_number: int
    timestamp: int
    entry_type: str
    actor: str
    transaction_ref: str
    data_hash: str
    prev_entry_hash: str
    entry_hash: str


class StoredIdempotencyKey(BaseModel):
    key: str
    wallet_address: str
    result_hash: str
    expires_at: int
