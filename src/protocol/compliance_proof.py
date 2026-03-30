"""
ComplianceProof model — the ZK attestation component of the hybrid Travel Rule payload.

This object provides machine-verifiable proof of compliance.
Encrypted PII travels alongside it (see HybridPayload).
"""

from __future__ import annotations

import time
from typing import Optional

from pydantic import BaseModel, Field

__all__ = ["ComplianceProof"]


class ComplianceProof(BaseModel):
    """
    The ZK attestation component of the hybrid Travel Rule payload.

    Public signals layout:
      [0]: 1 if originator credential valid, 0 if not
      [1]: 1 if originator sanctions-clear, 0 if not
      [2]: amount_tier (1-4)
      [3]: credential jurisdiction matches transfer jurisdiction
      [4]: Merkle root of sanctions list used
      [5]: Merkle root of issuer list used
    """

    proof_id: str = Field(..., description="UUID for audit trail")
    transfer_id: str = Field(..., description="Links proof to specific transfer")

    # ZK proof artifact
    groth16_proof: str = Field(..., description="Base64-encoded Groth16 proof bytes")
    public_signals: list[str] = Field(..., description="Circuit public outputs")
    verification_key: str = Field(..., description="Verification key for on-chain/off-chain verification")

    # Proof metadata (public, non-sensitive)
    originator_vasp_did: str = Field(..., description="DID of originating VASP")
    beneficiary_vasp_did: Optional[str] = Field(default=None, description="DID of beneficiary VASP (if known)")
    jurisdiction: str = Field(..., description="ISO 3166-1 alpha-2 jurisdiction code")
    amount_tier: int = Field(..., ge=1, le=4, description="Tier (1-4); NOT exact amount")

    # Timestamps (Unix epoch)
    proof_generated_at: int = Field(..., description="Unix timestamp of proof generation")
    proof_expires_at: int = Field(
        default=0,
        description="Unix timestamp when proof expires (default: 300s from generation)",
    )

    # SAR review flag — signals for human review, NOT automatic SAR filing
    sar_review_flag: bool = Field(
        default=False,
        description="True if activity warrants human SAR review — advisory only",
    )

    # Encrypted SAR payload (AES-256-GCM; key managed by HSM)
    encrypted_sar_payload: Optional[str] = Field(
        default=None,
        description="Encrypted SAR audit payload, decryptable under legal process",
    )

    def model_post_init(self, __context: object) -> None:
        if self.proof_expires_at == 0:
            self.proof_expires_at = self.proof_generated_at + 300

    @property
    def is_expired(self) -> bool:
        return int(time.time()) > self.proof_expires_at
