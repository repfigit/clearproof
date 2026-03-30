"""
IVMS101 ZK proof wrapper models.

Drop-in replacements for standard IVMS101 Originator and Message objects.
PII fields are encrypted; ZK proof provides compliance attestation.
Counterparties running zk-capable Travel Rule software verify the proof;
all counterparties can decrypt PII via mTLS.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .compliance_proof import ComplianceProof

__all__ = ["ZKIvms101Originator", "ZKIvms101Message"]


class ZKIvms101Originator(BaseModel):
    """
    Drop-in replacement for IVMS101 Originator object.

    PII fields are encrypted; ZK proof provides compliance attestation.
    """

    # Standard IVMS101 structural fields (non-PII)
    account_number: str = Field(..., description="Wallet address — required by IVMS101")

    # ZK proof reference
    zk_proof_ref: str = Field(..., description="proof_id linking to ComplianceProof")
    zk_verification_endpoint: str = Field(
        ..., description="URL where beneficiary can fetch and verify proof"
    )

    # Encrypted PII (always present in hybrid model)
    encrypted_natural_person: Optional[str] = Field(
        default=None,
        description="AES-256-GCM encrypted IVMS101 NaturalPerson",
    )


class ZKIvms101Message(BaseModel):
    """Full IVMS101 message with ZK originator + encrypted PII."""

    originator: ZKIvms101Originator
    beneficiary_account_number: str = Field(..., description="Beneficiary wallet address")
    originating_vasp_did: str
    beneficiary_vasp_did: Optional[str] = None
    transfer_amount: str = Field(..., description="Amount as string (not revealed in proof)")
    asset_type: str = Field(..., description="e.g. USDC, USDT")

    # Hybrid payload: proof + encrypted PII
    compliance_proof: Optional[ComplianceProof] = None
