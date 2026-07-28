"""
HybridPayload model — combines ZK proof with encrypted PII.

The ZK proof provides a machine-verifiable attestation that compliance
was performed correctly. The encrypted PII satisfies the regulatory
requirement to transmit originator/beneficiary information.

Both components travel together in every Travel Rule message.
"""

from __future__ import annotations

import base64
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .compliance_proof import ComplianceProof

__all__ = ["HybridPayload"]


class HybridPayload(BaseModel):
    """Hybrid Travel Rule payload: ZK proof + encrypted PII."""

    # ZK attestation component
    compliance_proof: ComplianceProof

    # Encrypted PII component (satisfies "transmit" requirement)
    # v1: AES-256-GCM with a shared master key (legacy).
    # v2: HPKE (RFC 9180) sealed to the beneficiary VASP's X25519 public key;
    #     the full envelope travels in ``pii_envelope``.
    encrypted_pii: bytes = Field(..., description="Encrypted IVMS101 originator PII")
    encryption_algorithm: str = Field(default="AES-256-GCM")
    pii_nonce: bytes = Field(default=b"", description="12-byte nonce for AES-256-GCM (v1 only)")
    pii_associated_data: str = Field(..., description="Envelope binding associated data")
    pii_envelope: dict[str, Any] | None = Field(
        default=None,
        description="HPKE v2 envelope (see src/sar/hpke_envelope.py); set iff encryption_algorithm is HPKE",
    )

    @field_validator("pii_nonce")
    @classmethod
    def validate_nonce_length(cls, v: bytes) -> bytes:
        if len(v) not in (0, 12):
            raise ValueError("pii_nonce must be exactly 12 bytes (or empty for HPKE v2 envelopes)")
        return v

    @property
    def is_hpke_v2(self) -> bool:
        """True if this payload carries an HPKE v2 envelope rather than v1 AES-GCM."""
        return self.pii_envelope is not None and self.pii_envelope.get("v") == 2

    def to_trp_extension(self) -> dict[str, Any]:
        """
        Serialize to TRP v3 extensions field format.

        TRP uses HTTPS POST with JSON payloads. The ZK proof reference
        and encrypted PII are placed in the extensions field so that
        ZK-capable beneficiaries can verify the proof.
        """
        return {
            "zk_travel_rule": {
                "version": "1.0",
                "compliance_proof": {
                    "proof_id": self.compliance_proof.proof_id,
                    "transfer_id": self.compliance_proof.transfer_id,
                    "groth16_proof": self.compliance_proof.groth16_proof,
                    "public_signals": self.compliance_proof.public_signals,
                    "verification_key": self.compliance_proof.verification_key,
                    "originator_vasp_did": self.compliance_proof.originator_vasp_did,
                    "beneficiary_vasp_did": self.compliance_proof.beneficiary_vasp_did,
                    "jurisdiction": self.compliance_proof.jurisdiction,
                    "amount_tier": self.compliance_proof.amount_tier,
                    "proof_generated_at": self.compliance_proof.proof_generated_at,
                    "proof_expires_at": self.compliance_proof.proof_expires_at,
                    # sar_review_flag excluded — internal advisory only (BSA anti-tipping-off)
                },
                "encrypted_pii": base64.b64encode(self.encrypted_pii).decode("ascii"),
                "encryption_algorithm": self.encryption_algorithm,
                "pii_nonce": base64.b64encode(self.pii_nonce).decode("ascii"),
                "pii_associated_data": self.pii_associated_data,
                "pii_envelope": self.pii_envelope,
            }
        }

    def to_trisa_envelope(self) -> dict[str, Any]:
        """
        Serialize to TRISA secure envelope format.

        TRISA uses mTLS for transport security. The hybrid payload is
        placed inside the TRISA SecureEnvelope with the ZK proof as
        an additional attestation layer.
        """
        return {
            "id": self.compliance_proof.transfer_id,
            "payload": base64.b64encode(self.encrypted_pii).decode("ascii"),
            "encryption_key": None,  # Exchanged via TRISA mTLS
            "encryption_algorithm": self.encryption_algorithm,
            "hmac": "",  # Computed by TRISA envelope layer
            "hmac_algorithm": "HMAC-SHA256",
            "sealed": False,
            "public_key_signature": "",
            "transfer_state": "PENDING",
            "extensions": {
                "zk_compliance_proof": {
                    "proof_id": self.compliance_proof.proof_id,
                    "groth16_proof": self.compliance_proof.groth16_proof,
                    "public_signals": self.compliance_proof.public_signals,
                    "verification_key": self.compliance_proof.verification_key,
                    "originator_vasp_did": self.compliance_proof.originator_vasp_did,
                    "jurisdiction": self.compliance_proof.jurisdiction,
                    "amount_tier": self.compliance_proof.amount_tier,
                    # sar_review_flag excluded — internal advisory only
                },
                "pii_nonce": base64.b64encode(self.pii_nonce).decode("ascii"),
                "pii_associated_data": self.pii_associated_data,
                "pii_envelope": self.pii_envelope,
            },
        }
