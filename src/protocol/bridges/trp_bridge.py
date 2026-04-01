"""
TRP/OpenVASP REST bridge — translates a hybrid payload into TRP v3 wire format.

TRP workflow:
  1. Originator obtains beneficiary Travel Address from their VASP.
  2. POST to the Travel Address endpoint with transfer + identity data.
  3. Beneficiary VASP responds with confirmation or rejection.

Wire format (JSON over HTTPS POST):
  - Top-level ``asset``, ``amount``, ``originator``, ``beneficiary`` fields
    follow the TRP v3 specification.
  - ``originatorPersons`` and ``beneficiaryPersons`` arrays are left empty
    because PII is replaced by the ZK proof + encrypted PII bundle.
  - The ``extensions.zk_travel_rule`` object carries the ZK proof reference
    and encrypted PII.  Legacy (non-ZK) parsers silently ignore extensions,
    so the message remains backwards-compatible.
"""

from __future__ import annotations

import base64
from typing import Any

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload

__all__ = ["TRPBridge"]

# SLIP-44 registered coin types used by TRP ``asset.slip44``.
_SLIP44_MAP: dict[str, int] = {
    "BTC": 0,
    "ETH": 60,
    "USDC": 60,   # ERC-20 on Ethereum
    "USDT": 195,  # Tron-native default; Ethereum variant also acceptable
}


class TRPBridge:
    """Translates hybrid payloads into TRP v3 JSON request bodies."""

    def build_trp_request(
        self,
        compliance_proof: ComplianceProof,
        hybrid_payload: HybridPayload,
        beneficiary_travel_address: str,
        amount: str,
        asset: str,
    ) -> dict[str, Any]:
        """
        Build a TRP v3 POST body embedding the hybrid ZK Travel Rule payload.

        The returned dict is JSON-serialisable and intended to be sent as the
        request body to ``POST {beneficiary_travel_address}``.

        Parameters
        ----------
        compliance_proof:
            The ZK compliance attestation for this transfer.
        hybrid_payload:
            The combined ZK proof + encrypted PII bundle.
        beneficiary_travel_address:
            HTTPS endpoint of the beneficiary VASP (TRP Travel Address).
        amount:
            Transfer amount as a decimal string (e.g. ``"1500.00"``).
        asset:
            Asset symbol (e.g. ``"ETH"``, ``"USDC"``).

        Returns
        -------
        dict
            TRP v3-compatible JSON body.  The ``extensions.zk_travel_rule``
            field is silently ignored by legacy parsers that do not understand
            ZK proofs.
        """
        return {
            "asset": {
                "slip44": self._asset_to_slip44(asset),
            },
            "amount": amount,
            "beneficiary": {
                "beneficiaryPersons": [],  # PII replaced by proof
                "accountNumber": [compliance_proof.transfer_id],
            },
            "originator": {
                "originatorPersons": [],  # PII replaced by proof
                "accountNumber": [compliance_proof.transfer_id],
            },
            # Encrypted PII alongside the message for regulatory record-keeping
            "ivms101_encrypted": base64.b64encode(
                hybrid_payload.encrypted_pii
            ).decode("ascii"),
            "ivms101_encryption_algorithm": hybrid_payload.encryption_algorithm,
            # Extension field — non-breaking for legacy parsers
            "extensions": {
                "zk_travel_rule": {
                    "version": "1.0",
                    "proof_id": compliance_proof.proof_id,
                    "groth16_proof": compliance_proof.groth16_proof,
                    "public_signals": compliance_proof.public_signals,
                    "verification_key": compliance_proof.verification_key,
                    "originator_vasp_did": compliance_proof.originator_vasp_did,
                    "beneficiary_vasp_did": compliance_proof.beneficiary_vasp_did,
                    "jurisdiction": compliance_proof.jurisdiction,
                    "amount_tier": compliance_proof.amount_tier,
                    "proof_generated_at": compliance_proof.proof_generated_at,
                    "proof_expires_at": compliance_proof.proof_expires_at,
                    # sar_review_flag excluded — internal advisory only (BSA anti-tipping-off)
                    # Encrypted PII nonce + AAD for envelope binding
                    "pii_nonce": base64.b64encode(
                        hybrid_payload.pii_nonce
                    ).decode("ascii"),
                    "pii_associated_data": hybrid_payload.pii_associated_data,
                },
            },
        }

    @staticmethod
    def _asset_to_slip44(asset: str) -> int:
        """
        Map an asset symbol to its SLIP-44 registered coin type.

        Falls back to 60 (Ethereum) for unrecognised symbols, which is
        appropriate for the majority of ERC-20 tokens.
        """
        return _SLIP44_MAP.get(asset.upper(), 60)
