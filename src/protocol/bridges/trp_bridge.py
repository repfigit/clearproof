"""Legacy experimental TRP-shaped payload builder and explicit local bilateral profile.

The legacy body omits mandatory person data and uses ambiguous symbol/SLIP-44
mapping. It is not evidence of TRP conformance or negotiated extension support.
Use build_pilot_request only with the matching local counterparty simulator;
that profile validates encrypted identity semantics without claiming live TRP interoperability.

Encrypted PII is serialized once through :meth:`HybridPayload.pii_wire_fields`:
``ivms101_encrypted`` / ``ivms101_encryption_algorithm`` stay at the top level
(unchanged keys) and ``pii_nonce``, ``pii_associated_data`` and the HPKE v2
``pii_envelope`` (null for legacy v1) travel in ``extensions.zk_travel_rule``,
together with ``transfer_id``. These keys are additive; :meth:`TRPBridge.parse_trp_request`
reads older bodies without them as legacy v1 and takes the transfer id from
``originator.accountNumber``.
"""

from __future__ import annotations

from typing import Any

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload

__all__ = ["TRPBridge"]

# SLIP-44 registered coin types used by TRP ``asset.slip44``.
_SLIP44_MAP: dict[str, int] = {
    "BTC": 0,
    "ETH": 60,
    "USDC": 60,  # ERC-20 on Ethereum
    "USDT": 195,  # Historical default; this does not identify every USDT deployment
}


class TRPBridge:
    """Legacy formatting plus a separately versioned local bilateral exchange boundary."""

    @staticmethod
    def build_pilot_request(record: dict, receipt: dict) -> dict:
        from src.protocol.bridges.pilot_bilateral import build_pilot_request

        return build_pilot_request(record, receipt)

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
            Experimental legacy JSON body. Extension acceptance and required
            TRP identity semantics are not established by this formatter.
        """
        pii = hybrid_payload.pii_wire_fields()
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
            "ivms101_encrypted": pii["encrypted_pii"],
            "ivms101_encryption_algorithm": pii["encryption_algorithm"],
            # Experimental extension; remote acceptance must be negotiated
            "extensions": {
                "zk_travel_rule": {
                    "version": "1.0",
                    "proof_id": compliance_proof.proof_id,
                    "transfer_id": compliance_proof.transfer_id,
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
                    # Encrypted PII nonce + AAD for envelope binding, and the HPKE v2 envelope
                    "pii_nonce": pii["pii_nonce"],
                    "pii_associated_data": pii["pii_associated_data"],
                    "pii_envelope": pii["pii_envelope"],
                },
            },
        }

    @staticmethod
    def parse_trp_request(request: dict[str, Any]) -> HybridPayload:
        """
        Beneficiary side of :meth:`build_trp_request`.

        Rebuilds the :class:`HybridPayload` (with any HPKE v2 envelope) so the
        beneficiary can decrypt the PII with its own key. The proof fields are
        taken as sent; verifying them is a separate step.
        """
        extension = request["extensions"]["zk_travel_rule"]
        proof = ComplianceProof(
            proof_id=extension["proof_id"],
            transfer_id=extension.get("transfer_id") or request["originator"]["accountNumber"][0],
            groth16_proof=extension["groth16_proof"],
            public_signals=extension["public_signals"],
            verification_key=extension["verification_key"],
            originator_vasp_did=extension["originator_vasp_did"],
            beneficiary_vasp_did=extension.get("beneficiary_vasp_did"),
            jurisdiction=extension["jurisdiction"],
            amount_tier=extension["amount_tier"],
            proof_generated_at=extension["proof_generated_at"],
            proof_expires_at=extension["proof_expires_at"],
        )
        fields = {
            "encrypted_pii": request["ivms101_encrypted"],
            "encryption_algorithm": request["ivms101_encryption_algorithm"],
            "pii_nonce": extension["pii_nonce"],
            "pii_associated_data": extension["pii_associated_data"],
            "pii_envelope": extension.get("pii_envelope"),
        }
        return HybridPayload.from_pii_wire_fields(proof, fields)

    @staticmethod
    def _asset_to_slip44(asset: str) -> int:
        """
        Map an asset symbol to its SLIP-44 registered coin type.

        Retains the historical fallback to 60 for unknown symbols. This is not
        an exact asset/chain identifier and must not establish pilot transfer identity.
        """
        return _SLIP44_MAP.get(asset.upper(), 60)
