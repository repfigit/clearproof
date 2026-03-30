"""
Integration tests for TRP bridge — verifies TRP v3 request structure.

Tests that TRPBridge.build_trp_request produces valid TRP v3-compatible
JSON with the zk_travel_rule extension field.
"""

from __future__ import annotations

import base64

import pytest

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload
from src.protocol.bridges.trp_bridge import TRPBridge


class TestTRPBridge:
    """Tests for TRP v3 bridge request building."""

    def test_build_trp_request_structure(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
    ):
        """build_trp_request returns a dict with required TRP v3 top-level fields."""
        bridge = TRPBridge()
        request = bridge.build_trp_request(
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
            beneficiary_travel_address="https://beneficiary.example.com/trp",
            amount="1500.00",
            asset="USDC",
        )

        # Top-level TRP v3 fields
        assert "asset" in request
        assert "amount" in request
        assert "beneficiary" in request
        assert "originator" in request
        assert "extensions" in request

        assert request["amount"] == "1500.00"
        assert request["asset"]["slip44"] == 60  # USDC -> Ethereum

    def test_zk_extension_present(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
    ):
        """The extensions field contains zk_travel_rule with proof data."""
        bridge = TRPBridge()
        request = bridge.build_trp_request(
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
            beneficiary_travel_address="https://beneficiary.example.com/trp",
            amount="1500.00",
            asset="ETH",
        )

        zk = request["extensions"]["zk_travel_rule"]
        assert zk["version"] == "1.0"
        assert zk["proof_id"] == sample_compliance_proof.proof_id
        assert zk["jurisdiction"] == sample_compliance_proof.jurisdiction
        assert zk["amount_tier"] == sample_compliance_proof.amount_tier
        assert "groth16_proof" in zk
        assert "public_signals" in zk

    def test_pii_persons_arrays_empty(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
    ):
        """originatorPersons and beneficiaryPersons are empty (PII replaced by ZK proof)."""
        bridge = TRPBridge()
        request = bridge.build_trp_request(
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
            beneficiary_travel_address="https://beneficiary.example.com/trp",
            amount="500.00",
            asset="BTC",
        )

        assert request["originator"]["originatorPersons"] == []
        assert request["beneficiary"]["beneficiaryPersons"] == []

    def test_encrypted_pii_included(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
    ):
        """Encrypted IVMS101 PII is included as base64 in the request body."""
        bridge = TRPBridge()
        request = bridge.build_trp_request(
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
            beneficiary_travel_address="https://beneficiary.example.com/trp",
            amount="1500.00",
            asset="USDC",
        )

        assert "ivms101_encrypted" in request
        assert request["ivms101_encryption_algorithm"] == "AES-256-GCM"
        # Verify it's valid base64
        raw = base64.b64decode(request["ivms101_encrypted"])
        assert len(raw) > 0

    def test_asset_slip44_mapping(self):
        """Known assets map to correct SLIP-44 coin types."""
        bridge = TRPBridge()
        assert bridge._asset_to_slip44("BTC") == 0
        assert bridge._asset_to_slip44("ETH") == 60
        assert bridge._asset_to_slip44("USDC") == 60
        assert bridge._asset_to_slip44("USDT") == 195

    def test_unknown_asset_defaults_to_ethereum(self):
        """Unknown assets default to SLIP-44 60 (Ethereum)."""
        bridge = TRPBridge()
        assert bridge._asset_to_slip44("UNKNOWN_TOKEN") == 60
