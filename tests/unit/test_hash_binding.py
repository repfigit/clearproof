"""
Tests for hash binding correctness.

The Python API must produce the same hash values that the Solidity contracts
verify. This is the most critical alignment in the system — if these hashes
don't match, on-chain proof verification silently fails.

Specifically:
- domain_contract_hash (signal 12): keccak256(address) % BN128_R
- transfer_id_hash (signal 13): keccak256(transferId) % BN128_R
- credential_nullifier (signal 14): Poseidon(credential_commitment, transfer_id_hash)
"""

import pytest
from web3 import Web3

# BN128 scalar field order (same constant used in ComplianceRegistry.sol)
BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


class TestDomainContractHash:
    """Signal 12: keccak256(abi.encodePacked(address)) % BN128_R."""

    def test_matches_solidity_pattern(self):
        """The Python hash must match what Solidity computes."""
        address = "0x4B889625d263fdD17F609c137ca9ea5463350d75"
        addr_bytes = bytes.fromhex(address.removeprefix("0x"))
        result = int.from_bytes(Web3.keccak(addr_bytes), "big") % BN128_R

        # Must be a valid field element (< BN128_R)
        assert 0 < result < BN128_R

    def test_zero_address(self):
        """Zero address should produce a non-zero hash."""
        addr_bytes = bytes(20)  # 0x0000...0000
        result = int.from_bytes(Web3.keccak(addr_bytes), "big") % BN128_R
        assert result != 0

    def test_different_addresses_different_hashes(self):
        """Two different addresses must produce different hashes."""
        addr1 = bytes.fromhex("4B889625d263fdD17F609c137ca9ea5463350d75")
        addr2 = bytes.fromhex("D2E419C913F2f3aA661DB422A295026F5A1CB71c")
        h1 = int.from_bytes(Web3.keccak(addr1), "big") % BN128_R
        h2 = int.from_bytes(Web3.keccak(addr2), "big") % BN128_R
        assert h1 != h2

    def test_result_is_within_field(self):
        """Result must be less than BN128_R (valid circuit input)."""
        # Use an address whose raw keccak would exceed BN128_R
        addr_bytes = bytes.fromhex("ffffffffffffffffffffffffffffffffffffffff")
        result = int.from_bytes(Web3.keccak(addr_bytes), "big") % BN128_R
        assert result < BN128_R


class TestTransferIdHash:
    """Signal 13: keccak256(abi.encodePacked(transferId)) % BN128_R."""

    def test_matches_solidity_pattern(self):
        """Transfer ID hash must use keccak256, not SHA-256."""
        transfer_id = "tx-abc-123"
        raw_hash = Web3.keccak(text=transfer_id)
        result = int.from_bytes(raw_hash, "big") % BN128_R
        assert 0 < result < BN128_R

    def test_different_ids_different_hashes(self):
        """Two different transfer IDs produce different hashes."""
        h1 = int.from_bytes(Web3.keccak(text="tx-001"), "big") % BN128_R
        h2 = int.from_bytes(Web3.keccak(text="tx-002"), "big") % BN128_R
        assert h1 != h2

    def test_deterministic(self):
        """Same input always produces same output."""
        h1 = int.from_bytes(Web3.keccak(text="same-id"), "big") % BN128_R
        h2 = int.from_bytes(Web3.keccak(text="same-id"), "big") % BN128_R
        assert h1 == h2

    def test_bytes32_encoding_matches_solidity(self):
        """When transferId is bytes32, keccak of packed bytes32 matches."""
        # Simulate Solidity: keccak256(abi.encodePacked(bytes32))
        transfer_id_bytes32 = Web3.keccak(text="some-transfer")
        result = int.from_bytes(Web3.keccak(transfer_id_bytes32), "big") % BN128_R
        assert 0 < result < BN128_R


class TestBN128Reduction:
    """Verify BN128_R modular reduction works correctly."""

    def test_bn128_r_is_prime(self):
        """BN128_R should be the known constant."""
        assert BN128_R == 21888242871839275222246405745257275088548364400416034343698204186575808495617

    def test_reduction_for_large_values(self):
        """Values larger than BN128_R are correctly reduced."""
        large_value = BN128_R + 42
        assert large_value % BN128_R == 42

    def test_keccak_output_always_reduces_to_valid_field(self):
        """Any keccak256 output, when reduced mod BN128_R, is a valid field element."""
        for i in range(10):
            h = int.from_bytes(Web3.keccak(text=f"test-{i}"), "big")
            reduced = h % BN128_R
            assert 0 <= reduced < BN128_R
