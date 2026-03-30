"""
Compliance tests for sanctions list Merkle tree.

Tests building the sanctions tree, generating non-membership proofs
for clean addresses, and verifying that sanctioned addresses cannot
produce non-membership proofs.

NOTE: These tests mock the Poseidon hash subprocess to avoid requiring
Node.js. The mock returns deterministic hashes based on input values.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.registry.sanctions_list import (
    SanctionsMerkleTree,
    KNOWN_SANCTIONED_ADDRESSES,
    _address_to_int,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_hash_counter = 0


def _mock_poseidon_hash_factory():
    """
    Create a deterministic mock for _poseidon_hash.

    Returns the sum of integer inputs as the hash (deterministic, sortable).
    For single inputs, returns the input value itself.
    For two inputs (internal nodes), returns sum of inputs.
    """
    async def _mock_poseidon(inputs: list[int | str]) -> str:
        int_inputs = [int(x) for x in inputs]
        if len(int_inputs) == 1:
            return str(int_inputs[0])
        return str(sum(int_inputs))

    return _mock_poseidon


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSanctionsTreeBuild:
    @pytest.mark.asyncio
    async def test_build_from_addresses(self):
        """SanctionsMerkleTree can be built from a list of addresses."""
        tree = SanctionsMerkleTree()

        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            root = await tree.build_from_addresses(
                KNOWN_SANCTIONED_ADDRESSES[:3]
            )

        assert root is not None
        assert tree.root == root
        assert len(tree.sorted_leaves) == 3
        assert tree.depth >= 1

    @pytest.mark.asyncio
    async def test_tree_root_is_deterministic(self):
        """Building from the same addresses produces the same root."""
        addresses = KNOWN_SANCTIONED_ADDRESSES[:4]

        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            tree1 = SanctionsMerkleTree()
            root1 = await tree1.build_from_addresses(addresses)

            tree2 = SanctionsMerkleTree()
            root2 = await tree2.build_from_addresses(addresses)

        assert root1 == root2

    @pytest.mark.asyncio
    async def test_known_sanctioned_addresses_exist(self):
        """The KNOWN_SANCTIONED_ADDRESSES list is non-empty."""
        assert len(KNOWN_SANCTIONED_ADDRESSES) > 0


class TestCleanAddressNonmembership:
    @pytest.mark.asyncio
    async def test_clean_address_nonmembership(self):
        """A clean (non-sanctioned) address can produce a non-membership witness."""
        tree = SanctionsMerkleTree()
        clean_address = "0x0000000000000000000000000000000000000001"

        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            await tree.build_from_addresses(KNOWN_SANCTIONED_ADDRESSES[:3])
            witness = await tree.generate_nonmembership_witness(clean_address)

        assert "left_neighbor" in witness
        assert "right_neighbor" in witness
        assert "left_path" in witness
        assert "right_path" in witness

        # The left and right paths should contain sibling hashes and indices
        assert "siblings" in witness["left_path"]
        assert "indices" in witness["left_path"]


class TestSanctionedAddressMembership:
    @pytest.mark.asyncio
    async def test_sanctioned_address_rejects_nonmembership(self):
        """A sanctioned address raises ValueError when requesting non-membership proof."""
        tree = SanctionsMerkleTree()
        # Use the first sanctioned address
        sanctioned = KNOWN_SANCTIONED_ADDRESSES[0]

        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            await tree.build_from_addresses(KNOWN_SANCTIONED_ADDRESSES[:3])

            with pytest.raises(
                ValueError,
                match="Address IS in the sanctions list",
            ):
                await tree.generate_nonmembership_witness(sanctioned)


class TestAddressToInt:
    def test_hex_address_conversion(self):
        """_address_to_int correctly converts hex addresses to integers."""
        addr = "0x0000000000000000000000000000000000000001"
        assert _address_to_int(addr) == 1

    def test_case_insensitive(self):
        """_address_to_int is case-insensitive."""
        lower = "0xabcdef"
        upper = "0xABCDEF"
        assert _address_to_int(lower) == _address_to_int(upper)

    def test_strips_0x_prefix(self):
        """_address_to_int handles addresses with and without 0x prefix."""
        with_prefix = "0xff"
        without_prefix = "ff"
        assert _address_to_int(with_prefix) == _address_to_int(without_prefix)
