"""
Tests for real OFAC sanctions addresses against the sanctions Merkle tree.

These tests use a mock Poseidon hash (no Node.js required) and verify
that known sanctioned addresses are properly included in the tree while
clean addresses can produce non-membership proofs.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.registry.sanctions_list import (
    KNOWN_SANCTIONED_ADDRESSES,
    SanctionsMerkleTree,
    _address_to_int,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_poseidon_hash_factory():
    """
    Deterministic mock for _poseidon_hash.

    Single inputs return the input value; two inputs return their sum.
    """

    async def _mock(inputs: list[int | str]) -> str:
        int_inputs = [int(x) for x in inputs]
        if len(int_inputs) == 1:
            return str(int_inputs[0])
        return str(sum(int_inputs))

    return _mock


TORNADO_CASH_ADDRESSES = [
    "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
    "0x722122dF12D4e14e13Ac3b6895a86e84145b6967",
    "0xDD4c48C0B24039969fC16D1cdF626eaB821d3384",
    "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
    "0xd96f2B1c14Db8458374d9Aca76E26c3D18364307",
    "0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBfA9",
    "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",
    "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",
    "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",
    "0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144",
    "0xF60dD140cFf0706bAE9Cd734Ac3683696B445d00",
]

LAZARUS_GROUP_ADDRESSES = [
    "0x7F367cC41522cE07553e823bf3be79A889debe1B",
    "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b",
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOFACTornadoCashBlocked:
    """Known Tornado Cash addresses must be in the tree (fail non-membership)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("address", TORNADO_CASH_ADDRESSES)
    async def test_tornado_cash_address_blocked(self, address: str):
        tree = SanctionsMerkleTree()
        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            await tree.build_from_addresses(KNOWN_SANCTIONED_ADDRESSES)
            with pytest.raises(
                ValueError,
                match="Address IS in the sanctions list",
            ):
                await tree.generate_nonmembership_witness(address)


class TestOFACLazarusBlocked:
    """Lazarus Group addresses must be in the tree (fail non-membership)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("address", LAZARUS_GROUP_ADDRESSES)
    async def test_lazarus_group_address_blocked(self, address: str):
        tree = SanctionsMerkleTree()
        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            await tree.build_from_addresses(KNOWN_SANCTIONED_ADDRESSES)
            with pytest.raises(
                ValueError,
                match="Address IS in the sanctions list",
            ):
                await tree.generate_nonmembership_witness(address)


class TestCleanAddressPasses:
    """A random non-sanctioned address can produce a non-membership witness."""

    @pytest.mark.asyncio
    async def test_clean_address_passes(self):
        # An address that is definitely not on any sanctions list
        clean = "0x0000000000000000000000000000000000C0FFEE"
        tree = SanctionsMerkleTree()
        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            await tree.build_from_addresses(KNOWN_SANCTIONED_ADDRESSES)
            witness = await tree.generate_nonmembership_witness(clean)

        assert "left_neighbor" in witness
        assert "right_neighbor" in witness
        assert "left_path" in witness
        assert "right_path" in witness

    @pytest.mark.asyncio
    async def test_another_clean_address_passes(self):
        clean = "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
        tree = SanctionsMerkleTree()
        with patch(
            "src.registry.sanctions_list._poseidon_hash",
            side_effect=_mock_poseidon_hash_factory(),
        ):
            await tree.build_from_addresses(KNOWN_SANCTIONED_ADDRESSES)
            witness = await tree.generate_nonmembership_witness(clean)

        assert "left_neighbor" in witness
        assert "right_neighbor" in witness


class TestTreeMinimumEntries:
    """The KNOWN_SANCTIONED_ADDRESSES list must contain at least 15 addresses."""

    def test_tree_has_minimum_entries(self):
        assert len(KNOWN_SANCTIONED_ADDRESSES) >= 15, (
            f"Expected at least 15 known sanctioned addresses, "
            f"got {len(KNOWN_SANCTIONED_ADDRESSES)}"
        )

    def test_addresses_are_valid_hex(self):
        for addr in KNOWN_SANCTIONED_ADDRESSES:
            assert addr.startswith("0x"), f"Address missing 0x prefix: {addr}"
            val = _address_to_int(addr)
            assert val > 0, f"Address converted to zero: {addr}"

    def test_no_duplicates(self):
        lower = [a.lower() for a in KNOWN_SANCTIONED_ADDRESSES]
        assert len(lower) == len(set(lower)), "Duplicate addresses found"


class TestBuildFromFile:
    """SanctionsMerkleTree.build_from_file loads a pre-built tree."""

    def test_build_from_file(self, tmp_path):
        import json

        data = {
            "root": "12345",
            "sorted_leaves": ["100", "200", "300"],
            "sorted_addresses": [
                "0xaaa0000000000000000000000000000000000000",
                "0xbbb0000000000000000000000000000000000000",
                "0xccc0000000000000000000000000000000000000",
            ],
            "depth": 2,
            "leaf_count": 3,
            "padded_size": 4,
            "source_metadata": {},
        }
        path = tmp_path / "test_tree.json"
        path.write_text(json.dumps(data))

        tree = SanctionsMerkleTree.build_from_file(str(path))
        assert tree.root == "12345"
        assert tree.sorted_leaves == [100, 200, 300]
        assert tree.depth == 2
        assert len(tree.sorted_addresses) == 3
