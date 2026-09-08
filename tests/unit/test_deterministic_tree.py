"""Tests for deterministic sanctions tree building."""

import json

import pytest

from scripts.build_sanctions_tree import (
    BUILD_SCRIPT_VERSION,
    MAX_SENTINEL,
    SANCTIONS_DOMAIN_TAG,
    build_merkle_tree,
    normalize_address,
)
from src.registry.sanctions_list import SanctionsMerkleTree


class TestAddressNormalization:
    def test_lowercase(self):
        assert (
            normalize_address("0xABCDEF1234567890abcdef1234567890ABCDEF12")
            == "0xabcdef1234567890abcdef1234567890abcdef12"
        )

    def test_adds_0x_prefix(self):
        assert normalize_address("abcdef1234567890abcdef1234567890abcdef12").startswith("0x")

    def test_strips_whitespace(self):
        assert normalize_address("  0xabc123  ") == normalize_address("0xabc123")

    def test_zero_pads_short_address(self):
        result = normalize_address("0xabc")
        assert len(result) == 42  # 0x + 40 hex
        assert result.startswith("0x")

    def test_deterministic(self):
        """Same input always produces same output."""
        addr = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"
        assert normalize_address(addr) == normalize_address(addr)

    def test_checksummed_and_lowercase_same_result(self):
        """EIP-55 checksummed and lowercase produce identical normalized form."""
        checksummed = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"
        lowered = "0x8589427373d6d84e98730d7795d8f6f8731fda16"
        assert normalize_address(checksummed) == normalize_address(lowered)


class TestBuildConfig:
    def test_version_exists(self):
        assert BUILD_SCRIPT_VERSION == "1.2.0"

    def test_domain_tag(self):
        assert SANCTIONS_DOMAIN_TAG == 1

    def test_sorted_output_is_deterministic(self):
        """Sorting normalized addresses is deterministic."""
        addrs = [
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "0x0000000000000000000000000000000000000001",
            "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
        ]
        normalized = sorted(normalize_address(a) for a in addrs)
        normalized2 = sorted(normalize_address(a) for a in reversed(addrs))
        assert normalized == normalized2


class TestSanctionsArtifact:
    @pytest.mark.asyncio
    async def test_artifact_load_can_generate_nonmembership_witness(self, tmp_path, monkeypatch):
        """A persisted tree artifact has enough data to generate Merkle paths."""

        async def fake_poseidon(inputs):
            values = [int(v) for v in inputs]
            result = values[0]
            for value in values[1:]:
                result = result * 1000003 + value
            return str(result)

        monkeypatch.setattr("scripts.build_sanctions_tree.poseidon_hash", fake_poseidon)
        monkeypatch.setattr("src.registry.sanctions_list._poseidon_hash", fake_poseidon)

        tree_data = await build_merkle_tree(
            [
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000004",
            ]
        )
        artifact = tmp_path / "sanctions_tree.json"
        artifact.write_text(json.dumps(tree_data), encoding="utf-8")

        loaded = SanctionsMerkleTree.build_from_file(str(artifact))
        witness = await loaded.generate_nonmembership_witness("0x0000000000000000000000000000000000000003")

        assert loaded.sorted_leaves[0] == 0
        assert loaded.sorted_leaves[-1] == MAX_SENTINEL
        assert witness["left_neighbor"] < witness["right_neighbor"]
        assert len(witness["left_path"]["siblings"]) == loaded.depth
        assert len(witness["right_path"]["siblings"]) == loaded.depth


async def test_explicit_circuit_depth_matches_native_builder_and_reload(tmp_path):
    tree_data = await build_merkle_tree([], target_depth=20)
    native = SanctionsMerkleTree(depth=20)
    assert tree_data["root"] == await native.build_from_addresses([])
    assert tree_data["depth"] == 20
    assert tree_data["padded_size"] == 2**20
    assert sum(map(len, tree_data["tree_layers"])) < 50
    path = tmp_path / "synthetic.json"
    path.write_text(json.dumps(tree_data))
    loaded = SanctionsMerkleTree.build_from_file(str(path))
    assert loaded.get_root() == native.get_root()
    assert loaded.depth == 20
    for depth in [0, 33, True]:
        with pytest.raises(ValueError, match="depth"):
            await build_merkle_tree([], target_depth=depth)
    with pytest.raises(ValueError, match="exceeds"):
        await build_merkle_tree(["0x" + "1" * 40], target_depth=1)


def test_builder_cli_exposes_depth_and_rejects_invalid_depth_before_building():
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts/build_sanctions_tree.py"
    help_result = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, timeout=10)
    assert help_result.returncode == 0
    assert b"--depth" in help_result.stdout
    invalid = subprocess.run(
        [sys.executable, str(script), "--offline", "--depth", "0"], capture_output=True, timeout=10
    )
    assert invalid.returncode != 0
    assert b"Merkle depth must" in invalid.stderr
    assert b"Building Merkle tree" not in invalid.stdout
