"""Local sanctions artifact lifecycle and declared tree-depth preservation."""

import json
import os

import pytest

from src.registry.sanctions_list import SanctionsMerkleTree


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("CIRCUIT_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path / "sanctions_tree.json"


async def write_tree(path):
    tree = SanctionsMerkleTree(depth=20)
    await tree.build_from_addresses([])
    path.write_text(
        json.dumps(
            {"root": tree.root, "depth": tree.depth, "sorted_leaves": tree.sorted_leaves, "tree_layers": tree._tree}
        )
    )
    return tree


def test_missing_artifact_and_unbuilt_tree_reject(artifact):
    with pytest.raises(RuntimeError, match="Sanctions tree file not found"):
        SanctionsMerkleTree.load()
    with pytest.raises(RuntimeError, match="Tree not built"):
        SanctionsMerkleTree().get_root()


@pytest.mark.parametrize("age", [99, 100, 101])
async def test_load_staleness_boundary(artifact, monkeypatch, caplog, age):
    expected = await write_tree(artifact)
    monkeypatch.setattr(SanctionsMerkleTree, "MAX_TREE_AGE_SECONDS", 100)
    monkeypatch.setattr("time.time", lambda: 1000)
    os.utime(artifact, (1000 - age, 1000 - age))
    loaded = SanctionsMerkleTree.load()
    assert loaded.get_root() == expected.get_root()
    assert loaded.depth == 20
    assert ("Sanctions tree is" in caplog.text) is (age > 100)


async def test_rebuild_loaded_fixed_depth_preserves_profile(artifact):
    expected = await write_tree(artifact)
    loaded = SanctionsMerkleTree.load()
    assert await loaded.build_from_addresses([]) == expected.get_root()
    assert loaded.depth == 20


@pytest.mark.parametrize("depth", [None, 0, -1, 33, True, 1.5, "20"])
def test_invalid_artifact_depth_rejected(artifact, depth):
    artifact.write_text(json.dumps({"root": "1", "sorted_leaves": ["0", "1"], "depth": depth}))
    with pytest.raises(ValueError, match="Merkle depth"):
        SanctionsMerkleTree.load()


async def test_metadata_only_legacy_artifact_cannot_generate_witness(artifact):
    artifact.write_text(json.dumps({"root": "1", "sorted_leaves": ["0", str(2**252 - 1)], "depth": 20}))
    loaded = SanctionsMerkleTree.load()
    with pytest.raises(RuntimeError, match="does not include tree_layers"):
        await loaded.generate_nonmembership_witness("0x01")
    with pytest.raises(RuntimeError, match="Tree is empty"):
        await SanctionsMerkleTree().generate_nonmembership_witness("0x01")


def test_invalid_json_rejected(artifact):
    artifact.write_text("{")
    with pytest.raises(json.JSONDecodeError):
        SanctionsMerkleTree.load()


@pytest.mark.parametrize("side", ["below", "above"])
async def test_missing_bracketing_leaves_cannot_produce_gap_witness(artifact, side):
    from src.registry.poseidon import poseidon_hash

    query = poseidon_hash([1, 1])
    leaves = [query + 1, query + 2] if side == "below" else [query - 2, query - 1]
    root = poseidon_hash(leaves)
    artifact.write_text(
        json.dumps(
            {
                "root": str(root),
                "sorted_leaves": leaves,
                "depth": 1,
                "tree_layers": [list(map(str, leaves)), [str(root)]],
            }
        )
    )
    tree = SanctionsMerkleTree.load()
    with pytest.raises(ValueError, match="not bracketed"):
        await tree.generate_nonmembership_witness("0x01")
