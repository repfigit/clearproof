"""Sparse tree paths agree with the dense Poseidon construction."""

import pytest

from src.registry.pilot_tree import PilotTree
from src.registry.poseidon import BN254_SCALAR_FIELD, poseidon_hash


def test_sparse_root_and_paths_match_dense_reference():
    entries = [("c", "33"), ("a", "11"), ("b", "22")]
    tree = PilotTree(entries, depth=3)
    assert tree.entries == tuple(sorted(entries))
    assert tree.depth == 3
    layer = [11, 22, 33, 0, 0, 0, 0, 0]
    while len(layer) > 1:
        layer = [poseidon_hash(layer[i : i + 2]) for i in range(0, len(layer), 2)]
    assert tree.root == str(layer[0])
    assert PilotTree(list(reversed(entries)), depth=3).root == tree.root
    for key, leaf in entries:
        proof = tree.membership(key)
        value = int(leaf)
        for sibling, direction in zip(proof["siblings"], proof["indices"], strict=True):
            value = poseidon_hash([int(sibling), value] if direction else [value, int(sibling)])
        assert str(value) == tree.root
    with pytest.raises(KeyError):
        tree.membership("missing")


@pytest.mark.parametrize(
    "entries,depth",
    [
        ([("a", "1"), ("a", "2")], 2),
        ([("a", "1"), ("b", "1")], 2),
        ([("a", "0")], 2),
        ([("a", str(BN254_SCALAR_FIELD))], 2),
        ([("a", "1"), ("b", "2"), ("c", "3")], 1),
        ([], 33),
        ([], True),
        ((("a", "1"),), 2),
    ],
)
def test_invalid_or_overfull_tree_rejected(entries, depth):
    with pytest.raises(ValueError):
        PilotTree(entries, depth=depth)


def test_empty_tree_has_no_membership():
    tree = PilotTree([], depth=2)
    zero_parent = poseidon_hash([0, 0])
    assert tree.root == str(poseidon_hash([zero_parent, zero_parent]))
    with pytest.raises(KeyError):
        tree.membership("empty")


@pytest.mark.parametrize("identity", [None, 1, "", "Uppercase", "-prefix", "contains space", "a" * 65])
def test_tree_rejects_noncanonical_record_identifiers(identity):
    with pytest.raises(ValueError, match="Invalid tree entry ID"):
        PilotTree([(identity, "1")], depth=2)


@pytest.mark.parametrize(
    "inventory,depth",
    [
        (None, 20),
        ((), 20),
        ({"0x" + "12" * 20}, 20),
        (["0x" + f"{i:040x}" for i in range(1, 4)], 2),
        ([], 0),
        ([], 33),
        ([], True),
    ],
)
def test_sanctions_inventory_rejects_invalid_container_depth_or_over_capacity(inventory, depth, monkeypatch):
    from unittest.mock import Mock

    from src.registry import pilot_sanctions

    hashing = Mock(side_effect=AssertionError("Rejected inventory must not be hashed"))
    monkeypatch.setattr(pilot_sanctions, "poseidon_hash", hashing)
    with pytest.raises(ValueError, match="^Sanctions input exceeds tree capacity$"):
        pilot_sanctions.PilotSanctionsTree(inventory, depth=depth)
    hashing.assert_not_called()


def test_profile_depths_hold_global_inventories_without_dense_allocation():
    from src.registry.pilot_sanctions import PilotSanctionsTree
    from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, ISSUER_TREE_DEPTH, SANCTIONS_TREE_DEPTH

    assert (ISSUANCE_TREE_DEPTH, ISSUER_TREE_DEPTH, SANCTIONS_TREE_DEPTH) == (32, 20, 20)
    # Two leaves hold the sentinels; the rest is address capacity.
    full = ["0x" + f"{i:040x}" for i in range(1, 2**2 - 1)]
    assert PilotSanctionsTree(full, depth=2).depth == 2
    issuance = PilotTree([("a", "1")], depth=ISSUANCE_TREE_DEPTH)
    assert len(issuance.membership("a")["siblings"]) == ISSUANCE_TREE_DEPTH
    sanctions = PilotSanctionsTree(["0x" + "12" * 20])
    assert sanctions.depth == SANCTIONS_TREE_DEPTH
    assert len(sanctions.gap("0x" + "13" * 20)["left_siblings"]) == SANCTIONS_TREE_DEPTH
