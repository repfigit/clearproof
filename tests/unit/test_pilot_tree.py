"""Sparse tree paths agree with the dense Poseidon construction."""

import pytest

from src.registry.pilot_tree import PilotTree
from src.registry.poseidon import BN254_SCALAR_FIELD, poseidon_hash


def test_sparse_root_and_paths_match_dense_reference():
    entries = [("c", "33"), ("a", "11"), ("b", "22")]
    tree = PilotTree(entries, depth=3)
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
        ([], 21),
        ([], True),
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
