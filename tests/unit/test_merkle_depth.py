"""Fixed circuit depths preserve real membership paths without full allocation."""

import pytest

from src.registry.issuer_registry import IssuerRegistry
from src.registry.merkle_depth import extend_depth
from src.registry.poseidon import poseidon_hash
from src.registry.sanctions_list import SanctionsMerkleTree


def fold(leaf, witness):
    value = int(leaf)
    for sibling, direction in zip(witness["siblings"], witness["indices"], strict=True):
        value = poseidon_hash([int(sibling), value] if direction else [value, int(sibling)])
    return str(value)


@pytest.mark.parametrize("depth", [0, -1, 33, True, 2.5])
def test_invalid_depths(depth):
    for factory in (IssuerRegistry, SanctionsMerkleTree):
        with pytest.raises(ValueError, match="Merkle depth"):
            factory(depth=depth)


async def test_real_issuer_witness_has_circuit_depth():
    registry = IssuerRegistry(depth=10)
    root = await registry.add_issuer("did:web:synthetic.example")
    witness = await registry.generate_membership_witness("did:web:synthetic.example")
    assert len(witness["siblings"]) == 10
    assert fold(witness["leaf"], witness) == root
    assert sum(map(len, registry._tree)) < 30


async def test_real_sanctions_witness_has_circuit_depth():
    tree = SanctionsMerkleTree(depth=20)
    root = await tree.build_from_addresses([])
    wallet = next("0x" + format(i, "040x") for i in range(1, 100) if poseidon_hash([1, i]) < tree._MAX_SENTINEL)
    witness = await tree.generate_nonmembership_witness(wallet)
    for side in ("left", "right"):
        path = witness[f"{side}_path"]
        assert len(path["siblings"]) == 20
        assert fold(witness[f"{side}_neighbor"], path) == root
    assert sum(map(len, tree._tree)) < 50


async def test_capacity_rejection_preserves_existing_trees():
    issuer = IssuerRegistry(depth=1)
    await issuer.add_issuer("did:web:a.example")
    root = await issuer.add_issuer("did:web:b.example")
    with pytest.raises(ValueError, match="exceeds"):
        await issuer.add_issuer("did:web:c.example")
    assert issuer.get_root() == root
    assert len(issuer._issuers) == 2
    sanctions = SanctionsMerkleTree(depth=1)
    root = await sanctions.build_from_addresses([])
    with pytest.raises(ValueError, match="exceeds"):
        await sanctions.build_from_addresses(["0x01"])
    assert sanctions.get_root() == root
    assert len(sanctions.sorted_leaves) == 2


async def test_extension_rejects_shrinking():
    async def hash_pair(values):
        return str(poseidon_hash(values))

    with pytest.raises(ValueError, match="exceeds"):
        await extend_depth([["0", "0"], ["1"]], 0, hash_pair)
