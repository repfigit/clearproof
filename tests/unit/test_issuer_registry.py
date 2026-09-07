"""Issuer set transitions and independently reconstructed Poseidon paths."""

import hashlib

import pytest

from src.registry.issuer_registry import IssuerRegistry, _did_to_int
from src.registry.poseidon import poseidon_hash


def reconstruct(witness):
    value = int(witness["leaf"])
    for sibling, direction in zip(witness["siblings"], witness["indices"], strict=True):
        pair = [int(sibling), value] if direction else [value, int(sibling)]
        value = poseidon_hash(pair)
    return str(value)


async def test_empty_duplicate_unknown_and_last_removal():
    registry = IssuerRegistry()
    with pytest.raises(RuntimeError, match="empty"):
        registry.get_root()
    with pytest.raises(KeyError):
        await registry.remove_issuer("did:example:missing")
    with pytest.raises(KeyError):
        await registry.generate_membership_witness("did:example:missing")
    original = await registry.add_issuer("did:example:first")
    with pytest.raises(ValueError, match="already registered"):
        await registry.add_issuer("did:example:first")
    assert registry.get_root() == original
    witness = await registry.generate_membership_witness("did:example:first")
    assert witness["siblings"] == ["0"]
    assert reconstruct(witness) == original
    assert await registry.remove_issuer("did:example:first") == "0"
    assert registry.depth == 0
    with pytest.raises(RuntimeError):
        registry.get_root()
    assert await registry.add_issuer("did:example:first") == original


async def test_paths_for_every_leaf_and_padding_after_removal():
    registry = IssuerRegistry()
    issuers = [f"did:example:issuer-{index}" for index in range(5)]
    for did in issuers:
        await registry.add_issuer(did)
    assert registry.depth == 3
    old_root = registry.get_root()
    for did in issuers:
        witness = await registry.generate_membership_witness(did)
        expected_did = int.from_bytes(hashlib.sha256(did.encode()).digest()[:16], "big")
        assert witness["leaf"] == str(poseidon_hash([2, expected_did]))
        assert reconstruct(witness) == old_root
    old_witness = await registry.generate_membership_witness(issuers[0])
    new_root = await registry.remove_issuer(issuers[1])
    assert registry.depth == 2
    assert new_root != old_root
    assert reconstruct(old_witness) != new_root
    with pytest.raises(KeyError):
        await registry.generate_membership_witness(issuers[1])
    for did in [issuers[0], *issuers[2:]]:
        assert reconstruct(await registry.generate_membership_witness(did)) == new_root


def test_entire_did_influences_hash():
    prefix = "did:example:" + "long-common-prefix" * 10
    assert _did_to_int(prefix + "a") != _did_to_int(prefix + "b")
    assert _did_to_int(prefix + "a") == _did_to_int(prefix + "a")
