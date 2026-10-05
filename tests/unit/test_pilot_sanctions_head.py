"""Pilot sanctions artifacts, root authentication and checkpoint publication arguments."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.chain.pilot_checkpoint import tenant_checkpoint_hash
from src.chain.pilot_sanctions_head import (
    SANCTIONS_KIND,
    authenticate_sanctions_root,
    checkpoint_arguments,
    registry_head_arguments,
    registry_tenant_hash,
)
from src.protocol.canonical import record_digest
from src.protocol.root_snapshot import (
    RootAuthority,
    RootSnapshot,
    RootTrustError,
    RootTrustStore,
    root_scope_id,
    sign_root,
)
from src.registry.pilot_sanctions import ARTIFACT_SCHEMA, PilotSanctionsTree

ADDRESSES = ["0x" + "ab" * 20, "0x" + "12" * 20, "0x" + "03" * 20]


def sanctions_case(tree=None, **changes):
    tree = tree or PilotSanctionsTree(list(ADDRESSES))
    private = Ed25519PrivateKey.generate()
    authority = RootAuthority(
        public_key=private.public_key().public_bytes_raw().hex(),
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address="0x" + "34" * 20,
        kinds=("sanctions-root", "issuer-root"),
        not_before=0,
        not_after=10_000,
    )
    fields = dict(
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address=authority.registry_address,
        kind="sanctions-root",
        root=tree.root,
        tree_depth=tree.depth,
        source_digest=tree.source_digest,
        revision=1,
        issued_at=100,
        expires_at=200,
        key_id=authority.key_id,
    )
    snapshot = RootSnapshot(**{**fields, **changes})
    return tree, sign_root(snapshot, private), RootTrustStore([authority])


def test_artifact_lists_sorted_addresses_and_round_trips():
    tree = PilotSanctionsTree(list(ADDRESSES))
    artifact = tree.artifact()
    assert artifact["schema_version"] == ARTIFACT_SCHEMA
    assert artifact["sorted_addresses"] == sorted(ADDRESSES)
    assert (artifact["address_count"], artifact["leaf_count"], artifact["depth"]) == (3, 5, 20)
    assert artifact["sentinels"] == ["0", str(2**160)]
    rebuilt = PilotSanctionsTree.from_artifact(artifact)
    assert (rebuilt.root, rebuilt.source_digest, rebuilt.addresses) == (tree.root, tree.source_digest, tree.addresses)
    assert PilotSanctionsTree.from_artifact(PilotSanctionsTree([]).artifact()).addresses == ()


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda a: a.update(schema_version="other"), "Unsupported"),
        (lambda a: a.update(profile="other"), "Unsupported"),
        (lambda a: a.update(sorted_addresses=None), "address list"),
        (lambda a: a.update(sorted_addresses=list(reversed(a["sorted_addresses"]))), "strictly sorted"),
        (lambda a: a.update(sorted_addresses=a["sorted_addresses"][:1] * 2), "strictly sorted"),
        (lambda a: a.update(sorted_addresses=["0x" + "AB" * 20]), "canonical raw EVM address"),
        (lambda a: a.update(root="1"), "does not match"),
        (lambda a: a.update(source_digest="0" * 64), "does not match"),
        (lambda a: a.update(address_count=4), "does not match"),
        (lambda a: a.update(depth=8), "does not match"),
        (lambda a: a.pop("leaf_domain_tag"), "does not match"),
    ],
)
def test_artifact_rejects_unsorted_or_inconsistent_publication(mutate, message):
    artifact = PilotSanctionsTree(list(ADDRESSES)).artifact()
    mutate(artifact)
    with pytest.raises(ValueError, match=message):
        PilotSanctionsTree.from_artifact(artifact)


def test_artifact_requires_a_mapping():
    with pytest.raises(ValueError, match="Unsupported"):
        PilotSanctionsTree.from_artifact([])


def test_registry_arguments_match_mirror_plan_head_and_kind():
    tree, signed, trust = sanctions_case()
    snapshot = signed.snapshot
    arguments = registry_head_arguments(signed, trust, tree, now=150, expected_revision=4)
    assert arguments == (
        bytes.fromhex(record_digest("clearproof/tenant-checkpoint/v1", {"tenant_id": "tenant-a"})),
        SANCTIONS_KIND,
        bytes.fromhex(root_scope_id(snapshot)),
        bytes.fromhex(snapshot.digest),
        int(tree.root),
        4,
        100,
        200,
        True,
    )
    assert arguments[0] == registry_tenant_hash("tenant-a")


def test_checkpoint_arguments_follow_existing_publication_flow():
    tree, signed, trust = sanctions_case()
    arguments = checkpoint_arguments(signed, trust, tree, now=150, expected_revision=0)
    assert arguments[0] == tenant_checkpoint_hash("tenant-a")
    assert arguments[3:6] == (int(tree.root), 0, 1)
    with pytest.raises(ValueError, match="preceding checkpoint revision"):
        checkpoint_arguments(signed, trust, tree, now=150, expected_revision=1)


@pytest.mark.parametrize("revision", [True, "0", -1, 2**53 - 1])
def test_registry_arguments_require_current_revision(revision):
    tree, signed, trust = sanctions_case()
    with pytest.raises(ValueError, match="current registry head revision"):
        registry_head_arguments(signed, trust, tree, now=150, expected_revision=revision)


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "issuer-root"},
        {"tree_depth": 8},
        {"root": "7"},
        {"source_digest": "f" * 64},
    ],
)
def test_approval_must_cover_exactly_the_rebuilt_tree(changes):
    tree, signed, trust = sanctions_case(**changes)
    with pytest.raises(RootTrustError, match="rebuilt pilot tree"):
        authenticate_sanctions_root(signed, trust, tree, now=150)


def test_tree_at_another_depth_is_rejected_even_with_matching_approval():
    tree = PilotSanctionsTree(list(ADDRESSES), depth=8)
    _, signed, trust = sanctions_case(tree=tree)
    with pytest.raises(RootTrustError, match="rebuilt pilot tree"):
        authenticate_sanctions_root(signed, trust, tree, now=150)


def test_untrusted_or_expired_approval_is_rejected():
    tree, signed, trust = sanctions_case()
    _, _, other_trust = sanctions_case()
    with pytest.raises(RootTrustError):
        authenticate_sanctions_root(signed, other_trust, tree, now=150)
    with pytest.raises(RootTrustError, match="validity interval"):
        authenticate_sanctions_root(signed, trust, tree, now=200)
