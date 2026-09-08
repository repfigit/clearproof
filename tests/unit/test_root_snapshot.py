"""Real registrar signatures, scoped trust, rotation and historical/current boundaries."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.protocol.root_snapshot import RootAuthority, RootSnapshot, RootTrustError, RootTrustStore, sign_root


def authority(private, **changes):
    return RootAuthority(
        **{
            "public_key": private.public_key().public_bytes_raw().hex(),
            "tenant_id": "tenant-a",
            "chain_id": 31337,
            "registry_address": "0x" + "1" * 40,
            "kinds": ("issuer-root", "issuance-root"),
            "issuer_dids": ("did:web:issuer.example",),
            "not_before": 50,
            "not_after": 500,
            **changes,
        }
    )


@pytest.fixture
def approval():
    private = Ed25519PrivateKey.generate()
    approved = authority(private)
    snapshot = RootSnapshot(
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address="0x" + "1" * 40,
        kind="issuer-root",
        root="123",
        tree_depth=8,
        source_digest="a" * 64,
        revision=1,
        issued_at=100,
        expires_at=200,
        key_id=approved.key_id,
    )
    return private, approved, sign_root(snapshot, private)


def test_current_requires_independent_head_and_historical_does_not_claim_current(approval):
    _, approved, signed = approval
    trust = RootTrustStore([approved])
    args = dict(
        now=150,
        expected_digest=signed.snapshot.digest,
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address="0x" + "1" * 40,
        kind="issuer-root",
    )
    assert trust.verify_current(signed, **args) == signed.snapshot
    with pytest.raises(RootTrustError):
        trust.verify_current(signed, **{**args, "expected_digest": "b" * 64})
    with pytest.raises(RootTrustError):
        trust.verify_current(signed, **{**args, "now": 200})
    assert trust.verify_historical(signed, evaluated_at=150) == signed.snapshot


@pytest.mark.parametrize(
    "change",
    [
        {"root": "124"},
        {"tenant_id": "tenant-b"},
        {"chain_id": 1},
        {"source_digest": "b" * 64},
        {"tree_depth": 9},
        {"registry_address": "0x" + "2" * 40},
        {"expires_at": 201},
        {"revision": 2, "previous_digest": "b" * 64},
        {"key_id": "0" * 64},
    ],
)
def test_tampering_rejected(approval, change):
    _, approved, signed = approval
    altered = type(signed).model_validate(
        {"snapshot": {**signed.snapshot.model_dump(), **change}, "signature": signed.signature}
    )
    with pytest.raises(RootTrustError):
        RootTrustStore([approved]).verify_historical(altered, evaluated_at=150)


@pytest.mark.parametrize(
    "scope",
    [
        {"tenant_id": "tenant-b"},
        {"chain_id": 1},
        {"registry_address": "0x" + "2" * 40},
        {"kinds": ("sanctions-root",)},
        {"not_before": 101},
        {"not_after": 199},
    ],
)
def test_valid_signature_outside_operator_scope_is_rejected(approval, scope):
    private, _, signed = approval
    with pytest.raises(RootTrustError):
        RootTrustStore([authority(private, **scope)]).verify_historical(signed, evaluated_at=150)


def test_rotation_requires_retained_explicit_keys_and_exact_issuer_scope(approval):
    private, approved, signed = approval
    new_key = Ed25519PrivateKey.generate()
    new_authority = authority(new_key)
    rotated = RootTrustStore([approved, new_authority])
    assert rotated.verify_historical(signed, evaluated_at=150) == signed.snapshot
    with pytest.raises(RootTrustError):
        RootTrustStore([new_authority]).verify_historical(signed, evaluated_at=150)
    next_snapshot = RootSnapshot.model_validate(
        {
            **signed.snapshot.model_dump(),
            "revision": 2,
            "previous_digest": signed.snapshot.digest,
            "key_id": new_authority.key_id,
        }
    )
    assert rotated.verify_historical(sign_root(next_snapshot, new_key), evaluated_at=150) == next_snapshot
    with pytest.raises(RootTrustError):
        sign_root(next_snapshot, private)
    issuance = RootSnapshot.model_validate(
        {**signed.snapshot.model_dump(), "kind": "issuance-root", "issuer_did": "did:web:other.example"}
    )
    with pytest.raises(RootTrustError):
        rotated.verify_historical(sign_root(issuance, private), evaluated_at=150)


def test_historical_key_compromise_and_duplicate_scope_cannot_be_bypassed(approval):
    _, approved, signed = approval
    RootTrustStore([approved]).verify_historical(signed, evaluated_at=150, verified_at=1000)
    compromised = RootAuthority.model_validate({**approved.model_dump(), "compromised_at": 160})
    for authorities in ([compromised], [approved, compromised], [compromised, approved]):
        with pytest.raises(RootTrustError, match="compromise"):
            RootTrustStore(authorities).verify_historical(signed, evaluated_at=150, verified_at=1000)
        with pytest.raises(RootTrustError, match="compromise"):
            RootTrustStore(authorities).verify_historical(signed, evaluated_at=170)
    with pytest.raises(RootTrustError):
        RootTrustStore([approved]).verify_historical(signed, evaluated_at=150, verified_at=149)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"registry_address": "0x" + "00" * 20}, "Root audience must be nonzero"),
        ({"expires_at": 100}, "validity interval"),
        ({"expires_at": 86501}, "validity interval"),
        ({"revision": 2}, "preceding snapshot digest"),
        ({"previous_digest": "ab" * 32}, "preceding snapshot digest"),
        ({"kind": "issuance-root"}, "canonical issuer identity"),
        ({"kind": "issuance-root", "issuer_did": "issuer.example"}, "canonical issuer identity"),
        ({"issuer_did": "did:web:issuer.example"}, "Only issuance roots"),
    ],
)
def test_root_snapshot_rejects_incoherent_scope_and_validity(approval, changes, message):
    with pytest.raises(ValueError, match=message):
        RootSnapshot.model_validate({**approval[2].snapshot.model_dump(), **changes})


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"not_before": 500}, "Invalid root authority interval"),
        ({"kinds": ("issuer-root", "issuer-root")}, "duplicate scope"),
        ({"issuer_dids": ("did:web:issuer.example", "did:web:issuer.example")}, "Duplicate issuer scope"),
        ({"issuer_dids": ("issuer.example",)}, "Noncanonical issuer scope"),
    ],
)
def test_root_authority_rejects_ambiguous_configuration(approval, changes, message):
    with pytest.raises(ValueError, match=message):
        RootAuthority.model_validate({**approval[1].model_dump(), **changes})


@pytest.mark.parametrize("count", [0, 257])
def test_root_authority_inventory_is_bounded(approval, count):
    with pytest.raises(ValueError, match="Configure 1–256 root authorities"):
        RootTrustStore([approval[1]] * count)


def test_root_scope_identity_survives_revision_but_separates_deployments(approval):
    from src.protocol.root_snapshot import root_scope_id

    snapshot = approval[2].snapshot
    revised = RootSnapshot.model_validate(
        {
            **snapshot.model_dump(),
            "revision": 2,
            "previous_digest": snapshot.digest,
            "root": "124",
        }
    )
    assert revised.digest != snapshot.digest
    assert root_scope_id(revised) == root_scope_id(snapshot)
    other = RootSnapshot.model_validate({**snapshot.model_dump(), "chain_id": 1})
    assert root_scope_id(other) != root_scope_id(snapshot)
