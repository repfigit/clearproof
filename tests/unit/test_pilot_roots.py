"""Real signatures with independent current pins and evaluation/current clocks."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.protocol.root_snapshot import RootAuthority, RootSnapshot, RootTrustError, RootTrustStore, sign_root
from src.protocol.transfer import VerificationContext
from src.prover.pilot_roots import CurrentRootPins, verify_pilot_roots


@pytest.fixture
def root_case():
    key = Ed25519PrivateKey.generate()
    authority = RootAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id="tenant-a",
        chain_id=1,
        registry_address="0x" + "12" * 20,
        kinds=("issuance-root", "issuer-root", "sanctions-root"),
        issuer_dids=("did:web:issuer.example", "did:web:other.example"),
        not_before=0,
        not_after=1000,
    )
    roots = [
        sign_root(
            RootSnapshot(
                tenant_id=authority.tenant_id,
                chain_id=authority.chain_id,
                registry_address=authority.registry_address,
                kind=kind,
                issuer_did="did:web:issuer.example" if kind == "issuance-root" else None,
                root=str(100 + i),
                tree_depth=8,
                source_digest="ab" * 32,
                revision=1,
                issued_at=100,
                expires_at=300,
                key_id=authority.key_id,
            ),
            key,
        )
        for i, kind in enumerate(authority.kinds)
    ]
    pins = CurrentRootPins(
        tenant_id=authority.tenant_id,
        chain_id=1,
        registry_address=authority.registry_address,
        issuer_did="did:web:issuer.example",
        issuance_digest=roots[0].snapshot.digest,
        issuer_digest=roots[1].snapshot.digest,
        sanctions_digest=roots[2].snapshot.digest,
    )
    fixture = json.loads((Path(__file__).resolve().parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    context = VerificationContext.model_validate(
        {
            **fixture["records"][1]["value"],
            "tenant_id": pins.tenant_id,
            "deployment_chain_id": "1",
            "deployment_address": pins.registry_address,
            "proof_profile": "pilot-transfer-v2",
            "evaluated_at": 150,
            "issuance_snapshot_digest": pins.issuance_digest,
            "issuer_snapshot_digest": pins.issuer_digest,
            "sanctions_snapshot_digest": pins.sanctions_digest,
        }
    )
    return key, dict(
        trust=RootTrustStore([authority]),
        pins=pins,
        context=context,
        issuance=roots[0],
        issuers=roots[1],
        sanctions=roots[2],
        now=200,
    )


def test_current_roots_require_all_three_scoped_signatures(root_case):
    _, args = root_case
    result = verify_pilot_roots(**args)
    assert (result.issuance.root, result.issuers.root, result.sanctions.root) == ("100", "101", "102")
    assert result.checked_at == 200


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-b"),
        ("deployment_address", "0x" + "34" * 20),
        ("deployment_chain_id", "2"),
        ("proof_profile", "legacy-v1"),
        ("proof_profile", "pilot-transfer-v1"),
        ("evaluated_at", 99),
        ("evaluated_at", 201),
        ("issuance_snapshot_digest", "00" * 32),
        ("issuer_snapshot_digest", "00" * 32),
        ("sanctions_snapshot_digest", "00" * 32),
    ],
)
def test_context_cannot_select_its_own_roots_or_time(root_case, field, value):
    _, args = root_case
    args["context"] = VerificationContext.model_validate({**args["context"].model_dump(), field: value})
    with pytest.raises(RootTrustError):
        verify_pilot_roots(**args)


@pytest.mark.parametrize("now", [True, 149, 300])
def test_current_clock_must_fit_approval(root_case, now):
    _, args = root_case
    with pytest.raises(RootTrustError):
        verify_pilot_roots(**{**args, "now": now})


@pytest.mark.parametrize("changes", [{"tree_depth": 9}, {"issuer_did": "did:web:other.example"}])
def test_even_pinned_valid_signature_must_match_expected_issuer_and_profile(root_case, changes):
    key, args = root_case
    replacement = sign_root(RootSnapshot.model_validate({**args["issuance"].snapshot.model_dump(), **changes}), key)
    args["issuance"] = replacement
    args["pins"] = CurrentRootPins.model_validate(
        {**args["pins"].model_dump(), "issuance_digest": replacement.snapshot.digest}
    )
    args["context"] = VerificationContext.model_validate(
        {**args["context"].model_dump(), "issuance_snapshot_digest": replacement.snapshot.digest}
    )
    with pytest.raises(RootTrustError, match="tree or credential issuer"):
        verify_pilot_roots(**args)


def test_old_approval_cannot_override_new_current_pin(root_case):
    _, args = root_case
    args["pins"] = CurrentRootPins.model_validate({**args["pins"].model_dump(), "issuer_digest": "ef" * 32})
    args["context"] = VerificationContext.model_validate(
        {**args["context"].model_dump(), "issuer_snapshot_digest": "ef" * 32}
    )
    with pytest.raises(RootTrustError, match="trusted current context"):
        verify_pilot_roots(**args)


def test_current_root_pins_reject_zero_registry_before_verification(root_case):
    _, args = root_case
    original = args["pins"].model_dump()
    with pytest.raises(ValueError, match="Invalid current root scope"):
        CurrentRootPins.model_validate({**original, "registry_address": "0x" + "00" * 20})
    assert CurrentRootPins.model_validate(original) == args["pins"]
    assert verify_pilot_roots(**args).checked_at == args["now"]
