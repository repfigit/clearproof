"""Credential preimage and real Circom witness checks (no proving-key ceremony)."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.protocol.credential import PilotCredential, holder_commitment
from src.registry.pilot_tree import PilotTree
from src.registry.poseidon import BN254_SCALAR_FIELD, poseidon_hash

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def credential():
    return PilotCredential(
        tenant_id="tenant-a",
        credential_nonce="a" * 64,
        issuer_did="did:web:issuer.example",
        subject_wallet="0x" + "1" * 40,
        holder_commitment=holder_commitment("123456"),
        jurisdiction="US",
        kyc_tier=2,
        sanctions_clear=True,
        issued_at=100,
        expires_at=200,
    )


def path(leaf):
    root = str(poseidon_hash([leaf, 0]))
    return str(poseidon_hash([root, poseidon_hash([0, 0])]))


@pytest.fixture
def witness(credential):
    issuance_tree = PilotTree([(credential.credential_nonce, credential.commitment)], depth=2)
    issuance = issuance_tree.root
    issuer_tree = PilotTree([("issuer", credential.authorized_issuer_leaf(issuance))], depth=2)
    authorized = issuer_tree.root
    issuance_path = issuance_tree.membership(credential.credential_nonce)
    issuer_path = issuer_tree.membership("issuer")
    return credential.witness(
        secret="123456",
        evaluated_at=150,
        issuance_root=issuance,
        authorized_issuer_root=authorized,
        issuance_siblings=issuance_path["siblings"],
        issuance_indices=issuance_path["indices"],
        issuer_siblings=issuer_path["siblings"],
        issuer_indices=issuer_path["indices"],
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-b"),
        ("credential_nonce", "b" * 64),
        ("issuer_did", "did:web:other.example"),
        ("subject_wallet", "0x" + "2" * 40),
        ("holder_commitment", holder_commitment("654321")),
        ("jurisdiction", "GB"),
        ("kyc_tier", 3),
        ("sanctions_clear", False),
        ("issued_at", 101),
        ("expires_at", 201),
    ],
)
def test_every_credential_fact_is_committed(credential, field, value):
    changed = PilotCredential.model_validate({**credential.model_dump(), field: value})
    assert changed.commitment != credential.commitment


@pytest.mark.parametrize("secret", ["0", "01", "-1", str(BN254_SCALAR_FIELD), "1\n", "١"])
def test_secret_encoding_fails_closed(secret):
    with pytest.raises(ValueError):
        holder_commitment(secret)


def test_model_rejects_invalid_or_private_error_rendering(credential):
    for change in [
        {"kyc_tier": True},
        {"holder_commitment": str(BN254_SCALAR_FIELD)},
        {"credential_nonce": "0" * 64},
        {"subject_wallet": "0x" + "0" * 40},
        {"expires_at": 100},
        {"jurisdiction": "us"},
    ]:
        with pytest.raises(ValidationError) as err:
            PilotCredential.model_validate({**credential.model_dump(), **change})
        assert credential.subject_wallet not in str(err.value)
    assert credential.subject_wallet not in repr(credential)


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    if not shutil.which("circom") or not shutil.which("node"):
        pytest.skip("requires circom and node for real witness checks")
    output = tmp_path_factory.mktemp("pilot-credential-circuit")
    source = output / "credential_test.circom"
    source.write_text(
        'pragma circom 2.1.6;\ninclude "circuits/pilot_credential.circom";\n'
        "component main {public [credential_commitment, authorized_issuer_root, expected_tenant, "
        "expected_subject, expected_jurisdiction, evaluated_at]} = PilotCredentialValidity(2, 2);\n"
    )
    result = subprocess.run(
        ["circom", str(source), "--wasm", "--r1cs", "-l", str(ROOT), "-o", str(output)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return output


def calculate(compiled, tmp_path, data):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(data))
    js = compiled / "credential_test_js"
    return subprocess.run(
        [
            "node",
            str(js / "generate_witness.js"),
            str(js / "credential_test.wasm"),
            str(source),
            str(tmp_path / "witness.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )


def test_real_valid_witness(compiled, tmp_path, witness):
    result = calculate(compiled, tmp_path, witness)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize(
    "attack",
    [
        "holder",
        "subject",
        "jurisdiction",
        "tenant",
        "future",
        "expired",
        "unissued",
        "unauthorized-issuer",
        "path-bit",
        "screening",
        "tier",
    ],
)
def test_real_adversarial_witness(compiled, tmp_path, witness, attack):
    data = copy.deepcopy(witness)
    if attack == "holder":
        data["holder_secret"] = "654321"
    elif attack in ("subject", "jurisdiction", "screening", "tier"):
        idx = {"subject": 6, "jurisdiction": 8, "screening": 12, "tier": 9}[attack]
        data["fields"][idx] = "0" if attack in ("tier", "screening") else str(int(data["fields"][idx]) + 1)
        # Recompute the credential and issuance root to emulate forged issuance.
        data["credential_commitment"] = str(poseidon_hash([102, *data["fields"]]))
        data["issuance_root"] = path(data["credential_commitment"])
        # An authenticated root containing a changed credential still cannot
        # satisfy the original expected subject/jurisdiction or invalid checks.
        issuer_leaf = str(poseidon_hash([103, *data["fields"][:2], data["issuance_root"]]))
        data["authorized_issuer_root"] = path(issuer_leaf)
    elif attack == "tenant":
        data["expected_tenant"][0] = str(int(data["expected_tenant"][0]) + 1)
    elif attack == "future":
        data["evaluated_at"] = "99"
    elif attack == "expired":
        data["evaluated_at"] = "200"
    elif attack == "unissued":
        data["fields"][4] = str(int(data["fields"][4]) + 1)
        data["credential_commitment"] = str(poseidon_hash([102, *data["fields"]]))
        data["issuance_root"] = path(data["credential_commitment"])
    elif attack == "unauthorized-issuer":
        data["fields"][0] = str(int(data["fields"][0]) + 1)
        data["credential_commitment"] = str(poseidon_hash([102, *data["fields"]]))
        data["issuance_root"] = path(data["credential_commitment"])
    elif attack == "path-bit":
        data["issuance_indices"][0] = 2
    result = calculate(compiled, tmp_path, data)
    assert result.returncode != 0
    assert b"Assert Failed" in result.stderr


def test_credential_issuer_requires_canonical_did(credential):
    with pytest.raises(ValueError, match="Issuer requires canonical did:web identity"):
        PilotCredential.model_validate({**credential.model_dump(), "issuer_did": "issuer.example"})


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"sanctions_clear": False}, "screening or holder binding failed"),
    ],
)
def test_screening_failure_prevents_witness(credential, changes, message):
    changed = PilotCredential.model_validate({**credential.model_dump(), **changes})
    with pytest.raises(ValueError, match=message):
        changed.witness(**witness_args())


def witness_args():
    # Synthetic roots test input validation only, not membership authenticity.
    return dict(
        secret="123456",
        evaluated_at=150,
        issuance_root="1",
        authorized_issuer_root="2",
        issuance_siblings=["0"],
        issuance_indices=[0],
        issuer_siblings=["0"],
        issuer_indices=[0],
    )


@pytest.mark.parametrize("side", ["issuance", "issuer"])
@pytest.mark.parametrize(
    "siblings,indices,message",
    [
        ((), [0], "Invalid membership path"),
        (["0"], (), "Invalid membership path"),
        ([], [], "Invalid membership path"),
        (["0"] * 33, [0] * 33, "Invalid membership path"),
        (["0"], [], "Invalid membership direction"),
        (["0"], [True], "Invalid membership direction"),
        (["0"], [2], "Invalid membership direction"),
        (["0"], [0.0], "Invalid membership direction"),
    ],
)
def test_credential_membership_paths_require_bounded_canonical_inputs(credential, side, siblings, indices, message):
    args = {**witness_args(), f"{side}_siblings": siblings, f"{side}_indices": indices}
    with pytest.raises(ValueError, match=message):
        credential.witness(**args)


@pytest.mark.parametrize("evaluated_at", [99, 200, True, 150.0])
def test_credential_witness_requires_current_integer_time(credential, evaluated_at):
    with pytest.raises(ValueError, match="Credential is outside its validity interval"):
        credential.witness(**{**witness_args(), "evaluated_at": evaluated_at})


def test_wrong_holder_secret_cannot_build_witness(credential):
    with pytest.raises(ValueError, match="Credential screening or holder binding failed"):
        credential.witness(**{**witness_args(), "secret": "654321"})
