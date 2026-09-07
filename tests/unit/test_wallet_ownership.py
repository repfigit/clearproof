"""Real EOA signatures and real staged extension witnesses; no trusted setup."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from src.protocol.wallet_ownership import (
    SECP256K1_N,
    WalletAttestation,
    WalletChallenge,
    WalletCredentialExtension,
    WalletOwnershipError,
)
from src.registry.poseidon import poseidon_hash

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def challenge(wallet_enrollment):
    wallet, consent, principal = wallet_enrollment
    value = WalletChallenge(
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        credential=consent.credential,
        chain_id=consent.chain_id,
        registry_address=consent.registry_address,
        nonce="cd" * 32,
        timestamp=1100,
        expires_at=1400,
    )
    signature = "0x" + wallet.sign_message(encode_defunct(text=value.message())).signature.hex()
    return value, signature


def test_signature_binds_exact_context(challenge):
    value, signature = challenge
    value.verify_signature(signature)
    for field, changed in [
        ("actor_id", "other"),
        ("chain_id", 1),
        ("registry_address", "0x" + "2" * 40),
        ("nonce", "ef" * 32),
    ]:
        candidate = WalletChallenge.model_validate({**value.model_dump(), field: changed})
        with pytest.raises(WalletOwnershipError):
            candidate.verify_signature(signature)
    changed = value.model_dump()
    changed["credential"]["credential_nonce"] = "ff" * 32
    with pytest.raises(WalletOwnershipError):
        WalletChallenge.model_validate(changed).verify_signature(signature)


def test_wrong_signer_malleability_and_private_representations(challenge):
    value, signature = challenge
    raw = bytes.fromhex(signature[2:])
    high = SECP256K1_N - int.from_bytes(raw[32:64], "big")
    malleated = "0x" + (raw[:32] + high.to_bytes(32, "big") + bytes([55 - raw[64]])).hex()
    wrong = "0x" + Account.create().sign_message(encode_defunct(text=value.message())).signature.hex()
    for invalid in [wrong, malleated, signature.upper(), "0x" + "00" * 65, signature[:-2] + "00"]:
        with pytest.raises(WalletOwnershipError):
            value.verify_signature(invalid)
    assert value.credential.subject_wallet not in repr(value)
    with pytest.raises(ValueError):
        WalletChallenge.model_validate({**value.model_dump(), "expires_at": 1401})


@pytest.fixture
def extension(challenge):
    value, signature = challenge
    attestation = WalletAttestation(
        attestation_id=value.nonce, challenge=value, signature=signature, issued_at=1200, expires_at=87600
    )
    return WalletCredentialExtension(
        credential_commitment=value.credential.commitment,
        attestation_digest=attestation.digest_scalar,
        issued_at=1200,
        expires_at=87600,
        wallet_ownership_verified=True,
    )


def test_versioned_commitment_flag_index_five_and_liveness(extension, challenge):
    original = challenge[0].credential.commitment
    assert len(extension.fields()) == 6 and extension.fields()[5] == 1
    changed = WalletCredentialExtension.model_validate({**extension.model_dump(), "wallet_ownership_verified": False})
    assert changed.commitment != extension.commitment
    assert challenge[0].credential.commitment == original
    with pytest.raises(WalletOwnershipError):
        changed.witness(evaluated_at=1300)
    for now in [1199, 87600, True]:
        with pytest.raises(WalletOwnershipError):
            extension.witness(evaluated_at=now)
    extension.witness(evaluated_at=1200)


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    if not shutil.which("circom") or not shutil.which("node"):
        pytest.skip("requires circom and node; dedicated CI job installs both")
    output = tmp_path_factory.mktemp("wallet-extension")
    result = subprocess.run(
        ["circom", str(ROOT / "circuits/wallet_ownership_credential.circom"), "--wasm", "--r1cs", "-o", str(output)],
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode()
    return output / "wallet_ownership_credential_js"


@pytest.mark.parametrize(
    "attack",
    [
        "valid",
        "flag-zero",
        "flag-two",
        "credential",
        "attestation",
        "domain",
        "future",
        "expired",
        "range",
        "commitment",
    ],
)
def test_real_extension_witness(compiled, tmp_path, extension, attack):
    data = copy.deepcopy(extension.witness(evaluated_at=1300))
    if attack in ("flag-zero", "flag-two", "domain", "range"):
        index, value = {"flag-zero": (5, "0"), "flag-two": (5, "2"), "domain": (0, "102"), "range": (4, str(2**53))}[
            attack
        ]
        data["fields"][index] = value
        data["extension_commitment"] = str(poseidon_hash(data["fields"]))
    elif attack in ("credential", "attestation"):
        key = "expected_credential_commitment" if attack == "credential" else "expected_attestation_digest"
        data[key] = str(int(data[key]) + 1)
    elif attack == "future":
        data["evaluated_at"] = "1199"
    elif attack == "expired":
        data["evaluated_at"] = "87600"
    elif attack == "commitment":
        data["extension_commitment"] = str(int(data["extension_commitment"]) + 1)
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(data))
    result = subprocess.run(
        [
            "node",
            str(compiled / "generate_witness.js"),
            str(compiled / "wallet_ownership_credential.wasm"),
            str(input_file),
            str(tmp_path / "witness.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )
    if attack == "valid":
        assert result.returncode == 0, result.stderr.decode()
    else:
        assert result.returncode != 0 and b"Assert Failed" in result.stderr


def test_shared_sdk_signing_vector():
    vector = json.loads((ROOT / "tests/vectors/wallet-ownership/challenge.json").read_text())
    assert WalletChallenge.model_validate(vector["challenge"]).message() == vector["message"]
