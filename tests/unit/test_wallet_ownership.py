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


@pytest.mark.parametrize("changes", [{"nonce": "00" * 32}, {"registry_address": "0x" + "00" * 20}])
def test_challenge_rejects_zero_nonce_and_registry(challenge, changes):
    with pytest.raises(ValueError, match="Wallet challenge requires a nonzero nonce and registry"):
        WalletChallenge.model_validate({**challenge[0].model_dump(), **changes})


@pytest.mark.parametrize("boundary", ["before", "expiry"])
def test_challenge_requires_current_credential_at_issuance(challenge, boundary):
    value = challenge[0]
    timestamp = value.credential.issued_at - 1 if boundary == "before" else value.credential.expires_at
    with pytest.raises(ValueError, match="Credential is not current at challenge issuance"):
        WalletChallenge.model_validate({**value.model_dump(), "timestamp": timestamp, "expires_at": timestamp + 300})


@pytest.mark.parametrize(
    "change,message",
    [
        ({"issued_at": 1099, "expires_at": 87499}, "outside the challenge validity interval"),
        ({"issued_at": 1400, "expires_at": 87800}, "outside the challenge validity interval"),
        ({"expires_at": 87601}, "24-hour TTL"),
        ({"attestation_id": "ef" * 32}, "identifier must bind the consumed challenge"),
    ],
)
def test_attestation_requires_challenge_identity_and_exact_ttl(challenge, change, message):
    value, signature = challenge
    fields = dict(attestation_id=value.nonce, challenge=value, signature=signature, issued_at=1200, expires_at=87600)
    with pytest.raises(ValueError, match=message):
        WalletAttestation.model_validate({**fields, **change})


@pytest.mark.parametrize("offset", [0, -1])
def test_extension_requires_positive_validity(extension, offset):
    with pytest.raises(ValueError, match="Extension requires a positive validity interval"):
        WalletCredentialExtension.model_validate({**extension.model_dump(), "expires_at": extension.issued_at + offset})


# ---------------------------------------------------------------------------
# SIWE (ERC-4361) profile — clearproof-wallet-challenge-v2 / -attestation-v2
# ---------------------------------------------------------------------------


@pytest.fixture
def challenge_v2(wallet_enrollment):
    from src.protocol.wallet_ownership import WalletChallengeV2

    wallet, consent, principal = wallet_enrollment
    value = WalletChallengeV2(
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        credential=consent.credential,
        chain_id=consent.chain_id,
        registry_address=consent.registry_address,
        nonce="cd" * 32,
        timestamp=1100,
        expires_at=1400,
        siwe_domain="clearproof.example",
        siwe_resource=f"urn:clearproof:credential:{consent.credential.credential_nonce}",
    )
    signature = "0x" + wallet.sign_message(encode_defunct(text=value.message())).signature.hex()
    return value, signature


def test_shared_sdk_signing_vector_v2():
    from src.protocol.wallet_ownership import WalletChallengeV2

    vector = json.loads((ROOT / "tests/vectors/wallet-ownership/challenge-v2.json").read_text())
    challenge = WalletChallengeV2.model_validate(vector["challenge"])
    assert challenge.message() == vector["message"]
    # The signed text must be a well-formed EIP-4361 message with the exact
    # challenge bindings (the reference SIWE parser is the check).
    from siwe import SiweMessage

    parsed = SiweMessage.from_message(vector["message"])
    assert parsed.nonce == challenge.nonce
    assert parsed.domain == challenge.siwe_domain
    assert int(parsed.chain_id) == challenge.chain_id
    assert parsed.address.lower() == challenge.credential.subject_wallet.lower()


def test_v2_signature_binds_exact_context(challenge_v2):
    from src.protocol.wallet_ownership import WalletChallengeV2

    value, signature = challenge_v2
    value.verify_signature(signature)
    # The SIWE message binds exactly what it renders: domain, subject address,
    # chain-id, nonce, issued-at/expiration-time and the credential resource.
    # The actor binding is enforced by the service's tenant context check, not
    # by the wallet signature (same as the server-side owner check in v1).
    for field, changed in [
        ("siwe_domain", "other.example"),
        ("siwe_resource", "urn:clearproof:credential:" + "ff" * 32),
        ("nonce", "ef" * 32),
        ("chain_id", 1),
    ]:
        candidate = WalletChallengeV2.model_validate({**value.model_dump(), field: changed})
        with pytest.raises(WalletOwnershipError):
            candidate.verify_signature(signature)
    # Timestamps move together (TTL is exact), shifting both SIWE time fields.
    shifted = WalletChallengeV2.model_validate({**value.model_dump(), "timestamp": 1101, "expires_at": 1401})
    with pytest.raises(WalletOwnershipError):
        shifted.verify_signature(signature)
    other = WalletChallengeV2.model_validate(
        {
            **value.model_dump(),
            "credential": {**value.model_dump()["credential"], "subject_wallet": "0x" + "9" * 40},
        }
    )
    with pytest.raises(WalletOwnershipError):
        other.verify_signature(signature)
    wrong = "0x" + Account.create().sign_message(encode_defunct(text=value.message())).signature.hex()
    with pytest.raises(WalletOwnershipError):
        value.verify_signature(wrong)


def test_siwe_message_and_iso_helpers_reject_invalid_input():
    from src.protocol import wallet_ownership as module

    with pytest.raises(ValueError, match="Invalid SIWE timestamp"):
        module._iso(-1)
    with pytest.raises(ValueError, match="Invalid SIWE domain"):
        module.siwe_message(
            domain="bad\nexample.com",
            address="0x" + "1" * 40,
            chain_id=1,
            nonce="n" * 64,
            issued_at=1,
            expiration_time=2,
            resource="urn:clearproof:credential:ab",
        )


def test_v2_challenge_and_attestation_validator_branches(wallet_enrollment):
    from src.protocol.wallet_ownership import WalletAttestationV2, WalletChallengeV2

    wallet, consent, principal = wallet_enrollment
    base = {
        "tenant_id": principal.tenant_id,
        "actor_id": principal.actor_id,
        "credential": consent.credential,
        "chain_id": consent.chain_id,
        "registry_address": consent.registry_address,
        "nonce": "cd" * 32,
        "timestamp": 1100,
        "expires_at": 1400,
        "siwe_domain": "issuer.example",
        "siwe_resource": f"urn:clearproof:credential:{consent.credential.credential_nonce}",
    }
    with pytest.raises(ValueError):
        WalletChallengeV2.model_validate({**base, "expires_at": 1500})
    with pytest.raises(ValueError):
        WalletChallengeV2.model_validate({**base, "nonce": "0" * 64})
    with pytest.raises(ValueError):
        WalletChallengeV2.model_validate({**base, "timestamp": consent.credential.expires_at})
    challenge = WalletChallengeV2.model_validate(base)
    attestation = WalletAttestationV2(
        attestation_id=challenge.nonce,
        challenge=challenge,
        signature="0x" + "45" * 65,
        issued_at=1200,
        expires_at=87600,
        delegation={"checked": True, "delegated": False, "delegate": None, "checked_at": 1200, "reason": None},
    )
    assert attestation.digest_scalar.isdigit()
    with pytest.raises(ValueError):
        WalletAttestationV2.model_validate({**attestation.model_dump(), "attestation_id": "ef" * 32})
    with pytest.raises(ValueError):
        WalletAttestationV2.model_validate(
            {**attestation.model_dump(), "method": "erc-1271", "signature": "0x" + "45" * 65}
        )


def test_v2_signature_rejects_malleated_and_misformed(challenge_v2):
    from src.protocol.wallet_ownership import WalletChallengeV2

    value, signature = challenge_v2
    raw = bytes.fromhex(signature[2:])
    high = SECP256K1_N - int.from_bytes(raw[32:64], "big")
    malleated = "0x" + (raw[:32] + high.to_bytes(32, "big") + bytes([55 - raw[64]])).hex()
    for invalid in [malleated, signature.upper(), "0x" + "00" * 65]:
        with pytest.raises(WalletOwnershipError):
            value.verify_signature(invalid)
    with pytest.raises(ValueError, match="Invalid SIWE domain"):
        WalletChallengeV2.model_validate({**value.model_dump(), "siwe_domain": "bad\nexample"})


def test_v2_attestation_binds_challenge_delegation_and_ttl(challenge_v2):
    from src.protocol.wallet_ownership import WalletAttestationV2

    value, signature = challenge_v2
    delegation = {"checked": True, "delegated": False, "delegate": None, "checked_at": 1150, "reason": None}
    attestation = WalletAttestationV2(
        attestation_id=value.nonce,
        challenge=value,
        signature=signature,
        issued_at=1200,
        expires_at=87600,
        delegation=delegation,
    )
    assert attestation.challenge == value
    unknown = {"checked": True, "extra": "x"}
    with pytest.raises(ValueError, match="Invalid delegation status record"):
        WalletAttestationV2.model_validate({**attestation.model_dump(), "delegation": unknown})
    missing_checked = {**delegation, "checked": "yes"}
    with pytest.raises(ValueError, match="Invalid delegation status record"):
        WalletAttestationV2.model_validate({**attestation.model_dump(), "delegation": missing_checked})
    with pytest.raises(ValueError, match="24-hour TTL"):
        WalletAttestationV2.model_validate({**attestation.model_dump(), "expires_at": 87601})
    with pytest.raises(ValueError, match="65-byte EOA signature"):
        WalletAttestationV2.model_validate({**attestation.model_dump(), "method": "erc-1271"})


def test_load_helpers_round_trip_both_versions(challenge, challenge_v2):
    from src.protocol.wallet_ownership import load_attestation, load_challenge

    challenge_v1, signature_v1 = challenge
    challenge2, signature_v2 = challenge_v2
    stored_v1 = challenge_v1.model_dump(mode="json")
    stored_v2 = challenge2.model_dump(mode="json")
    assert isinstance(load_challenge(stored_v1), WalletChallenge)
    assert isinstance(load_challenge(stored_v2), type(challenge2))
    attestation_v1 = WalletAttestation(
        attestation_id=stored_v1["nonce"],
        challenge=challenge_v1,
        signature=signature_v1,
        issued_at=1200,
        expires_at=87600,
    )
    from src.protocol.wallet_ownership import WalletAttestationV2

    attestation_v2 = WalletAttestationV2(
        attestation_id=stored_v2["nonce"],
        challenge=challenge2,
        signature=signature_v2,
        issued_at=1200,
        expires_at=87600,
        delegation={
            "checked": False,
            "delegated": None,
            "delegate": None,
            "checked_at": 1200,
            "reason": "unconfigured",
        },
    )
    assert isinstance(load_attestation(attestation_v1.model_dump(mode="json")), WalletAttestation)
    assert isinstance(load_attestation(attestation_v2.model_dump(mode="json")), type(attestation_v2))
