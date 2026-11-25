"""Tests for the frozen pre-audit circuit profile manifest, fail-closed validator, and AIF-67 BLS12-381 witness."""

from __future__ import annotations

import copy
import json
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.prover import preaudit_profile as mod
from src.prover.preaudit_profile import (
    PREAUDIT_MANIFEST_PATH,
    WALLET_OWNERSHIP_PUBLIC_SIGNALS,
    PreauditCircuitProfile,
    ProfileValidationError,
    validate_preaudit_profile,
)
from src.registry.poseidon import BLS12_381_SCALAR_FIELD, poseidon_hash_bls12381

ROOT = Path(__file__).resolve().parents[2]


def _copy_profile_tree(dst: Path) -> tuple[Path, dict]:
    """Copy the manifest and every file it pins into an isolated tmp directory."""
    raw = (ROOT / PREAUDIT_MANIFEST_PATH).read_text()
    data = json.loads(raw)
    manifest_dst = dst / PREAUDIT_MANIFEST_PATH
    manifest_dst.parent.mkdir(parents=True, exist_ok=True)
    manifest_dst.write_text(raw)

    paths: list[str] = [data["pilot_signals_source"]["path"]]
    for curve in data["curves"].values():
        paths.append(curve["poseidon_constants_json"]["path"])
        if curve["poseidon_circom_constants"] is not None:
            paths.append(curve["poseidon_circom_constants"]["path"])
    for circuit in data["circuits"]:
        for entry in circuit["source_files"]:
            paths.append(entry["path"])

    for rel in set(paths):
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    return dst, data


def test_committed_preaudit_profile_validates_and_locks_pilot_and_wallet_schemas():
    profile = validate_preaudit_profile(ROOT)
    assert profile.assurance == "preaudit-frozen-no-ceremony"
    assert profile.schema_version == "clearproof-preaudit-circuit-profile-v1"
    by_id = {c.circuit_id: c for c in profile.circuits}
    assert set(by_id) == {
        "pilot-transfer-v3-bn254",
        "wallet-ownership-v1-bn254",
        "wallet-ownership-v1-bls12381",
    }
    pilot = by_id["pilot-transfer-v3-bn254"]
    assert pilot.tree_depths == {"issuance": 32, "issuer": 20, "sanctions": 20}
    assert len(pilot.public_signals) == 8
    for cid in ("wallet-ownership-v1-bn254", "wallet-ownership-v1-bls12381"):
        assert tuple(s.name for s in by_id[cid].public_signals) == WALLET_OWNERSHIP_PUBLIC_SIGNALS
    # Trusted-digest pin passes with the exact digest and rejects any other pin.
    assert validate_preaudit_profile(ROOT, trusted_digest=profile.digest) == profile
    with pytest.raises(ProfileValidationError, match="untrusted_manifest_digest"):
        validate_preaudit_profile(ROOT, trusted_digest="00" * 32)
    with pytest.raises(ProfileValidationError, match="invalid_trust_pin"):
        validate_preaudit_profile(ROOT, trusted_digest="not-hex")


def test_validator_fails_closed_on_source_poseidon_and_r1cs_drift(tmp_path):
    tree, data = _copy_profile_tree(tmp_path / "tree")
    assert validate_preaudit_profile(tree).profile_id == data["profile_id"]

    # Size drift on pilot signals source
    sig = tree / data["pilot_signals_source"]["path"]
    original = sig.read_bytes()
    sig.write_bytes(original + b" ")
    with pytest.raises(ProfileValidationError, match="size_drift:specs/pilot-signals-v3.json"):
        validate_preaudit_profile(tree)

    # Same-size hash drift on BLS12-381 Poseidon constants
    sig.write_bytes(original)
    bls_json = tree / data["curves"]["bls12-381"]["poseidon_constants_json"]["path"]
    bls_bytes = bls_json.read_bytes()
    bls_json.write_bytes(bytes([bls_bytes[0] ^ 1]) + bls_bytes[1:])
    with pytest.raises(ProfileValidationError, match="hash_drift:src/registry/poseidon_constants_bls12381.json"):
        validate_preaudit_profile(tree)
    bls_json.write_bytes(bls_bytes)

    # Missing file or symlink rejected
    wallet_src = tree / "circuits/wallet_ownership_credential.circom"
    wallet_bytes = wallet_src.read_bytes()
    wallet_src.unlink()
    with pytest.raises(ProfileValidationError, match="missing_or_invalid_file:wallet_ownership_credential.circom"):
        validate_preaudit_profile(tree)
    wallet_src.symlink_to(tree / "circuits/pilot_compliance.circom")
    with pytest.raises(ProfileValidationError, match="missing_or_invalid_file:wallet_ownership_credential.circom"):
        validate_preaudit_profile(tree)
    wallet_src.unlink()
    wallet_src.write_bytes(wallet_bytes)

    # R1CS directory verification fails closed when compiled R1CS drifts
    r1cs_dir = tmp_path / "r1cs"
    r1cs_dir.mkdir()
    for circuit in data["circuits"]:
        stem = Path(circuit["entry_circuit"]).stem
        (r1cs_dir / f"{stem}.r1cs").write_bytes(b"not-matching-r1cs")
    with pytest.raises(ProfileValidationError, match="r1cs_hash_drift:pilot-transfer-v3-bn254"):
        validate_preaudit_profile(tree, r1cs_dir=r1cs_dir)


def test_validator_rejects_malformed_json_symlinks_and_path_escape(tmp_path):
    with pytest.raises(ProfileValidationError, match="manifest_unavailable"):
        validate_preaudit_profile(tmp_path)

    manifest = tmp_path / PREAUDIT_MANIFEST_PATH
    manifest.parent.mkdir(parents=True)
    for payload, expected in [
        (b"{bad", "invalid_json"),
        (b"\xff", "invalid_json"),
        (b"[]", "manifest_must_be_object"),
        (b'{"a":1,"a":2}', "duplicate_json_key"),
        (b'{"a":NaN}', "invalid_json_constant"),
    ]:
        manifest.write_bytes(payload)
        with pytest.raises(ProfileValidationError, match=f"^{expected}$"):
            validate_preaudit_profile(tmp_path)

    # Symlink manifest rejected
    target = tmp_path / "real.json"
    target.write_text("{}")
    manifest.unlink()
    manifest.symlink_to(target)
    with pytest.raises(ProfileValidationError, match="manifest_unavailable"):
        validate_preaudit_profile(tmp_path)

    # Structurally valid JSON that fails Pydantic schema validation
    manifest.unlink()
    manifest.write_text('{"schema_version": "wrong"}')
    with pytest.raises(ProfileValidationError, match="^invalid_manifest:"):
        validate_preaudit_profile(tmp_path)

    # _check_pinned_file rejects path traversal even if bypassing Pydantic
    fake = mod.PinnedFile.model_construct(path="../outside.txt", sha256="00" * 32, size=1)
    with pytest.raises(ProfileValidationError, match="path_escape"):
        mod._check_pinned_file(tmp_path, fake)


@pytest.mark.parametrize(
    "mutator,expected_fragment",
    [
        (lambda d: d["pilot_signals_source"].update(path="../escape.json"), "Unsafe relative path"),
        (lambda d: d["curves"]["bn254"].update(circom_prime="bls12381"), "Curve / circom prime mismatch"),
        (lambda d: d["curves"]["bn254"].update(scalar_field_bits=255), "Curve / scalar field bit-width mismatch"),
        (lambda d: d["curves"]["bn254"].update(scalar_field_order="12345"), "Curve / scalar field order mismatch"),
        (lambda d: d["curves"]["bn254"].update(poseidon_partial_rounds=[56]), "must cover t=2..17"),
        (
            lambda d: d["curves"]["bls12-381"].update(poseidon_circom_constants=None),
            "requires curve-correct Circom Poseidon constants",
        ),
        (lambda d: d["circuits"][0]["public_signals"][0].update(name="BAD"), "Invalid public signal name"),
        (lambda d: d["circuits"][0].update(entry_circuit="circuits/not_circom.txt"), "Invalid entry circuit path"),
        (
            lambda d: d["circuits"][0].update(source_files=[d["circuits"][0]["source_files"][1]]),
            "must be unique and include entry_circuit",
        ),
        (
            lambda d: d["circuits"][0].update(
                public_signals=[d["circuits"][0]["public_signals"][0], d["circuits"][0]["public_signals"][0]]
            ),
            "must be non-empty and unique",
        ),
        (
            lambda d: d["circuits"][0].update(public_signal_schema_digest="00" * 32),
            "public_signal_schema_digest mismatch",
        ),
        (lambda d: d["circuits"][0]["tree_depths"].update(issuance=0), "Invalid tree depth"),
        (lambda d: d["circuits"][0]["domain_tags"].update(holder=0), "Invalid domain tag"),
        (lambda d: d["curves"].pop("bls12-381"), "must pin both bn254 and bls12-381"),
        (
            lambda d: d["curves"].update({"bls12-381": {**d["curves"]["bn254"]}}),
            "Curve map key mismatch",
        ),
        (lambda d: d["circuits"].append(copy.deepcopy(d["circuits"][0])), "Duplicate circuit_id"),
        (lambda d: d["circuits"].pop(), "missing required pilot-transfer-v3 or AIF-67 circuits"),
    ],
)
def test_schema_validators_reject_each_tampering_mode(mutator, expected_fragment):
    base = json.loads((ROOT / PREAUDIT_MANIFEST_PATH).read_text())
    mutator(base)
    with pytest.raises(ValueError, match=expected_fragment):
        PreauditCircuitProfile.model_validate_json(json.dumps(base))


def test_composition_validators_reject_pilot_and_wallet_drift():
    base = json.loads((ROOT / PREAUDIT_MANIFEST_PATH).read_text())

    def recompute_digest(circuit: dict) -> None:
        signals = tuple(mod.PublicSignalEntry(name=s["name"], meaning=s["meaning"]) for s in circuit["public_signals"])
        circuit["public_signal_schema_digest"] = mod.signal_schema_digest(
            circuit_id=circuit["circuit_id"],
            profile_name=circuit["profile_name"],
            curve=circuit["curve"],
            public_signals=signals,
            tree_depths=circuit["tree_depths"],
            domain_tags=circuit["domain_tags"],
        )

    # 1. Pilot profile name drift
    d1 = copy.deepcopy(base)
    d1["circuits"][0]["profile_name"] = "pilot-transfer-v2"
    recompute_digest(d1["circuits"][0])
    with pytest.raises(ValueError, match="pilot-transfer-v3 profile name drifted"):
        PreauditCircuitProfile.model_validate_json(json.dumps(d1))

    # 2. Pilot public signals reordered
    d2 = copy.deepcopy(base)
    d2["circuits"][0]["public_signals"].reverse()
    recompute_digest(d2["circuits"][0])
    with pytest.raises(ValueError, match="pilot-transfer-v3 public signal layout drifted"):
        PreauditCircuitProfile.model_validate_json(json.dumps(d2))

    # 3. Pilot tree depths drifted
    d3 = copy.deepcopy(base)
    d3["circuits"][0]["tree_depths"]["issuance"] = 8
    recompute_digest(d3["circuits"][0])
    with pytest.raises(ValueError, match="pilot-transfer-v3 tree depths drifted"):
        PreauditCircuitProfile.model_validate_json(json.dumps(d3))

    # 4. Wallet-ownership curve mismatch
    d4 = copy.deepcopy(base)
    d4["circuits"][2]["curve"] = "bn254"
    recompute_digest(d4["circuits"][2])
    with pytest.raises(ValueError, match="wallet-ownership-v1-bls12381 curve mismatch"):
        PreauditCircuitProfile.model_validate_json(json.dumps(d4))

    # 5. Wallet-ownership signal drift
    d5 = copy.deepcopy(base)
    d5["circuits"][1]["public_signals"].reverse()
    recompute_digest(d5["circuits"][1])
    with pytest.raises(ValueError, match="wallet-ownership-v1-bn254 public signal layout drifted"):
        PreauditCircuitProfile.model_validate_json(json.dumps(d5))

    # 6. Wallet-ownership domain tag drift
    d6 = copy.deepcopy(base)
    d6["circuits"][2]["domain_tags"]["wallet_ownership_extension"] = 112
    recompute_digest(d6["circuits"][2])
    with pytest.raises(ValueError, match="wallet-ownership-v1-bls12381 domain tag drifted"):
        PreauditCircuitProfile.model_validate_json(json.dumps(d6))


def test_cli_entrypoint_succeeds_and_rejects_bad_pin(capsys, monkeypatch):
    assert mod.main(["--root", str(ROOT)]) == 0
    ok_payload = json.loads(capsys.readouterr().out)
    assert ok_payload["status"] == "ok"
    assert ok_payload["production_eligible"] is False
    assert ok_payload["circuits"] == [
        "pilot-transfer-v3-bn254",
        "wallet-ownership-v1-bn254",
        "wallet-ownership-v1-bls12381",
    ]

    assert mod.main(["--root", str(ROOT), "--trusted-digest", "ff" * 32]) == 1
    bad_payload = json.loads(capsys.readouterr().out)
    assert bad_payload["status"] == "rejected"
    assert bad_payload["reason"] == "untrusted_manifest_digest"

    monkeypatch.setattr(sys, "argv", ["preaudit_profile.py", "--root", str(ROOT)])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(mod.__file__, run_name="__main__")
    assert excinfo.value.code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"


@pytest.fixture(scope="module")
def compiled_bls_wallet_circuit(tmp_path_factory):
    if not shutil.which("circom") or not shutil.which("node"):
        pytest.skip("requires circom and node")
    out = tmp_path_factory.mktemp("preaudit-r1cs")
    for rel, extra in (
        ("circuits/pilot_compliance.circom", []),
        ("circuits/wallet_ownership_credential.circom", []),
        ("circuits/wallet_ownership_credential_bls12381.circom", ["--prime", "bls12381"]),
    ):
        res = subprocess.run(
            ["circom", str(ROOT / rel), *extra, "--r1cs", "--wasm", "-l", str(ROOT / "node_modules"), "-o", str(out)],
            capture_output=True,
            timeout=120,
        )
        assert res.returncode == 0, res.stderr.decode()
    return out


def test_compiled_r1cs_matches_frozen_preaudit_manifest(compiled_bls_wallet_circuit):
    """Compiled R1CS artifacts for all three frozen circuits match the pinned manifest hashes."""
    profile = validate_preaudit_profile(ROOT, r1cs_dir=compiled_bls_wallet_circuit)
    assert len(profile.circuits) == 3


@pytest.mark.parametrize(
    "attack",
    [
        "valid",
        "flag-zero",
        "flag-two",
        "domain",
        "credential-mismatch",
        "attestation-mismatch",
        "credential-zero",
        "attestation-zero",
        "before-issued",
        "expired",
        "commitment-tampered",
        "range-overflow",
    ],
)
def test_bls12381_wallet_ownership_witness_and_negative_cases(compiled_bls_wallet_circuit, tmp_path, attack):
    """Positive and negative proof/witness tests for AIF-67 on curve-correct BLS12-381 Poseidon."""
    cred_commitment = 12345678901234567890123456789012345678901234567890
    attestation_digest = 98765432109876543210987654321098765432109876543210
    fields = [111, cred_commitment, attestation_digest, 1200, 87600, 1]
    data = {
        "fields": [str(x) for x in fields],
        "extension_commitment": str(poseidon_hash_bls12381(fields)),
        "expected_credential_commitment": str(cred_commitment),
        "expected_attestation_digest": str(attestation_digest),
        "evaluated_at": "1300",
    }

    if attack == "flag-zero":
        fields[5] = 0
        data["fields"] = [str(x) for x in fields]
        data["extension_commitment"] = str(poseidon_hash_bls12381(fields))
    elif attack == "flag-two":
        fields[5] = 2
        data["fields"] = [str(x) for x in fields]
        data["extension_commitment"] = str(poseidon_hash_bls12381(fields))
    elif attack == "domain":
        fields[0] = 102
        data["fields"] = [str(x) for x in fields]
        data["extension_commitment"] = str(poseidon_hash_bls12381(fields))
    elif attack == "credential-mismatch":
        data["expected_credential_commitment"] = str(cred_commitment + 1)
    elif attack == "attestation-mismatch":
        data["expected_attestation_digest"] = str(attestation_digest + 1)
    elif attack == "credential-zero":
        fields[1] = 0
        data["fields"] = [str(x) for x in fields]
        data["expected_credential_commitment"] = "0"
        data["extension_commitment"] = str(poseidon_hash_bls12381(fields))
    elif attack == "attestation-zero":
        fields[2] = 0
        data["fields"] = [str(x) for x in fields]
        data["expected_attestation_digest"] = "0"
        data["extension_commitment"] = str(poseidon_hash_bls12381(fields))
    elif attack == "before-issued":
        data["evaluated_at"] = "1199"
    elif attack == "expired":
        data["evaluated_at"] = "87600"
    elif attack == "commitment-tampered":
        data["extension_commitment"] = str((int(data["extension_commitment"]) + 1) % BLS12_381_SCALAR_FIELD)
    elif attack == "range-overflow":
        fields[4] = 2**53
        data["fields"] = [str(x) for x in fields]
        data["extension_commitment"] = str(poseidon_hash_bls12381(fields))

    inp = tmp_path / "input.json"
    inp.write_text(json.dumps(data))
    js_dir = compiled_bls_wallet_circuit / "wallet_ownership_credential_bls12381_js"
    result = subprocess.run(
        [
            "node",
            str(js_dir / "generate_witness.js"),
            str(js_dir / "wallet_ownership_credential_bls12381.wasm"),
            str(inp),
            str(tmp_path / "witness.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )
    if attack == "valid":
        assert result.returncode == 0, result.stderr.decode()
    else:
        assert result.returncode != 0 and b"Assert Failed" in result.stderr
