"""Pinned artifact trust, mixed-file rejection and secret-free diagnostics."""

import hashlib
import json
import os
import subprocess
import sys

import pytest

from src.policy.model import POLICY_SCHEMA_DIGEST, PilotPolicy
from src.protocol.canonical import record_digest
from src.prover.pilot_artifacts import ArtifactError, PilotArtifactManifest, inspect_artifacts
from src.prover.pilot_compliance import PUBLIC_SIGNALS


def publish(root, value):
    raw = json.dumps(value).encode()
    (root / "manifest.json").write_bytes(raw)
    return PilotArtifactManifest.model_validate_json(raw).digest


@pytest.fixture
def bundle(tmp_path):
    tmp_path = tmp_path / "bundle"
    tmp_path.mkdir()
    # Deliberately not cryptographic test vectors: this suite tests the loader.
    # Groth16 verification remains a separate requirement.
    value = {
        "proof_profile": "pilot-transfer-v2",
        "policy_schema_digest": POLICY_SCHEMA_DIGEST,
        "source_bundle_digest": "34" * 32,
        "compiler_sha256": "56" * 32,
        "public_signals": list(PUBLIC_SIGNALS),
    }
    for role, content in (
        ("wasm", b"synthetic-wasm"),
        ("r1cs", b"synthetic-r1cs"),
        ("proving_key", b"synthetic-zkey"),
        (
            "verification_key",
            json.dumps({"protocol": "groth16", "curve": "bn128", "nPublic": 8, "IC": [["1", "2", "1"]] * 9}).encode(),
        ),
    ):
        filename = role + ".bin"
        (tmp_path / filename).write_bytes(content)
        value[role] = {"filename": filename, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    return tmp_path, value, publish(tmp_path, value)


def test_pinned_snapshot_and_read_only_report(bundle):
    root, value, pin = bundle
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    result = inspect_artifacts(root, trusted_digest=pin)
    assert result.report()["status"] == "development_unapproved"
    assert result.report()["production_eligible"] is False
    assert result.report()["policy_schema_supported"] is True
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before
    key = root / value["verification_key"]["filename"]
    key.write_bytes(b"replaced")
    assert result.verification_key_bytes == before[key.name]
    assert b"synthetic" not in repr(result).encode()
    assert str(root) not in json.dumps(result.report())


@pytest.mark.parametrize("role", ["wasm", "r1cs", "proving_key", "verification_key"])
def test_same_length_mixed_files_fail(bundle, role):
    root, value, pin = bundle
    path = root / value[role]["filename"]
    raw = path.read_bytes()
    path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    with pytest.raises(ArtifactError, match="artifact_hash_mismatch"):
        inspect_artifacts(root, trusted_digest=pin)


def test_manifest_cannot_approve_itself(bundle):
    root, value, pin = bundle
    value["policy_schema_digest"] = "78" * 32
    publish(root, value)
    with pytest.raises(ArtifactError, match="untrusted_manifest"):
        inspect_artifacts(root, trusted_digest=pin)


def test_production_cannot_use_even_pinned_development_bundle(bundle):
    root, _, pin = bundle
    with pytest.raises(ArtifactError, match="development_artifacts_forbidden"):
        inspect_artifacts(root, trusted_digest=pin, mode="production")


@pytest.mark.parametrize("mutation", ["production", "legacy", "reordered", "path", "duplicate", "unknown"])
def test_invalid_manifest_is_rejected_before_file_reads(bundle, mutation):
    root, value, pin = bundle
    if mutation == "production":
        value["assurance"] = "production-approved"
    elif mutation == "legacy":
        value["proof_profile"] = "legacy-v1"
    elif mutation == "reordered":
        value["public_signals"].reverse()
    elif mutation == "path":
        value["wasm"]["filename"] = "../secret"
    elif mutation == "duplicate":
        value["wasm"]["filename"] = value["r1cs"]["filename"]
    else:
        value["unexpected_secret"] = "must-not-appear"
    (root / "manifest.json").write_text(json.dumps(value))
    with pytest.raises(ArtifactError, match="^invalid_manifest$"):
        inspect_artifacts(root, trusted_digest=pin)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "truncated", "missing"])
def test_special_or_wrong_size_file_rejected_without_blocking(bundle, kind):
    root, value, pin = bundle
    path = root / value["wasm"]["filename"]
    path.unlink()
    if kind == "symlink":
        path.symlink_to(root / value["r1cs"]["filename"])
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "truncated":
        path.write_bytes(b"x")
    with pytest.raises(ArtifactError):
        inspect_artifacts(root, trusted_digest=pin)


def test_duplicate_json_key_is_not_silently_normalized(bundle):
    root, _, pin = bundle
    path = root / "manifest.json"
    raw = path.read_text()
    path.write_text('{"proof_profile":"legacy",' + raw[1:])
    with pytest.raises(ArtifactError, match="invalid_manifest"):
        inspect_artifacts(root, trusted_digest=pin)


def test_legacy_key_rejected_even_if_manifest_pinned(bundle):
    root, value, _ = bundle
    path = root / value["verification_key"]["filename"]
    raw = json.dumps({"protocol": "groth16", "curve": "bn128", "nPublic": 16, "IC": [0] * 17}).encode()
    path.write_bytes(raw)
    value["verification_key"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    pin = publish(root, value)
    with pytest.raises(ArtifactError, match="verification_key_profile_mismatch"):
        inspect_artifacts(root, trusted_digest=pin)


def test_doctor_exit_codes_and_no_paths_in_diagnostics(bundle):
    root, _, pin = bundle
    command = [sys.executable, "-m", "src.prover.pilot_artifacts", str(root), "--trusted-manifest-digest", pin]
    good = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert good.returncode == 0, good.stderr
    assert json.loads(good.stdout)["status"] == "development_unapproved"
    bad = subprocess.run([*command, "--mode", "production"], capture_output=True, text=True, timeout=15)
    assert bad.returncode == 1
    assert json.loads(bad.stdout)["reason"] == "development_artifacts_forbidden"
    assert str(root) not in bad.stdout + bad.stderr


def test_context_cannot_select_another_key_or_profile(bundle):
    from pathlib import Path

    from src.protocol.transfer import VerificationContext

    root, _, pin = bundle
    result = inspect_artifacts(root, trusted_digest=pin)
    fixture = json.loads((Path(__file__).resolve().parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    data = {**fixture["records"][1]["value"], "artifact_manifest_digest": pin, "proof_profile": "pilot-transfer-v2"}
    result.check_artifact_context(VerificationContext.model_validate(data))
    for key, changed in [("artifact_manifest_digest", "ab" * 32), ("proof_profile", "legacy-v1")]:
        with pytest.raises(ArtifactError, match="artifact_context_mismatch"):
            result.check_artifact_context(VerificationContext.model_validate({**data, key: changed}))


def test_published_policy_schema_matches_runtime():
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "specs/pilot-policy-v1.schema.json"
    schema = json.loads(path.read_text())
    assert schema == PilotPolicy.model_json_schema()
    assert record_digest("clearproof/policy-schema/v1", schema) == POLICY_SCHEMA_DIGEST
    schema["properties"]["rules"]["maxItems"] = 65
    assert record_digest("clearproof/policy-schema/v1", schema) != POLICY_SCHEMA_DIGEST


@pytest.mark.parametrize("schema_digest", ["00" * 32, "ab" * 32])
def test_pinned_unknown_policy_schema_is_inspectable_but_not_current_compatible(bundle, schema_digest):
    from pathlib import Path

    from src.protocol.transfer import VerificationContext

    root, value, _ = bundle
    value["policy_schema_digest"] = schema_digest
    pin = publish(root, value)
    inspected = inspect_artifacts(root, trusted_digest=pin)
    assert inspected.report()["policy_schema_supported"] is False
    fixture = json.loads((Path(__file__).resolve().parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    context = VerificationContext.model_validate(
        {**fixture["records"][1]["value"], "artifact_manifest_digest": pin, "proof_profile": "pilot-transfer-v2"}
    )
    with pytest.raises(ArtifactError, match="^unsupported_policy_schema$"):
        inspected.check_artifact_context(context)


def test_v1_remains_inspectable_but_cannot_enter_current_context(bundle):
    from pathlib import Path

    from src.protocol.transfer import VerificationContext

    root, value, _ = bundle
    value.pop("proof_profile")  # Original v1 manifests omitted the default field.
    pin = publish(root, value)
    inspected = inspect_artifacts(root, trusted_digest=pin)
    assert inspected.manifest.proof_profile == "pilot-transfer-v1"
    assert inspected.report()["current_profile_supported"] is False
    fixture = json.loads((Path(__file__).resolve().parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    context = VerificationContext.model_validate(
        {**fixture["records"][1]["value"], "artifact_manifest_digest": pin, "proof_profile": "pilot-transfer-v1"}
    )
    with pytest.raises(ArtifactError, match="historical_profile_not_current"):
        inspected.check_artifact_context(context)


@pytest.mark.parametrize("mode", ["", "test", "Production", None])
def test_unknown_runtime_mode_rejects_before_opening(bundle, mode):
    root, _, pin = bundle
    with pytest.raises(ArtifactError, match="^invalid_runtime_mode$"):
        inspect_artifacts(root / "missing", trusted_digest=pin, mode=mode)


@pytest.mark.parametrize("pin", [None, "", "AB" * 32, "00" * 31, "00" * 33])
def test_trust_pin_requires_canonical_sha256(bundle, pin):
    root, _, _ = bundle
    with pytest.raises(ArtifactError, match="^invalid_trust_pin$"):
        inspect_artifacts(root / "missing", trusted_digest=pin)


@pytest.mark.parametrize("kind", ["missing", "file", "symlink"])
def test_artifact_root_must_be_real_directory(bundle, tmp_path, kind):
    root, _, pin = bundle
    target = tmp_path / "alternative"
    if kind == "file":
        target.write_bytes(b"synthetic")
    elif kind == "symlink":
        target.symlink_to(root, target_is_directory=True)
    with pytest.raises(ArtifactError, match="^artifact_directory_unavailable$"):
        inspect_artifacts(target, trusted_digest=pin)


@pytest.mark.parametrize("mutation", ["grow", "truncate", "rewrite"])
def test_artifact_change_after_initial_stat_rejects(tmp_path, monkeypatch, mutation):
    from src.prover.pilot_artifacts import _read_file

    path = tmp_path / "artifact.bin"
    path.write_bytes(b"synthetic-original")
    original_size = path.stat().st_size
    original_fstat = os.fstat
    changed = False

    def mutate_after_snapshot(fd):
        nonlocal changed
        snapshot = original_fstat(fd)
        if not changed:
            changed = True
            if mutation == "grow":
                with path.open("ab") as writer:
                    writer.write(b"additional-bytes")
            elif mutation == "truncate":
                path.write_bytes(b"short")
            else:
                path.write_bytes(b"x" * original_size)
                # Ensure timestamp detection without relying on filesystem resolution.
                os.utime(path, ns=(snapshot.st_atime_ns, snapshot.st_mtime_ns + 1_000_000_000))
        return snapshot

    monkeypatch.setattr(os, "fstat", mutate_after_snapshot)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        message = "artifact_size_limit" if mutation == "grow" else "artifact_changed_during_read"
        with pytest.raises(ArtifactError, match=f"^{message}$"):
            _read_file(directory, path.name, limit=original_size)
        assert changed
    finally:
        os.close(directory)


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"{", "invalid_json"),
        (b'"\xff"', "invalid_json"),
        (b"NaN", "invalid_json_constant"),
        (b"Infinity", "invalid_json_constant"),
        (b"-Infinity", "invalid_json_constant"),
        (b'{"nested":{"key":1,"key":2}}', "duplicate_json_key"),
    ],
)
def test_strict_json_rejects_invalid_or_ambiguous_encoding(raw, code):
    from src.prover.pilot_artifacts import strict_json

    with pytest.raises(ArtifactError, match=f"^{code}$"):
        strict_json(raw)


def test_strict_json_enforces_exact_byte_limit():
    from src.prover.pilot_artifacts import strict_json

    assert strict_json(b"{}", limit=2) == {}
    with pytest.raises(ArtifactError, match="^json_size_limit$"):
        strict_json(b"{}", limit=1)
