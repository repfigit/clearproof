"""Re-derive the legacy fixture with explicit, unapproved development artifacts."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.test_development_circuits import LEGACY_PARITY_PROGRAM, ROOT, run


@pytest.mark.parametrize("mutation", ["none", "public", "private"])
def test_sdk_derivation_retains_only_a_complete_matching_development_vector(tmp_path, mutation, capfd):
    artifacts = os.environ.get("CLEARPROOF_LEGACY_TEST_ARTIFACTS")
    if artifacts is None:
        pytest.skip("requires explicit unapproved legacy development artifacts")
    assert artifacts.strip(), "Explicit legacy test bundle is empty"
    node = shutil.which("node")
    assert node, "Explicit legacy derivation requires installed Node"
    fixtures = ROOT / "tests/vectors/compliance"
    input_path, public_path = tmp_path / "input.json", tmp_path / "public.json"
    input_path.write_bytes((fixtures / "input.json").read_bytes())
    public_path.write_bytes((fixtures / "public.json").read_bytes())
    output = tmp_path / "regenerated-vector"
    if mutation == "public":
        public = json.loads(public_path.read_text())
        public[14] = str(int(public[14]) + 1)
        public_path.write_text(json.dumps(public))
    elif mutation == "private":
        inputs = json.loads(input_path.read_text())
        inputs["issuedAt"] += 1
        input_path.write_text(json.dumps(inputs))

    def derive():
        run(
            node,
            "--input-type=module",
            "-e",
            LEGACY_PARITY_PROGRAM,
            Path(artifacts),
            input_path,
            public_path,
            output,
            timeout=120,
        )

    if mutation != "none":
        with pytest.raises(subprocess.CalledProcessError):
            derive()
        stderr = capfd.readouterr().err
        expected_error = "input-derived public signals diverge" if mutation == "public" else "Assert Failed"
        assert expected_error in stderr
        assert not output.exists(), "Rejected derivation must not publish a vector"
        return

    derive()
    assert set(p.name for p in output.iterdir()) == {
        "input.json",
        "proof.json",
        "public.json",
        "verification_key.json",
        "MANIFEST.json",
    }
    assert (output / "input.json").read_bytes() == input_path.read_bytes()
    assert json.loads((output / "public.json").read_text()) == json.loads(public_path.read_text())
    manifest = json.loads((output / "MANIFEST.json").read_text())
    assert manifest["devKeysOnly"] is True
    assert "NOT valid for production" in manifest["warning"]
    assert manifest["all_public_signals_reproduced"] is True
    assert manifest["pairing_valid"] is True and manifest["policy_valid"] is False
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    assert manifest["artifacts"]["vkey_sha256"] == manifest["files"]["verification_key.json"]
    assert manifest["phase1_sha256"] == (Path(artifacts).parent / "ptau-sha256.txt").read_text().strip()
