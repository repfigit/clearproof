"""Reproduce historical BLS benchmark inputs without modifying committed vectors."""

import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import make_bls_input as converter
from src.registry.poseidon import poseidon_hash

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def isolated_converter(tmp_path, monkeypatch):
    root = tmp_path / "conversion"
    inputs = root / "tests/vectors/compliance/input.json"
    inputs.parent.mkdir(parents=True)
    inputs.write_bytes((ROOT / "tests/vectors/compliance/input.json").read_bytes())
    (root / "node_modules").symlink_to(ROOT / "node_modules", target_is_directory=True)
    scripts = root / "scripts"
    scripts.mkdir()
    for name in ("make_bls_input.py", "generate_poseidon_constants.py"):
        (scripts / name).symlink_to(ROOT / "scripts" / name)
    monkeypatch.setattr(converter, "REPO_ROOT", str(root))
    return root, inputs, root / "tests/vectors/compliance-bls/input_bls.json"


def test_real_conversion_reproduces_every_committed_bls_field(isolated_converter, capsys):
    _, inputs, output = isolated_converter
    before = inputs.read_bytes()
    converter.main()
    reference = json.loads((ROOT / "tests/vectors/compliance-bls/input_bls.json").read_text())
    assert json.loads(output.read_text()) == reference
    assert inputs.read_bytes() == before
    assert "BN254 self-check: all derived values reproduced" in capsys.readouterr().out


def test_executable_entry_resolves_its_isolated_script_location(isolated_converter):
    root, _, output = isolated_converter
    # A symlink preserves the real script's code while relocating its writable
    # fixture tree. runpy executes the same __main__ path used by Python's CLI.
    runpy.run_path(str(root / "scripts/make_bls_input.py"), run_name="__main__")
    reference = json.loads((ROOT / "tests/vectors/compliance-bls/input_bls.json").read_text())
    assert json.loads(output.read_text()) == reference


def test_fresh_python_process_converts_from_foreign_working_directory(isolated_converter, tmp_path):
    root, _, output = isolated_converter
    process = subprocess.run(
        [sys.executable, str(root / "scripts/make_bls_input.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert process.returncode == 0, process.stderr
    assert process.stderr == ""
    assert "BN254 self-check: all derived values reproduced" in process.stdout
    reference = json.loads((ROOT / "tests/vectors/compliance-bls/input_bls.json").read_text())
    assert json.loads(output.read_text()) == reference


@pytest.mark.parametrize(
    "field,message",
    [
        ("sanctionsTreeRoot", "BN254 left path root mismatch"),
        ("rightKey", "BN254 right path root mismatch"),
        ("issuerTreeRoot", "BN254 issuer root mismatch"),
        ("credentialCommitment", "BN254 commitment mismatch"),
        ("credentialNullifier", "BN254 nullifier mismatch"),
    ],
)
def test_corrupt_bn254_reference_is_rejected_before_output(isolated_converter, field, message):
    _, inputs, output = isolated_converter
    data = json.loads(inputs.read_text())
    data[field] = str(int(data[field]) + 1)
    inputs.write_text(json.dumps(data))
    with pytest.raises(AssertionError, match=message):
        converter.main()
    assert not output.exists()


def test_field_equivalent_bn254_path_cannot_silently_change_bls_root(isolated_converter):
    _, inputs, output = isolated_converter
    data = json.loads(inputs.read_text())
    # Adding p preserves a BN254 hash input but changes its value in BLS_R.
    # The independent left/right BLS root consistency check must catch this.
    data["rightPathElements"][0] = str(int(data["rightPathElements"][0]) + converter.BN254_R)
    inputs.write_text(json.dumps(data))
    with pytest.raises(AssertionError, match="BLS tree root inconsistency between paths"):
        converter.main()
    assert not output.exists()


@pytest.mark.parametrize("arity", [1, 2, 5, 16])
def test_optimized_bn254_hash_matches_native_parameters_across_arities(arity):
    inputs = [2**128 + i for i in range(arity)]
    optimized = converter.make_poseidon(converter.BN254_R)
    assert optimized(inputs) == poseidon_hash(inputs)
    assert optimized([value + converter.BN254_R for value in inputs]) == optimized(inputs)
