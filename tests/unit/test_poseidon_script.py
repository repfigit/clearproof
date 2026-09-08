"""Exercise the Node operational helper's actual stdin/stdout contract."""

import json
import subprocess
from pathlib import Path

import pytest

from src.registry.poseidon import poseidon_hash

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/poseidon_hash.js"


@pytest.mark.parametrize("wrapped", [False, True])
def test_poseidon_helper_preserves_large_decimal_inputs_from_external_directory(tmp_path, wrapped):
    inputs = [2**200 + 123, 2**128 + 456]
    # Decimal strings avoid JSON/JavaScript's lossy number conversion.
    encoded = [str(value) for value in inputs]
    payload = {"inputs": encoded} if wrapped else encoded
    result = subprocess.run(
        ["node", str(SCRIPT)],
        input=" " * 100_000 + json.dumps(payload) + "\n",
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == f"{poseidon_hash(inputs)}\n"


@pytest.mark.parametrize("payload", ["", "{", "null", "{}", '{"inputs":1}', '"array-required"'])
def test_poseidon_helper_rejects_invalid_json_shapes_without_a_hash(payload, tmp_path):
    result = subprocess.run(
        ["node", str(SCRIPT)], input=payload, cwd=tmp_path, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("Invalid input JSON: ")


@pytest.mark.parametrize("payload", ['["not-an-integer"]', "[1.5]", "[]", json.dumps(["1"] * 17)])
def test_poseidon_helper_rejects_invalid_field_input_or_arity(payload, tmp_path):
    result = subprocess.run(
        ["node", str(SCRIPT)], input=payload, cwd=tmp_path, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("Error: ")
