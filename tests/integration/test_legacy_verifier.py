"""Verify committed development vectors with the actual installed SnarkJS CLI."""

import json
import shutil
from pathlib import Path

import pytest

from src.prover.snarkjs_prover import SnarkJSProver
from src.prover.verifier import verify_proof


async def test_real_legacy_verifiers_accept_valid_and_reject_mutated_signals():
    root = Path(__file__).resolve().parents[2]
    if not shutil.which("npx") or not (root / "node_modules/snarkjs/cli.js").is_file():
        pytest.skip("requires installed local SnarkJS")
    vectors = root / "tests/vectors/compliance"
    proof = json.loads((vectors / "proof.json").read_text())
    public = json.loads((vectors / "public.json").read_text())
    key = vectors / "verification_key.json"
    assert await verify_proof(proof, public, str(key))
    prover = SnarkJSProver(vkey_path=str(key))
    assert await prover.verify(proof, public)
    modified = list(public)
    modified[0] = str(int(modified[0]) + 1)
    assert not await verify_proof(proof, modified, str(key))
    assert not await prover.verify(proof, modified)


async def test_real_legacy_prover_round_trip():
    import os
    import re

    artifacts = os.environ.get("CLEARPROOF_LEGACY_TEST_ARTIFACTS")
    if not artifacts:
        pytest.skip("requires local legacy development circuit artifacts")
    root = Path(__file__).resolve().parents[2]
    inputs = json.loads((root / "tests/vectors/compliance/input.json").read_text())
    # The shared vector uses SDK camelCase; the Python wrapper accepts circuit names.
    inputs = {re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower(): value for key, value in inputs.items()}
    prover = SnarkJSProver(artifacts_dir=artifacts, prove_timeout=120)
    proof, public = await prover.fullprove(inputs)
    assert proof["_meta"]["proving_time_ms"] >= 0
    assert await prover.verify(proof, public)
    public[0] = str(int(public[0]) + 1)
    assert not await prover.verify(proof, public)
