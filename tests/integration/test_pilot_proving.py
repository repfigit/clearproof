"""Real pinned memory-only proving with an explicit development artifact bundle."""

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from src.prover.pilot_prover import PilotProver, PilotProvingError

ROOT = Path(__file__).resolve().parents[2]


async def test_real_memory_only_proving_and_tampered_witness(tmp_path, monkeypatch):
    location = os.getenv("CLEARPROOF_PILOT_TEST_ARTIFACTS")
    if not location:
        pytest.skip("requires an explicit unapproved development artifact bundle")
    root = Path(location)
    runtime = ROOT / "node_modules/snarkjs/build/snarkjs.min.js"
    prover = PilotProver.load(
        root,
        trusted_digest=(root / "development-manifest-pin.txt").read_text().strip(),
        bundle_path=runtime,
        bundle_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
        node=Path(shutil.which("node")),
    )
    # The directory is explicitly owned by this test; it may contain public runtime
    # code during the operation, never private inputs or generated witness files.
    scratch = tmp_path / "owned-runtime"
    scratch.mkdir()
    monkeypatch.setattr("src.prover.pilot_prover.tempfile.tempdir", str(scratch))
    witness = json.loads((root / "synthetic.json").read_bytes())
    expected = json.loads((root / "expected-public.json").read_bytes())
    result = await prover.prove(witness, expected_signals=expected)
    assert result.public_signals == tuple(expected)
    assert (await prover.verifier.inspect(result.proof, expected, expected_signals=expected)).cryptographic_valid
    assert not list(scratch.iterdir())
    altered = {**witness, "projection_commitment": str(int(witness["projection_commitment"]) + 1)}
    with pytest.raises(PilotProvingError, match="proving_runtime_failed"):
        await prover.prove(altered, expected_signals=expected)
    assert not list(scratch.iterdir())
