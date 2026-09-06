"""Opt-in real Groth16 verification of the ADR 0006 local synthetic proof.

The local bundle's own pin is read for reproducibility only. Production trust
configuration must be independent; this fixture never approves a policy or key.
"""

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from src.prover.pilot_artifacts import inspect_artifacts
from src.prover.pilot_verifier import PilotPairingVerifier, ProofInspectionError

ROOT = Path(__file__).resolve().parents[2]


async def test_real_pinned_pairing_and_tampered_proof():
    location = os.environ.get("CLEARPROOF_PILOT_TEST_ARTIFACTS")
    if not location:
        pytest.skip("requires the explicit ADR 0006 local development artifact directory")
    root = Path(location)
    artifacts = inspect_artifacts(root, trusted_digest=(root / "development-manifest-pin.txt").read_text().strip())
    bundle = ROOT / "node_modules/snarkjs/build/snarkjs.min.js"
    verifier = PilotPairingVerifier.load(
        artifacts,
        bundle_path=bundle,
        bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
        node=Path(shutil.which("node")),
    )
    proof = (root / "proof.json").read_bytes()
    signals = json.loads((root / "public.json").read_bytes())
    expected = json.loads((root / "expected-public.json").read_bytes())
    result = await verifier.inspect(proof, signals, expected_signals=expected)
    assert result.cryptographic_valid
    wrong_signals = [str(int(signals[0]) + 1), *signals[1:]]
    with pytest.raises(ProofInspectionError, match="public_signal_context_mismatch"):
        await verifier.inspect(proof, wrong_signals, expected_signals=expected)
    # Even if a caller supplies wrong expectations, the pairing must reject.
    wrong_result = await verifier.inspect(proof, wrong_signals, expected_signals=wrong_signals)
    assert not wrong_result.cryptographic_valid
    changed = json.loads(proof)
    changed["pi_c"][0] = str(int(changed["pi_c"][0]) + 1)
    assert not (
        await verifier.inspect(json.dumps(changed).encode(), signals, expected_signals=expected)
    ).cryptographic_valid
