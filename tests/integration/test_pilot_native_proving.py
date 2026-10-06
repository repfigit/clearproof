"""Explicit source-pinned native build and unapproved current-profile artifacts."""

import hashlib
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from src.prover.pilot_native_prover import PilotNativeProver
from src.prover.pilot_prover import PilotProver, PilotProvingError
from src.prover.proof_job_worker import ProofJobWorker
from tests.integration.pilot_job_setup import provision
from tests.integration.test_pilot_storage import db as db
from tests.integration.test_proof_job_acceptance import body

pytestmark = pytest.mark.skipif(
    not os.getenv("CLEARPROOF_PILOT_TEST_ARTIFACTS") or not os.getenv("CLEARPROOF_RAPIDSNARK_TEST_BIN"),
    reason="requires explicit unapproved artifacts and an optional pinned native test build",
)


def backend(javascript):
    return PilotNativeProver.load(
        javascript,
        binary=Path(os.environ["CLEARPROOF_RAPIDSNARK_TEST_BIN"]),
        binary_sha256=os.environ["CLEARPROOF_RAPIDSNARK_TEST_SHA256"],
    )


@pytest.fixture
def actual_native():
    root = Path(os.environ["CLEARPROOF_PILOT_TEST_ARTIFACTS"])
    runtime = Path(__file__).parents[2] / "node_modules/snarkjs/build/snarkjs.min.js"
    javascript = PilotProver.load(
        root,
        trusted_digest=(root / "development-manifest-pin.txt").read_text().strip(),
        bundle_path=runtime,
        bundle_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
        node=Path(shutil.which("node")),
    )
    return backend(javascript), root


async def test_real_native_memory_transport_and_independent_pairing(actual_native):
    native, root = actual_native
    expected = json.loads((root / "expected-public.json").read_text())
    result = await native.prove(json.loads((root / "synthetic.json").read_text()), expected_signals=expected)
    assert result.public_signals == tuple(expected)
    assert (await native.verifier.inspect(result.proof, expected, expected_signals=expected)).cryptographic_valid


async def test_real_native_rejects_unsatisfied_witness_and_wrong_expected_statement(actual_native):
    native, root = actual_native
    witness = json.loads((root / "synthetic.json").read_text())
    expected = json.loads((root / "expected-public.json").read_text())
    with pytest.raises(PilotProvingError, match="native_runtime_failed"):
        await native.prove(
            {**witness, "projection_commitment": str(int(witness["projection_commitment"]) + 1)},
            expected_signals=expected,
        )
    altered = [str(int(expected[0]) + 1), *expected[1:]]
    with pytest.raises(PilotProvingError, match="proving_signal_mismatch"):
        await native.prove(witness, expected_signals=altered)


@pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires owned PostgreSQL")
async def test_actual_native_job_handoff_uses_backend_pin_and_current_state_guards(db):
    service, who, _, credential = await provision(db)
    key = (who.tenant_id, "synthetic-target")
    original = service.targets[key]
    native = backend(original.prover)
    service.targets[key] = replace(original, prover=native)
    assert service.targets[key].digest != original.digest
    admitted = await service.enqueue(who, body(credential))
    assert await ProofJobWorker(service).run_once()
    response = await service.read(who, admitted.job_id)
    assert response["status"] == "completed" and response["result_available"]
    assert not response["authorization_consumed"]
    # Replacing the selected backend cannot hand out a proof under the same
    # target identifier, even when the statement and artifact manifest match.
    service.targets[key] = original
    stale = await service.read(who, admitted.job_id)
    assert not stale["result_available"] and "result" not in stale
