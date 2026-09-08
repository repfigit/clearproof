"""The contract-fixture runner must verify real proofs before emitting JSON."""

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import pilot_contract_fixture as fixture


@pytest.mark.parametrize("tamper", [False, True])
def test_real_fixture_proof_validation_and_temporary_cleanup(tamper, monkeypatch, capsys):
    location = os.environ.get("CLEARPROOF_PILOT_TEST_ARTIFACTS")
    if not location:
        pytest.skip("requires explicit synthetic pilot development artifacts")
    registry = "0x" + "12" * 20
    evaluated_at = 1_800_000_000
    monkeypatch.setattr(sys, "argv", [fixture.__file__, location, registry, str(evaluated_at)])
    real_run = subprocess.run
    temporary_directories = []

    def generate_then_optionally_tamper(args, **kwargs):
        result = real_run(args, **kwargs)
        if "fullprove" in args:
            signals_path = Path(args[-1])
            temporary_directories.append(signals_path.parent)
            if tamper:
                signals = json.loads(signals_path.read_text())
                # Keep public context unchanged but alter the claimed private
                # authorization nullifier. The actual pairing must reject it.
                signals[3] = str(int(signals[3]) + 1)
                signals_path.write_text(json.dumps(signals))
        return result

    monkeypatch.setattr(fixture.subprocess, "run", generate_then_optionally_tamper)
    if tamper:
        with pytest.raises(RuntimeError, match="Synthetic current proof did not verify"):
            fixture.main()
        assert capsys.readouterr().out == ""
    else:
        runpy.run_path(fixture.__file__, run_name="__main__")
        output = capsys.readouterr()
        assert output.err == ""
        payload = json.loads(output.out)
        assert payload["scope"] == "synthetic-contract-checkpoints"
        assert payload["assurance"] == "development-unapproved"
        assert payload["python_current_valid"] is True
        assert payload["evaluated_at"] == evaluated_at
        assert int(payload["signals"][4]) == evaluated_at
        assert int(payload["signals"][7]) == int(registry, 16)
        assert payload["valid_until"] == int(payload["signals"][5]) > evaluated_at
        assert len(payload["heads"]) == 8
        assert [head["value"] for head in payload["heads"][-5:]] == ["0", "0", "0", "0", "1"]
        assert all(len(head["digest"]) == 64 for head in payload["heads"])
        assert payload["proof"]["protocol"] == "groth16"
    assert len(temporary_directories) == 1
    assert all(not path.exists() for path in temporary_directories)


@pytest.mark.parametrize("failure", ["timeout", "exit"])
def test_prover_failure_propagates_without_fixture_output_and_cleans_input(failure, monkeypatch, capsys):
    location = os.environ.get("CLEARPROOF_PILOT_TEST_ARTIFACTS")
    if not location:
        pytest.skip("requires explicit synthetic pilot development artifacts")
    monkeypatch.setattr(sys, "argv", [fixture.__file__, location, "0x" + "12" * 20, "1800000000"])
    directories = []

    def fail(args, **kwargs):
        assert args[2:4] == ["groth16", "fullprove"]
        source = Path(args[4])
        assert source.exists()
        directories.append(source.parent)
        assert kwargs["check"] is True
        assert kwargs["timeout"] == 120
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 120)
        raise subprocess.CalledProcessError(7, args)

    monkeypatch.setattr(fixture.subprocess, "run", fail)
    error = subprocess.TimeoutExpired if failure == "timeout" else subprocess.CalledProcessError
    with pytest.raises(error):
        fixture.main()
    assert capsys.readouterr().out == ""
    assert len(directories) == 1
    assert not directories[0].exists()
