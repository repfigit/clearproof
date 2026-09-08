"""Operational generator output and rare Cauchy-matrix rejection paths."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import generate_poseidon_constants as generator


def test_mds_redraws_all_values_after_duplicates_and_zero_denominators(monkeypatch):
    real = generator.GrainLFSR(2, 56)
    # Keep round constants from the actual Grain stream, while injecting only
    # the rare matrix draws. Rejection must restart the entire four-value draw.
    draws = Mock(side_effect=[1, 1, 2, 3, 1, 2, generator.P - 1, 4, 1, 2, 3, 4])
    stream = SimpleNamespace(next_field_element=real.next_field_element, next_bits_as_int=draws)
    factory = Mock(return_value=stream)
    monkeypatch.setattr(generator, "GrainLFSR", factory)
    constants, matrix = generator.generate_parameters(2, 56)
    factory.assert_called_once_with(2, 56)
    assert draws.call_count == 12
    assert all(call.args == (254,) for call in draws.call_args_list)
    committed = json.loads(Path(generator.OUTPUT_PATH).read_text())
    assert constants == [int(value, 16) for value in committed["C"][0]]
    for i, x in enumerate((1, 2)):
        for j, y in enumerate((3, 4)):
            assert matrix[i][j] * (x + y) % generator.P == 1
    assert (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % generator.P != 0


def test_real_generation_writes_complete_reference_constants_to_new_directory(tmp_path, monkeypatch, capsys):
    committed = Path(generator.OUTPUT_PATH).read_bytes()
    destination = tmp_path / "new" / "nested" / "parameters.json"
    monkeypatch.setattr(generator, "OUTPUT_PATH", str(destination))
    monkeypatch.setattr(sys, "argv", ["generate_poseidon_constants.py"])
    generator.main()
    assert json.loads(destination.read_text()) == json.loads(committed)
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.count("done") == 16
    assert f"Wrote {destination}" in output.out


@pytest.mark.parametrize("changed", [False, True])
def test_verify_only_reports_mismatch_and_never_rewrites_input(changed, tmp_path, monkeypatch, capsys):
    reference = json.loads(Path(generator.OUTPUT_PATH).read_text())
    destination = tmp_path / "parameters.json"
    saved = json.loads(json.dumps(reference))
    if changed:
        saved["C"][0][0] = hex(int(saved["C"][0][0], 16) + 1)
    destination.write_text(json.dumps(saved))
    before = destination.read_bytes()
    modified_before = destination.stat().st_mtime_ns

    # Output lifecycle is independent of the expensive generation already
    # exercised above and by live reference-vector parity tests.
    def cached_parameters(t, rounds):
        assert rounds == generator.N_ROUNDS_P[t - 2]
        return (
            [int(value, 16) for value in reference["C"][t - 2]],
            [[int(value, 16) for value in row] for row in reference["M"][t - 2]],
        )

    monkeypatch.setattr(generator, "generate_parameters", cached_parameters)
    monkeypatch.setattr(generator, "OUTPUT_PATH", str(destination))
    monkeypatch.setattr(sys, "argv", ["generate_poseidon_constants.py", "--verify-only"])
    if changed:
        with pytest.raises(SystemExit, match="VERIFY FAILED: regenerated parameters differ from committed file"):
            generator.main()
        assert "VERIFY OK" not in capsys.readouterr().out
    else:
        generator.main()
        assert "VERIFY OK: regenerated parameters match the committed file" in capsys.readouterr().out
    assert destination.read_bytes() == before
    assert destination.stat().st_mtime_ns == modified_before


@pytest.mark.parametrize("contents,error", [(None, FileNotFoundError), ("{invalid json", json.JSONDecodeError)])
def test_verify_only_does_not_replace_missing_or_malformed_reference(contents, error, tmp_path, monkeypatch):
    destination = tmp_path / "reference.json"
    if contents is not None:
        destination.write_text(contents)
    monkeypatch.setattr(generator, "OUTPUT_PATH", str(destination))
    monkeypatch.setattr(generator, "generate_parameters", lambda t, rounds: ([], []))
    monkeypatch.setattr(sys, "argv", ["generate_poseidon_constants.py", "--verify-only"])
    with pytest.raises(error):
        generator.main()
    if contents is None:
        assert not destination.exists()
    else:
        assert destination.read_text() == contents
