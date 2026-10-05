"""The generator must catch stale files and reject ambiguity without partial writes."""

import copy
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import generate_signal_constants as generator

ROOT = Path(__file__).resolve().parents[2]
SOURCE = json.loads((ROOT / generator.SOURCE).read_text())


@pytest.fixture
def project(tmp_path):
    for relative in (generator.SOURCE, Path("specs/pilot-transfer-v3.md"), Path("docs/internal/CIRCUIT_SIGNALS.md")):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    return tmp_path


def test_committed_outputs_match_source_and_real_cli():
    assert generator.generate(ROOT, check=True) == []
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_signal_constants.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_generation_detects_missing_and_modified_outputs_without_writing(project):
    outputs = generator.render(project)
    missing = generator.generate(project, check=True)
    assert len(missing) == 6
    assert not (project / "src/prover/generated_signals.py").exists()
    assert generator.generate(project, check=False) == missing
    assert generator.generate(project, check=False) == []
    for path, expected in outputs.items():
        target = project / path
        changed = (
            expected.replace("| 0 | projection_commitment", "| 0 | stale_commitment")
            if path.suffix == ".md"
            else expected + "stale-output\n"
        )
        target.write_text(changed)
        assert generator.generate(project, check=True) == [str(path)]
        assert target.read_text() == changed
        assert generator.generate(project, check=False) == [str(path)]
        assert target.read_text() == expected


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {},
        {**SOURCE, "schema_version": True},
        {**SOURCE, "schema_version": 2},
        {**SOURCE, "profile": "pilot-transfer-v2"},
        {**SOURCE, "unexpected": 1},
    ],
)
def test_wrong_version_or_shape_rejects(bad):
    with pytest.raises(ValueError):
        generator.validate(bad)


@pytest.mark.parametrize("key", ["tree_depths", "domain_tags", "limits"])
@pytest.mark.parametrize("bad", [None, [], {}, True, 0, -1, "20", 90000])
def test_invalid_numeric_sections_reject(key, bad):
    data = copy.deepcopy(SOURCE)
    if bad is None or type(bad) is list or type(bad) is dict:
        data[key] = bad
    else:
        data[key][next(iter(data[key]))] = bad
    with pytest.raises(ValueError):
        generator.validate(data)


def test_colliding_domain_tags_reject():
    data = copy.deepcopy(SOURCE)
    data["domain_tags"]["holder"] = data["domain_tags"]["credential"]
    with pytest.raises(ValueError, match="distinct"):
        generator.validate(data)


def test_duplicate_source_keys_reject_before_any_writes(project):
    target = project / generator.SOURCE
    target.write_text(target.read_text().replace('"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'))
    with pytest.raises(ValueError, match="Duplicate JSON"):
        generator.generate(project, check=False)
    assert not (project / "src/prover/generated_signals.py").exists()


def test_reordering_json_object_keys_cannot_reorder_tree_instantiation(project):
    data = copy.deepcopy(SOURCE)
    data["tree_depths"] = {key: data["tree_depths"][key] for key in ("sanctions", "issuer", "issuance")}
    (project / generator.SOURCE).write_text(json.dumps(data))
    generator.generate(project, check=False)
    metadata = json.loads((project / "packages/circuits/pilot-profile.json").read_text())
    assert metadata["template"] == "PilotCompliance(32, 20, 20)"
    assert metadata["treeDepths"] == {"issuance": 32, "authorizedIssuers": 20, "sanctions": 20}


@pytest.mark.parametrize("key", ["public_signals", "projection_fields"])
@pytest.mark.parametrize("bad", [None, {}, [], "short", 7])
def test_invalid_field_inventory_rejects(key, bad):
    data = copy.deepcopy(SOURCE)
    data[key] = bad
    with pytest.raises(ValueError):
        generator.validate(data)


@pytest.mark.parametrize("key", ["public_signals", "projection_fields"])
@pytest.mark.parametrize("bad", [None, [], {}, {"name": "x", "extra": 1}, "not-a-row"])
def test_invalid_field_rows_reject(key, bad):
    data = copy.deepcopy(SOURCE)
    data[key][0] = bad
    with pytest.raises(ValueError):
        generator.validate(data)


@pytest.mark.parametrize("key", ["public_signals", "projection_fields"])
@pytest.mark.parametrize("bad", [None, 1, "", "UpperCase", "has-hyphen", "x\n"])
def test_invalid_names_reject(key, bad):
    data = copy.deepcopy(SOURCE)
    data[key][0]["name"] = bad
    with pytest.raises(ValueError):
        generator.validate(data)


@pytest.mark.parametrize("key", ["public_signals", "projection_fields"])
def test_duplicate_field_names_reject(key):
    data = copy.deepcopy(SOURCE)
    data[key][0]["name"] = data[key][1]["name"]
    with pytest.raises(ValueError, match="Duplicate"):
        generator.validate(data)


@pytest.mark.parametrize("bad", [True, "128", 0, 253])
def test_invalid_width_rejects(bad):
    data = copy.deepcopy(SOURCE)
    data["projection_fields"][0]["bits"] = bad
    with pytest.raises(ValueError, match="bit width"):
        generator.validate(data)


@pytest.mark.parametrize("bad", [None, 1, "", "new\nline", "new\rline", "table|column"])
def test_invalid_meaning_rejects(bad):
    data = copy.deepcopy(SOURCE)
    data["public_signals"][0]["meaning"] = bad
    with pytest.raises(ValueError, match="meaning"):
        generator.validate(data)


@pytest.mark.parametrize(
    "markers",
    [
        "",
        generator.BEGIN,
        generator.END,
        generator.END + generator.BEGIN,
        generator.BEGIN * 2 + generator.END,
        generator.BEGIN + generator.END * 2,
    ],
)
def test_missing_or_ambiguous_markers_never_partially_write(project, markers):
    (project / "docs/internal/CIRCUIT_SIGNALS.md").write_text(markers)
    before = {p: p.read_bytes() for p in project.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="markers"):
        generator.generate(project, check=False)
    assert {p: p.read_bytes() for p in project.rglob("*") if p.is_file()} == before


def test_cli_exit_codes_and_drift_report(project, monkeypatch, capsys):
    monkeypatch.setattr(generator, "ROOT", project)
    assert generator.main(["--check"]) == 1
    assert "src/prover/generated_signals.py" in capsys.readouterr().out
    assert generator.main([]) == 0
    assert "generated" in capsys.readouterr().out
    assert generator.main(["--check"]) == 0
    assert "match" in capsys.readouterr().out
    (project / generator.SOURCE).write_text("{")
    assert generator.main([]) == 2
    assert "failed" in capsys.readouterr().out
    (project / generator.SOURCE).unlink()
    assert generator.main(["--check"]) == 2


def test_script_entrypoint_uses_check_without_mutating_source(monkeypatch):
    path = ROOT / "scripts/generate_signal_constants.py"
    monkeypatch.setattr(sys, "argv", [str(path), "--check"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(path), run_name="__main__")
    assert exc.value.code == 0
