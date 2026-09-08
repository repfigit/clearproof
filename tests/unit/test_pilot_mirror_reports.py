"""Doctor acceptance and retained report integrity, separate from EVM tests."""

import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import test_pilot_mirror as runner


@pytest.fixture
def artifacts(tmp_path):
    directory = tmp_path / "artifacts"
    directory.mkdir(exist_ok=True)
    (directory / "development-manifest-pin.txt").write_text("synthetic-pin\n")
    return directory


def doctor_report(mode):
    if mode == "production":
        return {"production_eligible": False, "reason": "development_artifacts_forbidden"}
    return {
        "production_eligible": False, "status": "development_unapproved", "manifest_digest": "synthetic-pin",
        "current_profile_supported": True, "policy_schema_supported": True,
    }


def test_doctor_requires_development_success_and_production_rejection(artifacts, monkeypatch):
    def respond(command, **kwargs):
        mode = command[-1]
        assert command[-2] == "--mode"
        assert command[command.index("--trusted-manifest-digest") + 1] == "synthetic-pin"
        assert kwargs["timeout"] == 125
        return SimpleNamespace(
            returncode=1 if mode == "production" else 0, stderr="", stdout=json.dumps(doctor_report(mode))
        )

    command = Mock(side_effect=respond)
    monkeypatch.setattr(runner.subprocess, "run", command)
    runner.check_doctor(artifacts)
    assert command.call_count == 2


@pytest.mark.parametrize(
    "failure", ["exit", "stderr", "eligible", "status", "pin", "profile", "policy", "production_reason"]
)
def test_doctor_rejects_incorrect_assurance_or_process_results(artifacts, monkeypatch, failure):
    def respond(command, **kwargs):
        mode = command[-1]
        report = doctor_report(mode)
        if mode == "development":
            mutations = {
                "eligible": ("production_eligible", True), "status": ("status", "production"),
                "pin": ("manifest_digest", "wrong"), "profile": ("current_profile_supported", False),
                "policy": ("policy_schema_supported", False),
            }
            if failure in mutations:
                key, value = mutations[failure]
                report[key] = value
        elif failure == "production_reason":
            report["reason"] = "unknown"
        return SimpleNamespace(
            returncode=9 if failure == "exit" else (1 if mode == "production" else 0),
            stderr="synthetic warning" if failure == "stderr" else "", stdout=json.dumps(report),
        )

    monkeypatch.setattr(runner.subprocess, "run", respond)
    with pytest.raises(RuntimeError, match="Artifact doctor|Built artifact doctor"):
        runner.check_doctor(artifacts)


REPORTS = (
    "policy-comparison.json", "history.encrypted.json", "reviewer-trust.json", "history-report.json",
    "history-clock.json", "observation-cohort.json", "observations.json", "investigation.json",
    "counterparty-scenarios.json",
)


@pytest.fixture
def reports(tmp_path):
    output = tmp_path / "run"
    (output / "reports").mkdir(parents=True)
    (output / "private").mkdir()
    (output / "private/reviewer-key.json").write_text('{"synthetic":"private placeholder"}')
    for name in REPORTS:
        (output / "reports" / name).write_text(json.dumps({"synthetic": name}))
    return output


def test_report_manifest_hashes_every_report_and_never_includes_private_contents(reports, artifacts):
    runner.finish_outputs(reports, artifacts)
    path = reports / "run.json"
    manifest = json.loads(path.read_text())
    assert path.stat().st_mode & 0o777 == 0o600
    assert manifest["assurance"] == "development-unapproved"
    assert manifest["clean_environment"] == "not-established"
    assert manifest["artifact_manifest_pin"] == "synthetic-pin"
    assert "private placeholder" not in path.read_text()
    assert [row["path"] for row in manifest["reports"]] == ["reports/" + name for name in sorted(REPORTS)]
    for row in manifest["reports"]:
        content = (reports / row["path"]).read_bytes()
        assert row["bytes"] == len(content)
        assert row["sha256"] == hashlib.sha256(content).hexdigest()
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        runner.finish_outputs(reports, artifacts)
    assert path.read_bytes() == before


@pytest.mark.parametrize("failure", ["missing", "extra", "key", "invalid_json"])
def test_invalid_report_inventory_does_not_publish_success_manifest(reports, artifacts, failure):
    if failure == "missing":
        (reports / "reports" / REPORTS[0]).unlink()
    elif failure == "extra":
        (reports / "reports/unexpected.json").write_text("{}")
    elif failure == "key":
        (reports / "private/reviewer-key.json").unlink()
    else:
        (reports / "reports" / REPORTS[0]).write_text("{invalid")
    with pytest.raises((RuntimeError, json.JSONDecodeError)):
        runner.finish_outputs(reports, artifacts)
    assert not (reports / "run.json").exists()
