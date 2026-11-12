"""The container entry point reuses verified inputs and never runs acceptance on unverified ones."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "docker/pilot/run-pilot.sh"
STUB_PYTHON = """#!/bin/bash
echo "$@" >> "$CALLS"
case "$1" in
  scripts/test_development_circuits.py) mkdir -p "$2/pilot" || exit 9; exit "${BUILD_EXIT:-0}" ;;
  scripts/test_pilot_local.py) exit "${PILOT_EXIT:-0}" ;;
esac
exit 8
"""


@pytest.fixture
def harness(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("The entry point refuses to run as root")
    commands = tmp_path / "bin"
    commands.mkdir()
    for name in ["id", "date", "mv", "mkdir", "touch", "rm", "echo", "bash"]:
        (commands / name).symlink_to(shutil.which(name))
    data = tmp_path / "data"
    data.mkdir()
    calls = tmp_path / "calls.log"
    calls.touch()
    python = tmp_path / "python"
    python.write_text(STUB_PYTHON)
    python.chmod(0o755)

    def stub(name, body):
        path = commands / name
        path.write_text("#!/bin/bash\n" + body)
        path.chmod(0o755)

    # By default the pinned digest check passes and a download writes its output file.
    stub("sha256sum", "exit ${SHA_EXIT:-0}\n")
    stub("curl", 'echo curl >> "$CALLS"\nwhile [ "$1" != "-o" ]; do shift; done\necho ptau > "$2"\n')

    def run(**env):
        result = subprocess.run(
            ["/bin/bash", str(SCRIPT)],
            cwd=tmp_path,
            env={
                "PATH": str(commands),
                "PILOT_DATA": str(data),
                "PILOT_PYTHON": str(python),
                "POSTGRES_BIN": "/synthetic/postgres/bin",
                "CALLS": str(calls),
                **env,
            },
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result, calls.read_text().splitlines()

    return data, run


def test_first_run_downloads_builds_then_runs_preflight_and_acceptance(harness):
    data, run = harness
    result, calls = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "UNAPPROVED" in result.stdout
    artifacts = data / "development-artifacts"
    assert calls[0] == "curl"
    assert calls[1] == f"scripts/test_development_circuits.py {artifacts} --prepared-ptau {data}/ppot_0080_17.ptau"
    (run_dir,) = (data / "runs").parent.glob("runs")
    preflight, acceptance = calls[2], calls[3]
    assert preflight.endswith("--postgres-bin /synthetic/postgres/bin --preflight")
    assert acceptance + " --preflight" == preflight
    assert acceptance.startswith(f"scripts/test_pilot_local.py {artifacts}/pilot {run_dir}/")
    assert (artifacts / ".complete").is_file() and len(calls) == 4


def test_second_run_reuses_verified_inputs_and_uses_a_new_run_directory(harness):
    data, run = harness
    (data / "ppot_0080_17.ptau").write_text("ptau")
    (data / "development-artifacts/pilot").mkdir(parents=True)
    (data / "development-artifacts/.complete").touch()
    result, calls = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Reusing development artifacts" in result.stdout
    assert [call.split()[0] for call in calls] == ["scripts/test_pilot_local.py"] * 2


def test_interrupted_build_is_set_aside_not_reused(harness):
    data, run = harness
    (data / "ppot_0080_17.ptau").write_text("ptau")
    stale = data / "development-artifacts"
    stale.mkdir()
    (stale / "partial.zkey").write_text("partial")
    result, calls = run()
    assert result.returncode == 0, result.stdout + result.stderr
    (moved,) = data.glob("development-artifacts.incomplete.*")
    assert (moved / "partial.zkey").is_file() and not (stale / "partial.zkey").exists()
    assert calls[0].startswith("scripts/test_development_circuits.py")


def test_digest_mismatch_after_download_stops_before_any_build(harness):
    data, run = harness
    result, calls = run(SHA_EXIT="1")
    assert result.returncode == 1
    assert "does not match its pinned SHA-256" in result.stderr
    assert calls == ["curl"] and not (data / "development-artifacts").exists()


def test_failed_build_is_not_marked_complete_and_acceptance_does_not_run(harness):
    data, run = harness
    result, calls = run(BUILD_EXIT="3")
    assert result.returncode == 3
    assert not (data / "development-artifacts/.complete").exists()
    assert not any(call.startswith("scripts/test_pilot_local.py") for call in calls)


def test_failed_preflight_stops_before_the_acceptance_run(harness):
    data, run = harness
    result, calls = run(PILOT_EXIT="4")
    assert result.returncode == 4
    assert [call for call in calls if call.startswith("scripts/test_pilot_local.py")] == [calls[-1]]
    assert calls[-1].endswith("--preflight") and "Done." not in result.stdout


def test_unwritable_data_directory_is_refused(harness, tmp_path):
    _, run = harness
    result, calls = run(PILOT_DATA=str(tmp_path / "missing"))
    assert result.returncode == 2 and "must be a writable directory" in result.stderr and calls == []
