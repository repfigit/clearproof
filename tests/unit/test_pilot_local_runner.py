"""Local acceptance orchestration owns only its private PostgreSQL cluster."""

import contextlib
import runpy
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from psycopg.conninfo import conninfo_to_dict

from scripts import test_pilot_local as runner


@pytest.fixture
def setup(tmp_path, monkeypatch):
    binaries = tmp_path / "pg-bin"
    binaries.mkdir()
    for name in ("initdb", "pg_ctl", "createdb"):
        executable = binaries / name
        executable.write_text("synthetic executable boundary")
        executable.chmod(0o700)
    artifacts = tmp_path / "pilot-artifacts"
    artifacts.mkdir()
    output = tmp_path / "private run"
    monkeypatch.setattr(sys, "argv", [runner.__file__, str(artifacts), str(output), "--postgres-bin", str(binaries)])
    version = Mock(return_value="initdb (PostgreSQL) 18.3\n")
    monkeypatch.setattr(runner.subprocess, "check_output", version)
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs))
        if Path(command[0]).name == "initdb":
            (output / "postgres").mkdir()
        return SimpleNamespace(returncode=0)

    execute = Mock(side_effect=run)
    monkeypatch.setattr(runner.subprocess, "run", execute)
    return SimpleNamespace(
        binaries=binaries, artifacts=artifacts, output=output,
        version=version, execute=execute, commands=commands, run=run,
    )


def test_success_uses_private_socket_rejects_tcp_and_stops_cluster(setup, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "synthetic-parent-connection")
    assert runner.main() == 0
    assert setup.output.stat().st_mode & 0o777 == 0o700
    assert len(setup.commands) == 5
    initialize, start, create, child, stop = setup.commands
    assert "--auth-local=trust" in initialize[0] and "--auth-host=reject" in initialize[0]
    options = shlex.split(start[0][start[0].index("-o") + 1])
    assert options[options.index("-h") + 1] == ""
    socket_dir = options[options.index("-k") + 1]
    assert create[0][create[0].index("-h") + 1] == socket_dir
    connection = conninfo_to_dict(child[1]["env"]["DATABASE_URL"])
    assert connection == {"host": socket_dir, "port": "5432", "dbname": "clearproof_test"}
    assert runner.os.environ["DATABASE_URL"] == "synthetic-parent-connection"
    assert child[0][-2:] == ["--output", str(setup.output / "pilot")]
    assert stop[0][-4:] == ["-m", "immediate", "-w", "stop"]
    assert not Path(socket_dir).exists()


@pytest.mark.parametrize("name", ["initdb", "pg_ctl", "createdb"])
@pytest.mark.parametrize("missing", [False, True])
def test_missing_or_nonexecutable_postgres_is_rejected_before_output(setup, name, missing):
    executable = setup.binaries / name
    if missing:
        executable.unlink()
    else:
        executable.chmod(0o600)
    with pytest.raises(SystemExit) as result:
        runner.main()
    assert result.value.code == 2
    assert not setup.output.exists()
    setup.version.assert_not_called()
    setup.execute.assert_not_called()


def test_missing_artifacts_are_rejected_before_cluster_creation(setup):
    setup.artifacts.rmdir()
    with pytest.raises(FileNotFoundError):
        runner.main()
    setup.execute.assert_not_called()
    assert not setup.output.exists()


def test_wrong_postgres_version_is_rejected_before_output(setup):
    setup.version.return_value = "initdb (PostgreSQL) 17.9\n"
    with pytest.raises(SystemExit) as result:
        runner.main()
    assert result.value.code == 2
    assert not setup.output.exists()
    setup.execute.assert_not_called()


def test_existing_output_is_not_reused(setup):
    setup.output.mkdir()
    marker = setup.output / "existing"
    marker.write_text("preserve")
    with pytest.raises(FileExistsError):
        runner.main()
    assert marker.read_text() == "preserve"
    setup.execute.assert_not_called()


def test_overlong_socket_directory_fails_before_initdb(setup, monkeypatch):
    monkeypatch.setattr(runner.tempfile, "TemporaryDirectory", lambda **kwargs: contextlib.nullcontext("/" + "x" * 81))
    with pytest.raises(ValueError, match="Select a shorter TMPDIR"):
        runner.main()
    setup.execute.assert_not_called()


@pytest.mark.parametrize("stage", ["start", "createdb", "child"])
def test_failure_after_initialization_always_attempts_stop(setup, stage):
    error = subprocess.CalledProcessError(7, ["synthetic failure"])

    def fail(command, **kwargs):
        setup.run(command, **kwargs)
        is_stage = (
            stage == "start" and command[-1] == "start"
            or stage == "createdb" and Path(command[0]).name == "createdb"
            or stage == "child" and "--output" in command
        )
        if is_stage:
            raise error
        return SimpleNamespace(returncode=0)

    setup.execute.side_effect = fail
    with pytest.raises(subprocess.CalledProcessError) as caught:
        runner.main()
    assert caught.value is error
    assert setup.commands[-1][0][-1] == "stop"


@pytest.mark.parametrize("pid_exists", [False, True])
def test_failed_stop_only_overrides_child_status_when_cluster_may_remain(setup, pid_exists):
    def run(command, **kwargs):
        setup.run(command, **kwargs)
        if command[-1] == "stop":
            if pid_exists:
                (setup.output / "postgres/postmaster.pid").write_text("synthetic marker")
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=7 if "--output" in command else 0)

    setup.execute.side_effect = run
    if pid_exists:
        with pytest.raises(RuntimeError, match="Owned PostgreSQL cluster did not stop"):
            runner.main()
    else:
        assert runner.main() == 7


def test_executable_entry_preserves_success_status(setup):
    with pytest.raises(SystemExit) as result:
        runpy.run_path(runner.__file__, run_name="__main__")
    assert result.value.code == 0
    assert setup.commands[-1][0][-1] == "stop"
