"""Owned-process orchestration complements actual mirror acceptance runs."""

import io
import runpy
import signal
import subprocess
import sys
import urllib.error
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from scripts import test_pilot_mirror as runner


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    artifacts = tmp_path / "bundle"
    artifacts.mkdir()
    (artifacts / "verification-key.json").write_text("{}")
    (artifacts / "development-manifest-pin.txt").write_text("synthetic-pin")
    output = tmp_path / "private-output"
    monkeypatch.setattr(sys, "argv", [runner.__file__, str(artifacts)])
    monkeypatch.setenv("DATABASE_URL", "synthetic-database")
    monkeypatch.setenv("CLEARPROOF_PILOT_RUN_OUTPUT", "synthetic-inherited-destination")
    node = Mock(pid=987654310)
    node.poll.return_value = None
    node.wait.return_value = 0
    tests = Mock(pid=987654311)
    tests.wait.return_value = 0
    processes = Mock(side_effect=[node, tests])
    doctor, finish, kill = Mock(), Mock(), Mock()
    response = Mock(return_value=io.BytesIO(b'{"result":"0x7a69"}'))
    clock = SimpleNamespace(monotonic=Mock(return_value=0), sleep=Mock())
    monkeypatch.setattr(runner.subprocess, "Popen", processes)
    monkeypatch.setattr(runner, "check_doctor", doctor)
    monkeypatch.setattr(runner, "finish_outputs", finish)
    monkeypatch.setattr(runner.os, "killpg", kill)
    monkeypatch.setattr(runner.urllib.request, "urlopen", response)
    monkeypatch.setattr(runner, "time", clock)
    return SimpleNamespace(
        artifacts=artifacts, output=output, node=node, tests=tests, processes=processes,
        doctor=doctor, finish=finish, kill=kill, response=response, clock=clock,
    )


@pytest.mark.parametrize("retain", [False, True])
def test_success_scopes_child_environment_and_cleans_both_processes(boundary, monkeypatch, retain):
    if retain:
        monkeypatch.setattr(sys, "argv", [*sys.argv, "--output", str(boundary.output)])
    assert runner.main() == 0
    boundary.doctor.assert_called_once_with(boundary.artifacts)
    assert boundary.processes.call_count == 2
    node_call, tests_call = boundary.processes.call_args_list
    for invocation in (node_call, tests_call):
        assert invocation.kwargs["start_new_session"] is True
        env = invocation.kwargs["env"]
        assert env["CLEARPROOF_MIRROR_TEST_RPC"].startswith("http://127.0.0.1:")
        assert env["CLEARPROOF_POLICY_CLI_TEST"] == "1"
        assert env["CLEARPROOF_PILOT_TEST_ARTIFACTS"] == str(boundary.artifacts)
        if retain:
            assert env["CLEARPROOF_PILOT_RUN_OUTPUT"] == str(boundary.output)
        else:
            assert "CLEARPROOF_PILOT_RUN_OUTPUT" not in env
    assert runner.os.environ["CLEARPROOF_PILOT_RUN_OUTPUT"] == "synthetic-inherited-destination"
    assert node_call.kwargs["stdout"].closed
    assert tests_call.args[0][-2:] == ["-q", "--tb=short"]
    assert boundary.tests.wait.call_args_list == [call(timeout=420), call()]
    assert boundary.kill.call_args_list == [
        call(boundary.tests.pid, signal.SIGKILL), call(boundary.node.pid, signal.SIGKILL),
    ]
    if retain:
        for directory in (boundary.output, boundary.output / "reports", boundary.output / "private"):
            assert directory.stat().st_mode & 0o777 == 0o700
        boundary.finish.assert_called_once_with(boundary.output, boundary.artifacts)
    else:
        boundary.finish.assert_not_called()


def test_missing_database_rejects_executable_entry_before_launch(boundary, monkeypatch):
    monkeypatch.delenv("DATABASE_URL")
    with pytest.raises(SystemExit) as result:
        runpy.run_path(runner.__file__, run_name="__main__")
    assert result.value.code == 2
    boundary.processes.assert_not_called()


@pytest.mark.parametrize("filename", ["verification-key.json", "development-manifest-pin.txt"])
def test_incomplete_artifacts_are_rejected_before_doctor_or_evm(boundary, filename):
    (boundary.artifacts / filename).unlink()
    with pytest.raises(SystemExit) as result:
        runner.main()
    assert result.value.code == 2
    boundary.doctor.assert_not_called()
    boundary.processes.assert_not_called()


def test_doctor_failure_prevents_process_launch(boundary):
    boundary.doctor.side_effect = RuntimeError("synthetic invalid artifacts")
    with pytest.raises(RuntimeError, match="synthetic invalid artifacts"):
        runner.main()
    boundary.processes.assert_not_called()


def test_existing_output_is_not_reused(boundary, monkeypatch):
    boundary.output.mkdir()
    marker = boundary.output / "existing"
    marker.write_text("preserve")
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--output", str(boundary.output)])
    with pytest.raises(FileExistsError):
        runner.main()
    assert marker.read_text() == "preserve"
    boundary.processes.assert_not_called()


@pytest.mark.parametrize("failure", [urllib.error.URLError("synthetic refused"), TimeoutError("synthetic timeout")])
def test_readiness_retries_then_runs_tests(boundary, failure):
    boundary.response.side_effect = [failure, io.BytesIO(b'{"result":"0x7a69"}')]
    assert runner.main() == 0
    assert boundary.response.call_count == 2
    boundary.clock.sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize("failure", ["exited", "wrong_chain", "deadline"])
def test_readiness_failure_stops_node_without_launching_pytest(boundary, failure):
    if failure == "exited":
        boundary.node.poll.return_value = 1
        message = "Owned local EVM exited before readiness"
    elif failure == "wrong_chain":
        boundary.response.return_value = io.BytesIO(b'{"result":"0x1"}')
        message = "Local EVM has an unexpected chain ID"
    else:
        boundary.response.side_effect = urllib.error.URLError("synthetic refused")
        boundary.clock.monotonic.side_effect = [0, 31]
        message = "Owned local EVM did not become ready"
    with pytest.raises(RuntimeError, match=message):
        runner.main()
    assert boundary.processes.call_count == 1
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGKILL)
    boundary.node.wait.assert_called_once_with()


def test_failed_test_status_does_not_publish_success_manifest(boundary, monkeypatch):
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--output", str(boundary.output)])
    boundary.tests.wait.return_value = 7
    assert runner.main() == 7
    boundary.finish.assert_not_called()
    assert boundary.kill.call_count == 2


def test_test_launch_failure_cleans_existing_evm(boundary):
    boundary.processes.side_effect = [boundary.node, OSError("synthetic child launch failure")]
    with pytest.raises(OSError, match="synthetic child launch failure"):
        runner.main()
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGKILL)


def test_test_timeout_kills_and_reaps_both_children(boundary):
    boundary.tests.wait.side_effect = [subprocess.TimeoutExpired("synthetic tests", 420), 0]
    with pytest.raises(subprocess.TimeoutExpired):
        runner.main()
    assert boundary.kill.call_count == 2
    boundary.node.wait.assert_called_once_with()
    assert boundary.tests.wait.call_args_list == [call(timeout=420), call()]


def test_cleanup_tolerates_an_already_exited_process_group(boundary):
    boundary.kill.side_effect = [ProcessLookupError(), None]
    assert runner.main() == 0
    assert boundary.kill.call_count == 2
    boundary.node.wait.assert_called_once_with()


def test_report_finalization_failure_still_reaps_children(boundary, monkeypatch):
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--output", str(boundary.output)])
    boundary.finish.side_effect = RuntimeError("synthetic report failure")
    with pytest.raises(RuntimeError, match="synthetic report failure"):
        runner.main()
    assert boundary.kill.call_count == 2
    boundary.node.wait.assert_called_once_with()
