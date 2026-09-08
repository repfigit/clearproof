"""Checkpoint orchestration failures complement the separate real-EVM test."""

import io
import runpy
import signal
import subprocess
import urllib.error
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from scripts import test_checkpoint_evm as runner


@pytest.fixture
def boundary(monkeypatch):
    node = Mock(pid=987654321)
    node.poll.return_value = None
    node.wait.return_value = 0
    processes = Mock(return_value=node)
    commands = []

    def run(args, **kwargs):
        commands.append((args, kwargs))
        return SimpleNamespace(stdout="/synthetic/hardhat-cli.js\n", returncode=0)

    run_command = Mock(side_effect=run)
    response = Mock(return_value=io.BytesIO(b'{"result":"0x7a69"}'))
    kill = Mock()
    clock = SimpleNamespace(monotonic=Mock(return_value=0), sleep=Mock())
    monkeypatch.setattr(runner.subprocess, "run", run_command)
    monkeypatch.setattr(runner.subprocess, "Popen", processes)
    monkeypatch.setattr(runner.urllib.request, "urlopen", response)
    monkeypatch.setattr(runner.os, "killpg", kill)
    monkeypatch.setattr(runner, "time", clock)
    return SimpleNamespace(
        node=node, processes=processes, commands=commands, run=run_command,
        response=response, kill=kill, clock=clock,
    )


def test_success_scopes_rpc_to_child_and_terminates_only_owned_group(boundary, monkeypatch):
    monkeypatch.setenv("CHECKPOINT_TEST_RPC", "http://synthetic-existing.invalid")
    assert runner.main() == 0
    assert len(boundary.commands) == 3
    resolution, compile_command, tests = boundary.commands
    assert "require.resolve('hardhat/internal/cli/cli.js')" in resolution[0]
    assert compile_command[0] == ["node", "/synthetic/hardhat-cli.js", "compile"]
    assert tests[0][-2:] == ["tests/integration/test_pilot_checkpoint.py", "-q"]
    url = tests[1]["env"]["CHECKPOINT_TEST_RPC"]
    assert url.startswith("http://127.0.0.1:") and not url.endswith(":0")
    assert runner.os.environ["CHECKPOINT_TEST_RPC"] == "http://synthetic-existing.invalid"
    assert boundary.response.call_args.args[0].full_url == url
    assert boundary.processes.call_args.kwargs["start_new_session"] is True
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGTERM)
    boundary.node.wait.assert_called_once_with(timeout=5)


def test_test_failure_status_is_preserved_and_node_is_stopped(boundary):
    boundary.run.side_effect = [SimpleNamespace(stdout="cli"), SimpleNamespace(), SimpleNamespace(returncode=7)]
    assert runner.main() == 7
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGTERM)


def test_compile_failure_does_not_launch_a_node(boundary):
    error = subprocess.CalledProcessError(2, ["node", "cli", "compile"])
    boundary.run.side_effect = [SimpleNamespace(stdout="cli"), error]
    with pytest.raises(subprocess.CalledProcessError) as caught:
        runner.main()
    assert caught.value is error
    boundary.processes.assert_not_called()
    boundary.kill.assert_not_called()


def test_exited_node_is_not_signalled_and_tests_do_not_run(boundary):
    boundary.node.poll.return_value = 1
    with pytest.raises(RuntimeError, match="Owned Hardhat node exited during startup"):
        runner.main()
    assert len(boundary.commands) == 2
    boundary.response.assert_not_called()
    boundary.kill.assert_not_called()


@pytest.mark.parametrize("failure", [urllib.error.URLError("synthetic refused"), TimeoutError("synthetic timeout")])
def test_readiness_retries_transient_errors_then_runs_tests(boundary, failure):
    boundary.response.side_effect = [failure, io.BytesIO(b'{"result":"0x7a69"}')]
    assert runner.main() == 0
    assert boundary.response.call_count == 2
    boundary.clock.sleep.assert_called_once_with(0.1)


def test_readiness_deadline_stops_node_without_running_tests(boundary):
    boundary.clock.monotonic.side_effect = [0, 0, 31]
    boundary.response.side_effect = urllib.error.URLError("synthetic refused")
    with pytest.raises(RuntimeError, match="Owned Hardhat node did not become ready"):
        runner.main()
    assert len(boundary.commands) == 2
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGTERM)


def test_wrong_chain_is_rejected_and_cleaned_up(boundary):
    boundary.response.return_value = io.BytesIO(b'{"result":"0x1"}')
    with pytest.raises(AssertionError):
        runner.main()
    assert len(boundary.commands) == 2
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGTERM)


def test_stubborn_node_is_killed_after_grace_period(boundary):
    boundary.node.wait.side_effect = [subprocess.TimeoutExpired("synthetic node", 5), 0]
    assert runner.main() == 0
    assert boundary.kill.call_args_list == [
        call(boundary.node.pid, signal.SIGTERM), call(boundary.node.pid, signal.SIGKILL),
    ]
    assert boundary.node.wait.call_args_list == [call(timeout=5), call()]


def test_child_launch_exception_still_stops_owned_node(boundary):
    error = OSError("synthetic pytest launch failure")
    boundary.run.side_effect = [SimpleNamespace(stdout="cli"), SimpleNamespace(), error]
    with pytest.raises(OSError) as caught:
        runner.main()
    assert caught.value is error
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGTERM)


def test_executable_entry_returns_runner_status(boundary):
    with pytest.raises(SystemExit) as result:
        runpy.run_path(runner.__file__, run_name="__main__")
    assert result.value.code == 0
    boundary.kill.assert_called_once_with(boundary.node.pid, signal.SIGTERM)
