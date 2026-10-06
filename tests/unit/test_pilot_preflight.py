# SPDX-License-Identifier: Apache-2.0
"""Preflight checks the selected interpreter/toolchain before owned services."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import test_pilot_local as runner
from scripts import test_pilot_mirror as mirror


@pytest.fixture
def setup(tmp_path, monkeypatch):
    cli = tmp_path / "packages/cli/dist/index.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("synthetic built CLI marker")
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    modules = Mock(return_value=object())
    monkeypatch.setattr(runner.importlib.util, "find_spec", modules)
    node = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(runner.subprocess, "run", node)
    doctor = Mock()
    monkeypatch.setattr(mirror, "check_doctor", doctor)
    return SimpleNamespace(cli=cli, modules=modules, node=node, doctor=doctor, artifacts=tmp_path / "artifacts")


def test_preflight_uses_bounded_node_and_complete_doctor_checks(setup):
    runner.check_prerequisites(setup.artifacts)
    assert setup.modules.call_count == 5
    command, kwargs = setup.node.call_args
    assert command[0][:2] == ["node", "-e"]
    assert "major < 22" in command[0][2] and "minor < 12" in command[0][2]
    assert "require.resolve('hardhat'" in command[0][2]
    assert kwargs["timeout"] == 10 and kwargs["capture_output"] is True
    setup.doctor.assert_called_once_with(setup.artifacts)


def test_old_python_fails_before_dependencies(setup, monkeypatch):
    monkeypatch.setattr(runner.sys, "version_info", (3, 10))
    with pytest.raises(RuntimeError, match="Python 3.11"):
        runner.check_prerequisites(setup.artifacts)
    setup.modules.assert_not_called()
    setup.node.assert_not_called()


@pytest.mark.parametrize("missing", ["pytest", "pytest_asyncio", "psycopg", "cryptography", "web3"])
def test_missing_python_dependency_stops_before_node(setup, missing):
    setup.modules.side_effect = lambda name: None if name == missing else object()
    with pytest.raises(RuntimeError, match="locked Python"):
        runner.check_prerequisites(setup.artifacts)
    setup.node.assert_not_called()


def test_missing_built_cli_stops_before_node(setup):
    setup.cli.unlink()
    with pytest.raises(RuntimeError, match="Build the CLI"):
        runner.check_prerequisites(setup.artifacts)
    setup.node.assert_not_called()


def test_bad_node_or_hardhat_result_does_not_invoke_doctor(setup):
    setup.node.return_value.returncode = 1
    with pytest.raises(RuntimeError, match="Node 22.12"):
        runner.check_prerequisites(setup.artifacts)
    setup.doctor.assert_not_called()


def test_doctor_failure_is_not_converted_to_success(setup):
    setup.doctor.side_effect = RuntimeError("Synthetic incomplete bundle")
    with pytest.raises(RuntimeError, match="incomplete bundle"):
        runner.check_prerequisites(setup.artifacts)
