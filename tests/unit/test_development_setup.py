"""Development setup preconditions and isolated phase-one orchestration."""

import hashlib
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import test_development_circuits as runner


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / "synthetic-repo"
    root.mkdir()
    output = tmp_path / "new-output"
    monkeypatch.setattr(runner, "ROOT", root)
    monkeypatch.setattr(sys, "argv", [runner.__file__, str(output)])
    return root, output


@pytest.mark.parametrize("missing", ["node", "circom"])
def test_missing_tools_stop_before_setup_commands(setup, monkeypatch, missing):
    root, output = setup
    monkeypatch.setattr(runner.shutil, "which", lambda name: None if name == missing else f"/synthetic/{name}")
    command = Mock()
    monkeypatch.setattr(runner, "run", command)
    with pytest.raises(SystemExit, match="Node and Circom must be installed"):
        runner.main()
    command.assert_not_called()
    assert not (output / "DEVELOPMENT-ONLY.txt").exists()


def test_missing_repository_dependencies_stop_before_setup(setup, monkeypatch):
    _, output = setup
    monkeypatch.setattr(runner.shutil, "which", lambda name: f"/synthetic/{name}")
    command = Mock()
    monkeypatch.setattr(runner, "run", command)
    with pytest.raises(SystemExit, match="Install the repository dependencies before running"):
        runner.main()
    command.assert_not_called()
    assert not (output / "DEVELOPMENT-ONLY.txt").exists()


@pytest.mark.parametrize("kind", ["directory", "symlink", "dangling_symlink"])
def test_existing_output_including_symlinks_is_never_reused(setup, monkeypatch, kind):
    root, output = setup
    target = root / "existing-target"
    if kind == "directory":
        output.mkdir()
    else:
        if kind == "symlink":
            target.mkdir()
        output.symlink_to(target, target_is_directory=True)
    tools = Mock(return_value=None)
    monkeypatch.setattr(runner.shutil, "which", tools)
    with pytest.raises(FileExistsError):
        runner.main()
    tools.assert_not_called()
    if kind == "dangling_symlink":
        assert not target.exists()


@pytest.mark.parametrize("prepared", [False, True])
def test_phase_one_sequence_is_unapproved_hashed_and_intermediates_removed(setup, monkeypatch, prepared):
    root, output = setup
    cli = root / "node_modules/snarkjs/build/cli.cjs"
    cli.parent.mkdir(parents=True)
    cli.write_text("synthetic tool boundary")
    if prepared:
        source = root / "explicit-local.ptau"
        source.write_bytes(b"synthetic prepared parameters")
        monkeypatch.setattr(sys, "argv", [*sys.argv, "--prepared-ptau", str(source)])
    monkeypatch.setattr(runner.shutil, "which", lambda name: f"/synthetic/{name}")
    commands = []

    def run(*args, **kwargs):
        commands.append((args, kwargs))
        if args[0] == "/synthetic/circom":
            raise RuntimeError("stop at real compiler boundary")
        if args[3] == "new":
            Path(args[-1]).write_bytes(b"synthetic initial parameters")
        elif args[3] == "contribute":
            Path(args[5]).write_bytes(b"synthetic contributed parameters")
        else:
            assert args[3:5] == ("prepare", "phase2")
            assert kwargs["timeout"] == 5400
            Path(args[6]).write_bytes(b"synthetic prepared parameters")

    monkeypatch.setattr(runner, "run", run)
    with pytest.raises(RuntimeError, match="stop at real compiler boundary"):
        runner.main()
    if prepared:
        assert len(commands) == 1
        assert source.read_bytes() == b"synthetic prepared parameters"
    else:
        assert [args[3] for args, _ in commands[:3]] == ["new", "contribute", "prepare"]
    assert not (output / "UNAPPROVED-initial.ptau").exists()
    assert not (output / "UNAPPROVED-contributed.ptau").exists()
    expected_digest = hashlib.sha256(b"synthetic prepared parameters").hexdigest()
    assert (output / "ptau-sha256.txt").read_text().strip() == expected_digest
    assert "UNAPPROVED development keys" in (output / "DEVELOPMENT-ONLY.txt").read_text()
