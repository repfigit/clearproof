"""Legacy verification must honor the CLI result and own its child process."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.prover import verifier


@pytest.mark.parametrize("returncode,stdout,expected", [(1, b"NOT OK", False), (0, b"", True), (1, b"", False)])
async def test_cli_exit_status_is_authoritative(tmp_path, monkeypatch, returncode, stdout, expected):
    key = tmp_path / "key.json"
    key.write_text("{}")
    captured = []

    async def spawn(*args, **kwargs):
        public, proof = map(Path, args[-2:])
        captured.extend((public, proof))
        assert json.loads(public.read_text()) == ["1"]
        assert json.loads(proof.read_text()) == {"pi_a": ["2"]}
        return SimpleNamespace(returncode=returncode, communicate=AsyncMock(return_value=(stdout, b"")))

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    assert await verifier.verify_proof({"pi_a": ["2"], "_meta": {}}, ["1"], str(key)) is expected
    assert all(not path.exists() for path in captured)


async def test_missing_key(tmp_path):
    with pytest.raises(FileNotFoundError, match="Verification key"):
        await verifier.verify_proof({}, [], str(tmp_path / "absent"))


@pytest.mark.parametrize("cancel", [False, True])
async def test_real_child_is_reaped_before_temporary_files_removed(tmp_path, monkeypatch, cancel):
    import sys

    key = tmp_path / "key.json"
    key.write_text("{}")
    original_spawn = asyncio.create_subprocess_exec
    started = asyncio.Event()
    processes = []
    files = []

    async def spawn(*args, **kwargs):
        files.extend(map(Path, args[-2:]))
        child = await original_spawn(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)
        processes.append(child)
        started.set()
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    task = asyncio.create_task(verifier.verify_proof({}, [], str(key), timeout=0.1 if not cancel else 60))
    await asyncio.wait_for(started.wait(), timeout=5)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        assert await task is False
    assert processes[0].returncode is not None
    assert all(not path.exists() for path in files)


async def test_spawn_failure_cleans_temporary_files(tmp_path, monkeypatch):
    key = tmp_path / "key.json"
    key.write_text("{}")
    files = []

    async def spawn(*args, **kwargs):
        files.extend(map(Path, args[-2:]))
        raise FileNotFoundError("npx unavailable")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(FileNotFoundError, match="npx unavailable"):
        await verifier.verify_proof({}, [], str(key))
    assert all(not path.exists() for path in files)


async def test_prover_verification_needs_only_verification_key(tmp_path, monkeypatch):
    from src.prover.snarkjs_prover import SnarkJSProver

    key = tmp_path / "verification_key.json"
    key.write_text("{}")
    spawn = AsyncMock(return_value=SimpleNamespace(returncode=1, communicate=AsyncMock(return_value=(b"OK", b""))))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    prover = SnarkJSProver(artifacts_dir=str(tmp_path))
    assert await prover.verify({}, []) is False
    assert spawn.await_args.args[:4] == ("npx", "--no-install", "snarkjs", "groth16")
