"""Proof generation owns temporary witness files and sanitizes tool failures."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.prover.snarkjs_prover import ProverError, SnarkJSProver


@pytest.fixture
def prover(tmp_path):
    instance = SnarkJSProver(artifacts_dir=str(tmp_path))
    for path in (instance.wasm_path, instance.zkey_path, instance.vkey_path, instance.witness_js):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
    return instance


@pytest.mark.parametrize("stage", ["witness", "proof"])
async def test_tool_failure_does_not_expose_private_input(prover, monkeypatch, stage):
    calls = []

    async def spawn(*args, **kwargs):
        calls.append(args)
        code = 1 if stage == "witness" or len(calls) == 2 else 0
        return SimpleNamespace(returncode=code, communicate=AsyncMock(return_value=(b"", b"synthetic-secret-input")))

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(ProverError) as error:
        await prover.fullprove({"secret": "synthetic-secret-input"})
    assert "synthetic-secret-input" not in str(error.value)
    assert len(calls) == (1 if stage == "witness" else 2)
    assert not Path(calls[0][-2]).exists()
    assert not Path(calls[0][-1]).exists()


async def test_success_uses_private_directory_and_returns_proof(prover, monkeypatch):
    calls = []

    async def spawn(*args, **kwargs):
        calls.append(args)
        if args[0] == "node":
            input_path, witness = map(Path, args[-2:])
            assert json.loads(input_path.read_text()) == {"amount": "42"}
            assert input_path.parent.stat().st_mode & 0o077 == 0
            witness.write_bytes(b"synthetic witness")
        else:
            assert args[:5] == ("npx", "--no-install", "snarkjs", "groth16", "prove")
            witness, proof, public = map(Path, args[-3:])
            assert witness.read_bytes() == b"synthetic witness"
            proof.write_text('{"pi_a": ["1"]}')
            public.write_text('["42"]')
        return SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"", b"")))

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    proof, public = await prover.fullprove({"amount": "42"})
    assert proof["pi_a"] == ["1"]
    assert proof["_meta"]["proving_time_ms"] >= 0
    assert public == ["42"]
    assert not Path(calls[0][-2]).parent.exists()


@pytest.mark.parametrize("stage", ["witness", "proof"])
@pytest.mark.parametrize("cancel", [False, True])
async def test_real_child_cleanup_at_each_stage(prover, monkeypatch, stage, cancel):
    import sys

    original_spawn = asyncio.create_subprocess_exec
    entered = asyncio.Event()
    children = []
    files = []
    prover.witness_timeout = prover.prove_timeout = 60 if cancel else 0.1

    async def spawn(*args, **kwargs):
        if args[0] == "node":
            files.extend(map(Path, args[-2:]))
            if stage == "proof":
                files[-1].write_bytes(b"witness")
                return SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"", b"")))
        child = await original_spawn(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)
        children.append(child)
        entered.set()
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    task = asyncio.create_task(prover.fullprove({}))
    await asyncio.wait_for(entered.wait(), timeout=5)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(ProverError, match="timed out"):
            await task
    assert children[0].returncode is not None
    assert not files[0].parent.exists()


@pytest.mark.parametrize("attribute", ["wasm_path", "zkey_path", "vkey_path"])
async def test_missing_artifact_rejected_before_spawn(prover, monkeypatch, attribute):
    getattr(prover, attribute).unlink()
    spawn = AsyncMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(FileNotFoundError, match="not found"):
        await prover.fullprove({})
    spawn.assert_not_called()


async def test_invalid_output_cleans_files(prover, monkeypatch):
    files = []

    async def spawn(*args, **kwargs):
        if args[0] == "node":
            files.append(Path(args[-2]))
        else:
            Path(args[-2]).write_text("invalid JSON")
        return SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"", b"")))

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(json.JSONDecodeError):
        await prover.fullprove({})
    assert not files[0].parent.exists()
