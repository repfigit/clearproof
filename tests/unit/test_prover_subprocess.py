"""Process ownership includes cancellation during creation and platform cleanup."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.prover import _subprocess as module


@pytest.mark.parametrize("grouped,already_exited", [(False, False), (True, True)])
async def test_cleanup_platform_and_exit_race(monkeypatch, grouped, already_exited):
    proc = SimpleNamespace(
        pid=123,
        returncode=None,
        communicate=AsyncMock(side_effect=TimeoutError),
        wait=AsyncMock(),
        kill=Mock(),
    )
    killpg = Mock(side_effect=ProcessLookupError if already_exited else None)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix" if grouped else "nt", killpg=killpg))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
    with pytest.raises(TimeoutError):
        await module.run_tool("local-tool", timeout=1)
    proc.wait.assert_awaited_once()
    if grouped:
        killpg.assert_called_once()
    else:
        proc.kill.assert_called_once()


async def test_cancellation_during_creation_retains_child_ownership(monkeypatch):
    entered = asyncio.Event()
    release = asyncio.Event()
    proc = SimpleNamespace(returncode=None, kill=Mock(), wait=AsyncMock())

    async def spawn(*args, **kwargs):
        entered.set()
        await release.wait()
        return proc

    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    task = asyncio.create_task(module.run_tool("local-tool", timeout=60))
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    proc.kill.assert_called_once()
    proc.wait.assert_awaited_once()
