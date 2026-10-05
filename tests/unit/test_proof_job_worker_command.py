"""Supervised command startup, shutdown and redacted failures."""

import asyncio
import runpy

import pytest

from src.prover import proof_job_worker as module
from src.storage.keyring import KeyRing, KeyVersion


@pytest.mark.parametrize("mode", ["shutdown", "empty", "loader-error", "handler-error"])
async def test_supervisor_closes_storage_and_cancels_owned_work(monkeypatch, mode):
    events, callbacks = [], []

    class Database:
        def __init__(self, **kwargs):
            pass

        async def connect(self):
            events.append("connected")

        async def close(self):
            events.append("closed")

    async def targets(db, cipher):
        if mode == "loader-error":
            raise ValueError("PRIVATE-DETAIL")
        return {} if mode == "empty" else {("tenant-a", "target"): object()}

    async def run(worker, stop):
        events.append("started")
        try:
            await asyncio.Event().wait()
        finally:
            events.append("cleaned")

    loop = asyncio.get_running_loop()

    def install(signum, callback):
        if mode == "handler-error":
            raise RuntimeError("handler unavailable")
        callbacks.append(signum)
        loop.call_soon(callback)

    monkeypatch.setattr("src.storage.database.Database", Database)
    monkeypatch.setattr("src.storage.keyring.load_keyring", lambda: KeyRing(KeyVersion("current", b"a" * 32, 0)))
    monkeypatch.setattr("src.services.proving_configuration.load_proving_targets", targets)
    monkeypatch.setattr(module.ProofJobWorker, "run", run)
    monkeypatch.setattr(loop, "add_signal_handler", install)
    monkeypatch.setattr(loop, "remove_signal_handler", lambda signum: callbacks.remove(signum))
    if mode == "shutdown":
        await module.serve()
        assert "cleaned" in events and not callbacks
    else:
        with pytest.raises((RuntimeError, ValueError)):
            await module.serve()
    assert events[0] == "connected" and events[-1] == "closed"


@pytest.mark.parametrize("failure", [False, True])
def test_command_exit_is_redacted(monkeypatch, capsys, failure):
    def run(coro):
        coro.close()
        if failure:
            raise RuntimeError("SYNTHETIC-PRIVATE-DETAIL")

    monkeypatch.setattr(module.asyncio, "run", run)
    assert module.main() == (1 if failure else 0)
    assert "PRIVATE" not in capsys.readouterr().err


def test_module_entrypoint_executes_command(monkeypatch):
    def run(coro):
        coro.close()

    monkeypatch.setattr(module.asyncio, "run", run)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module(module.__name__, run_name="__main__")
    assert exc.value.code == 0
