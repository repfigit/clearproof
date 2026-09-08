"""Run local cryptographic tools with bounded lifetime and owned cleanup."""

from __future__ import annotations

import asyncio
import os
import signal


async def run_tool(*args: str, timeout: float) -> int:
    """Return the exit status; reap the process on timeout or cancellation.

    POSIX children get a dedicated process group so wrappers such as npx cannot
    leave their workers behind. Tool output may contain witness data and is
    discarded rather than included in exceptions or logs.
    """
    proc = None
    grouped = os.name == "posix"
    creation = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=grouped,
        )
    )
    try:
        try:
            proc = await asyncio.shield(creation)
        except asyncio.CancelledError:
            proc = await creation
            raise
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode
    finally:
        if proc is not None and proc.returncode is None:
            try:
                if grouped:
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
