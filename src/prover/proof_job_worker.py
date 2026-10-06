"""One leased job per worker; PostgreSQL bounds concurrency across workers.

The API never starts a prover task. Run workers as separately supervised Linux
processes with independently provisioned operator configuration. Lease failures
cancel and reap the owned runtime before releasing or abandoning its slot.
"""

import asyncio
import signal
import time
from contextlib import suppress

from fastapi import HTTPException

from src.prover.pilot_prover import PilotProvingError
from src.services.proof_jobs import ProofJobService
from src.storage.proof_jobs import LeaseLost, ProofJobError


class ProofJobWorker:
    def __init__(self, service: ProofJobService):
        self.service = service
        self.queue = service.queue

    async def _watch(self, claim):
        while True:
            async with asyncio.timeout(5):
                state = await self.queue.heartbeat(claim)
            if state != "proving":
                return state
            await asyncio.sleep(2)

    async def _execute(self, claim):
        async with asyncio.timeout(max(1, claim.snapshot.expires_at - int(time.time()))):
            return await self.service.execute(claim)

    async def run_once(self) -> bool:
        """True means one claim was handled; false means no runnable slot/job."""
        async with asyncio.timeout(5):
            claim = await self.queue.claim()
        if claim is None:
            return False
        work = asyncio.create_task(self._execute(claim))
        watch = asyncio.create_task(self._watch(claim))
        error, retryable = "worker_interrupted", True
        cancelled = False
        completed = False
        try:
            done, _ = await asyncio.wait((work, watch), return_when=asyncio.FIRST_COMPLETED)
            if watch in done:
                state = watch.result()
                error, retryable = ("job_expired", False) if state == "job_expired" else ("worker_interrupted", False)
            else:
                work.result()
                completed = True
        except PilotProvingError:
            error = "prover_failed"
        except ProofJobError as exc:
            error = "configuration_changed" if str(exc) == "configuration_changed" else "current_state_rejected"
            retryable = False
        except (ValueError, TypeError, KeyError, HTTPException):
            error, retryable = "current_state_rejected", False
        except TimeoutError:
            # A heartbeat timeout is an interruption, not evidence of business
            # expiry. Database expiry wins in the fenced completion transaction.
            pass
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            # Worker/database/runtime exception text must not expose inputs.
            pass
        finally:
            # Cancel each task once; repeated cancellation must not interrupt a
            # backend's subprocess reaping. Shield the owned cleanup task.
            for task in (work, watch):
                if not task.done():
                    task.cancel()
            cleanup = asyncio.ensure_future(asyncio.gather(work, watch, return_exceptions=True))
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    cancelled = True
            if not completed:
                # The child is gone before this acknowledgement. If storage is
                # unavailable/lost, abandon the fenced lease for crash recovery.
                with suppress(Exception):
                    async with asyncio.timeout(5):
                        await self.queue.finish(claim, error=error, retryable=retryable)
        if cancelled:
            raise asyncio.CancelledError
        return True

    async def run(self, stop: asyncio.Event):
        """Supervised poll loop; stop is also checked between completed claims."""
        while not stop.is_set():
            try:
                handled = await self.run_once()
            except (TimeoutError, LeaseLost):
                handled = False
            if not handled:
                with suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=1)


async def serve():
    """Operator command: python -m src.prover.proof_job_worker.

    Configure DATABASE_URL, the same PII keyring and PILOT_PROVING_FACTORY used
    by the API. Signals cancel the active job and wait for its runtime cleanup.
    SQL stores queue limits; replicas cannot independently multiply them.
    """
    from src.services.proving_configuration import load_proving_targets
    from src.storage.database import Database
    from src.storage.keyring import load_keyring
    from src.storage.pilot_cipher import RecordCipher

    cipher = RecordCipher(load_keyring())
    db = Database(pool_min=1, pool_max=4)
    await db.connect()
    try:
        targets = await load_proving_targets(db, cipher)
        if not targets:
            raise RuntimeError("Configure operator proving targets before starting a worker")
        stop = asyncio.Event()
        task = asyncio.create_task(ProofJobWorker(ProofJobService(db, cipher, targets)).run(stop))
        loop = asyncio.get_running_loop()

        def shutdown():
            stop.set()
            task.cancel()

        installed = []
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(signum, shutdown)
                installed.append(signum)
            with suppress(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            for signum in installed:
                loop.remove_signal_handler(signum)
    finally:
        await db.close()


def main():
    import sys

    try:
        asyncio.run(serve())
    except Exception:
        # No unredacted provider/database/factory traceback in supervisor logs.
        print("Pilot proof worker stopped: check operator configuration and service availability", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
