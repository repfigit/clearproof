"""Read-only pairing inspection with a pinned key and a pooled local runtime.

The operator-pinned bundle is verified once and written once, at construction,
to a private per-verifier runtime directory. Long-lived Node workers are pooled
process-wide up to the validated ``PAIRING_PROCESS_LIMIT`` (decimal, 1..32,
default 2) and reused across calls; each verifier keeps at most that many idle
workers. A timeout, cancellation or runtime failure retires only the affected
worker, and the next call spawns a fresh one. Saturation fails fast with
``PairingCapacityExceeded`` instead of queueing caller work.

A positive result is cryptographic evidence only. No root, enrollment, policy,
revocation, settlement or authorization-consumption decision occurs here.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import stat
import tempfile
import threading
import weakref
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from src.protocol.credential import scalar
from src.protocol.transfer import Record
from src.prover.pilot_artifacts import InspectedArtifacts, strict_json

BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Coordinate = Annotated[str, Field(pattern=r"^(0|[1-9][0-9]{0,76})$", max_length=77)]
G1 = tuple[Coordinate, Coordinate, Literal["1"]]
G2 = tuple[tuple[Coordinate, Coordinate], tuple[Coordinate, Coordinate], tuple[Literal["1"], Literal["0"]]]


class ProofInspectionError(ValueError):
    """Bounded validation/runtime failure; diagnostics contain no input values."""


class PairingCapacityExceeded(ProofInspectionError):
    """Transient local saturation; it says nothing about proof validity."""


class PairingConfigurationError(RuntimeError):
    """Invalid operator pool configuration; raised at import or on explicit parse."""


DEFAULT_PAIRING_PROCESS_LIMIT = 2
MAX_PAIRING_PROCESS_LIMIT = 32
MAX_PAIRING_PAYLOAD = 131072
STARTUP_TIMEOUT = 10


def pairing_process_limit(environ: Mapping[str, str] | None = None) -> int:
    """Validated bound from ``PAIRING_PROCESS_LIMIT``; unset/blank keeps the default."""
    source = os.environ if environ is None else environ
    raw = source.get("PAIRING_PROCESS_LIMIT")
    if raw is None or not raw.strip():
        return DEFAULT_PAIRING_PROCESS_LIMIT
    value = raw.strip()
    if not re.fullmatch(r"[1-9][0-9]?", value) or int(value) > MAX_PAIRING_PROCESS_LIMIT:
        raise PairingConfigurationError(
            f"PAIRING_PROCESS_LIMIT must be a decimal integer between 1 and {MAX_PAIRING_PROCESS_LIMIT}"
        )
    return int(value)


# Resolved once at import so a bad operator value fails startup, not the first
# proof. Shared across every verifier and event loop in this Python process. No
# waiting queue holds private inputs or a tenant transaction while all slots are
# occupied.
PAIRING_PROCESS_LIMIT = pairing_process_limit()
_SLOT_LOCK = threading.Lock()
_PAIRING_SLOTS = threading.BoundedSemaphore(PAIRING_PROCESS_LIMIT)
_PAIRING_SLOTS_LIMIT = PAIRING_PROCESS_LIMIT


def _pairing_slots() -> threading.BoundedSemaphore:
    """Current process-wide slot bound, rebuilt if the module limit was replaced."""
    global _PAIRING_SLOTS, _PAIRING_SLOTS_LIMIT
    with _SLOT_LOCK:
        if _PAIRING_SLOTS_LIMIT != PAIRING_PROCESS_LIMIT:
            _PAIRING_SLOTS = threading.BoundedSemaphore(PAIRING_PROCESS_LIMIT)
            _PAIRING_SLOTS_LIMIT = PAIRING_PROCESS_LIMIT
        return _PAIRING_SLOTS


def _kill_group(proc) -> None:
    if proc.returncode is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _dispose(directory: Path, workers: list) -> None:
    """Synchronous last resort for garbage-collected verifiers (no running loop)."""
    for worker in list(workers):
        _kill_group(worker.proc)
    shutil.rmtree(directory, ignore_errors=True)


async def _reap(proc) -> None:
    if proc.returncode is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    cleanup = asyncio.create_task(proc.wait())
    cancelled = False
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            cancelled = True
    cleanup.result()
    if cancelled:
        raise asyncio.CancelledError


class PilotProof(Record):
    protocol: Literal["groth16"]
    curve: Literal["bn128"]
    pi_a: G1
    pi_b: G2
    pi_c: G1

    @model_validator(mode="after")
    def field_coordinates(self):
        values = [*self.pi_a, *self.pi_c, *(v for pair in self.pi_b for v in pair)]
        if any(int(value) >= BASE_FIELD for value in values):
            raise ValueError("Noncanonical curve coordinate")
        return self

    @classmethod
    def parse(cls, raw: bytes) -> PilotProof:
        if type(raw) is not bytes:
            raise ProofInspectionError("invalid_proof_encoding")
        try:
            strict_json(raw, limit=8192)
            return cls.model_validate_json(raw)
        except ValueError:
            raise ProofInspectionError("invalid_proof_encoding") from None


def public_signals(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or len(value) != 8:
        raise ProofInspectionError("invalid_public_signals")
    try:
        for item in value:
            scalar(item)
    except ValueError:
        raise ProofInspectionError("invalid_public_signals") from None
    return tuple(value)


@dataclass(frozen=True)
class PairingInspection:
    cryptographic_valid: bool
    # Explicitly no ambiguous `valid`/`compliant`/`authorized` property.
    manifest_digest: str
    proof_profile: Literal["pilot-transfer-v1", "pilot-transfer-v2", "pilot-transfer-v3"]


# Long-lived worker: one JSON request per line, one status byte per line. Lines
# are consumed sequentially so a slow pairing cannot reorder concurrent requests.
_RUNNER = r"""
const readline = require("node:readline");
process.stdin.setEncoding("utf8");
const lines = readline.createInterface({input: process.stdin, crlfDelay: Infinity, terminal: false});
process.stdout.write("R\n");
(async () => {
    for await (const line of lines) {
        if (line.length > 131072) { process.stdout.write("2\n"); continue; }
        try {
            const {key, signals, proof} = JSON.parse(line);
            const valid = await snarkjs.groth16.verify(key, signals, proof);
            process.stdout.write(valid === true ? "1\n" : "0\n");
        } catch (_) { process.stdout.write("2\n"); }
    }
})();
"""


def pinned_bundle(path: Path, expected_sha256: str) -> bytes:
    if type(expected_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ProofInspectionError("invalid_runtime_pin")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            meta = os.fstat(stream.fileno())
            if not stat.S_ISREG(meta.st_mode) or not 0 < meta.st_size <= 2 * 1024 * 1024:
                raise ProofInspectionError("invalid_runtime_bundle")
            data = stream.read(2 * 1024 * 1024 + 1)
        if len(data) != meta.st_size or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha256):
            raise ProofInspectionError("runtime_bundle_mismatch")
        return data
    except OSError:
        raise ProofInspectionError("runtime_bundle_unavailable") from None


@dataclass(frozen=True)
class PilotPairingVerifier:
    """Construct using operator-inspected artifacts and an independently pinned bundle.

    Node is an operator-owned absolute executable path, part of the trusted host
    runtime. The pinned browser IIFE bundle is self-contained and snapshotted;
    no npx, package resolution, downloads or customer-data files are used.
    """

    artifacts: InspectedArtifacts = field(repr=False)
    bundle: bytes = field(repr=False)
    node: Path = field(repr=False)
    _directory: Path = field(default=Path("."), repr=False, compare=False)
    _script: Path = field(default=Path("."), repr=False, compare=False)
    _idle: deque = field(default_factory=deque, repr=False, compare=False)
    _workers: list = field(default_factory=list, repr=False, compare=False)
    _spawns: set = field(default_factory=set, repr=False, compare=False)
    _unready: set = field(default_factory=set, repr=False, compare=False)

    def __post_init__(self):
        # Write the already-verified snapshot exactly once; later calls only spawn.
        directory = None
        try:
            directory = Path(tempfile.mkdtemp(prefix="clearproof-pairing-"))
            script = directory / "runtime.cjs"
            fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(self.bundle + b"\n" + _RUNNER.encode("ascii"))
        except OSError:
            if directory is not None:
                shutil.rmtree(directory, ignore_errors=True)
            raise ProofInspectionError("pairing_runtime_unavailable") from None
        object.__setattr__(self, "_directory", directory)
        object.__setattr__(self, "_script", script)
        weakref.finalize(self, _dispose, directory, self._workers)

    @classmethod
    def load(cls, artifacts: InspectedArtifacts, *, bundle_path: Path, bundle_sha256: str, node: Path):
        if not node.is_absolute() or not node.is_file() or not os.access(node, os.X_OK):
            raise ProofInspectionError("invalid_node_runtime")
        return cls(artifacts, pinned_bundle(bundle_path, bundle_sha256), node)

    def runtime_processes(self) -> tuple[asyncio.subprocess.Process, ...]:
        """Live owned workers (idle and busy); benchmark instrumentation only."""
        return tuple(worker.proc for worker in self._workers if worker.proc.returncode is None)

    async def _borrow(self, holder: dict[str, _Worker | None]) -> _Worker:
        while self._idle:
            worker = self._idle.pop()
            if worker.proc.returncode is None:
                return worker
            if worker in self._workers:
                self._workers.remove(worker)
        creation = asyncio.create_task(
            asyncio.create_subprocess_exec(
                str(self.node),
                "--max-old-space-size=256",
                str(self._script),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={"LANG": "C", "TZ": "UTC"},
                cwd=str(self._directory),
                start_new_session=True,
                limit=1 << 18,
            )
        )
        self._spawns.add(creation)
        creation.add_done_callback(self._spawns.discard)
        cancelled = False
        while not creation.done():
            try:
                await asyncio.shield(creation)
            except asyncio.CancelledError:
                cancelled = True
        # Publish ownership before honoring cancellation so cleanup is never lost.
        worker = _Worker(creation.result(), asyncio.Event())
        holder["worker"] = worker
        self._workers.append(worker)
        self._unready.add(worker)
        if cancelled:
            raise asyncio.CancelledError
        try:
            await self._await_ready(worker)
        finally:
            self._unready.discard(worker)
            worker.ready.set()
        return worker

    async def _await_ready(self, worker: _Worker) -> None:
        # The runner emits one readiness byte only after the script is fully read,
        # so the runtime directory may be removed while the request is in flight.
        try:
            ready = await asyncio.wait_for(worker.proc.stdout.readline(), STARTUP_TIMEOUT)
        except asyncio.TimeoutError:
            raise ProofInspectionError("pairing_timeout") from None
        except OSError:
            raise ProofInspectionError("pairing_runtime_unavailable") from None
        if ready != b"R\n":
            raise ProofInspectionError("pairing_runtime_failed")

    async def _exchange(self, worker: _Worker, payload: bytes, timeout: int) -> bytes:
        async def roundtrip() -> bytes:
            worker.proc.stdin.write(payload + b"\n")
            await worker.proc.stdin.drain()
            try:
                line = await worker.proc.stdout.readline()
            except ValueError:  # separator missing past the stream buffer limit
                return b""
            if worker.proc.returncode is not None:
                return b""
            return line

        return await asyncio.wait_for(roundtrip(), timeout)

    async def _retire(self, holder: dict[str, _Worker | None]) -> None:
        worker, holder["worker"] = holder.get("worker"), None
        if worker is None:
            return
        if worker in self._workers:
            self._workers.remove(worker)
        await _reap(worker.proc)

    def _park(self, worker: _Worker) -> None:
        if worker.proc.returncode is None:
            self._idle.append(worker)
        elif worker in self._workers:
            self._workers.remove(worker)

    async def aclose(self) -> None:
        """Reap idle workers and drop the runtime directory; in-flight calls own theirs."""
        if self._spawns:
            await asyncio.gather(*tuple(self._spawns), return_exceptions=True)
        while self._unready:
            await asyncio.gather(*(worker.ready.wait() for worker in tuple(self._unready)), return_exceptions=True)
        while self._idle:
            await _reap(self._idle.pop().proc)
        # Busy workers stay tracked so the finalizer can reap them on collection.
        shutil.rmtree(self._directory, ignore_errors=True)

    async def inspect(
        self,
        proof_bytes: bytes,
        signals: list[str] | tuple[str, ...],
        *,
        expected_signals: list[str] | tuple[str, ...],
        timeout: int = 10,
    ) -> PairingInspection:
        if type(timeout) is not int or not 1 <= timeout <= 60:
            raise ProofInspectionError("invalid_verification_timeout")
        proof = PilotProof.parse(proof_bytes)
        supplied = public_signals(signals)
        expected = public_signals(expected_signals)
        if supplied != expected:
            raise ProofInspectionError("public_signal_context_mismatch")
        payload = json.dumps(
            {
                "key": strict_json(self.artifacts.verification_key_bytes),
                "signals": list(supplied),
                "proof": proof.model_dump(mode="json"),
            }
        ).encode("ascii")
        if len(payload) > MAX_PAIRING_PAYLOAD:
            raise ProofInspectionError("pairing_runtime_failed")
        slots = _pairing_slots()
        if not slots.acquire(blocking=False):
            raise PairingCapacityExceeded("pairing_capacity_exceeded")
        holder: dict[str, _Worker | None] = {"worker": None}
        try:
            try:
                worker = await self._borrow(holder)
                reply = await self._exchange(worker, payload, timeout)
            except asyncio.TimeoutError:
                # Builtin TimeoutError subclasses OSError; check it first.
                raise ProofInspectionError("pairing_timeout") from None
            except OSError:
                raise ProofInspectionError("pairing_runtime_unavailable") from None
            # The pinned runtime is trusted; its wrapper emits exactly one byte per line.
            if reply not in (b"1\n", b"0\n"):
                raise ProofInspectionError("pairing_runtime_failed")
            holder["worker"] = None
            self._park(worker)
            return PairingInspection(
                reply == b"1\n", self.artifacts.manifest.digest, self.artifacts.manifest.proof_profile
            )
        finally:
            # Keep the capacity slot through owned-process cleanup, even when a
            # caller cancels repeatedly during creation or reaping.
            try:
                await self._retire(holder)
            finally:
                slots.release()


@dataclass(eq=False)
class _Worker:
    proc: asyncio.subprocess.Process
    ready: asyncio.Event | None = None
