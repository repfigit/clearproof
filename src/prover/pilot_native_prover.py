"""Optional operator-pinned Linux prover with anonymous in-memory transport."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from src.prover.pilot_artifacts import strict_json
from src.prover.pilot_prover import MAX_INPUT, PilotProver, PilotProvingError, ProvingResult, bounded_output
from src.prover.pilot_verifier import PilotProof, public_signals

MAX_WITNESS = 4 * 1024 * 1024
MAX_BINARY = 64 * 1024 * 1024
MAX_KEY = 128 * 1024 * 1024

_GUARD = r"""
import ctypes, json, os, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_FSIZE, (4194304, 4194304))
parent = int(sys.argv[1])
if os.getppid() != parent or ctypes.CDLL(None, use_errno=True).prctl(1, 9, 0, 0, 0) != 0:
    sys.exit(2)
os.sched_setaffinity(0, json.loads(sys.argv[2]))
if os.getppid() != parent:
    sys.exit(2)
os.execv(sys.argv[3], sys.argv[3:])
"""

_RUNNER = r"""
const fs = require('node:fs');
const pins = JSON.parse(process.argv[2]);
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
    input += chunk;
    if (Buffer.byteLength(input, 'utf8') > 65536) process.exit(2);
});
process.stdin.on('end', async () => {
    try {
        const data = JSON.parse(input);
        if (pins.mode === 'witness') {
            const output = {type: 'mem'};
            await snarkjs.wtns.calculate(data.witness, fs.readFileSync(pins.wasm), output);
            if (!output.data || output.data.byteLength > 4194304) process.exit(2);
            fs.writeFileSync(pins.witness, output.data);
        } else {
            if (!await snarkjs.groth16.verify(data.key, data.signals, data.proof)) process.exit(2);
        }
        process.stdout.write('1', () => process.exit(0));
    } catch { process.exit(2); }
});
"""


def _seal(fd):
    import fcntl

    # Stable Linux UAPI (linux/fcntl.h). Some standalone Python distributions
    # omit these names even though the running kernel supports sealing.
    fcntl.fcntl(fd, 1033, 0x000F)


def _memfd(name):
    # Linux libc ABI: int memfd_create(const char *, unsigned int). Calling libc
    # also supports Python builds configured without os.memfd_create.
    library = ctypes.CDLL(None, use_errno=True)
    try:
        create = library.memfd_create
    except AttributeError:
        raise OSError("Anonymous Linux memory files are unavailable") from None
    create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    create.restype = ctypes.c_int
    fd = create(name.encode("ascii"), 0x0001 | 0x0002)  # CLOEXEC | ALLOW_SEALING
    if fd < 0:
        raise OSError(ctypes.get_errno(), "Anonymous Linux memory file creation failed")
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    return fd


def _snapshot(path: Path, expected: str, maximum: int, descriptors: list[int], *, size=None, executable=False):
    """Pin a bounded regular file's bytes, then seal the immutable snapshot."""
    if type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise PilotProvingError("invalid_native_pin")
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(source)
        if (
            not stat.S_ISREG(meta.st_mode)
            or not 0 < meta.st_size <= maximum
            or (size is not None and meta.st_size != size)
            or (executable and not meta.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        ):
            raise PilotProvingError("native_file_rejected")
        target = _memfd("clearproof-public-runtime")
        descriptors.append(target)
        digest = hashlib.sha256()
        remaining = meta.st_size
        while remaining:
            block = os.read(source, min(remaining, 262144))
            if not block:
                raise PilotProvingError("native_file_rejected")
            digest.update(block)
            pending = memoryview(block)
            while pending:
                written = os.write(target, pending)
                if written <= 0:
                    raise PilotProvingError("native_file_rejected")
                pending = pending[written:]
            remaining -= len(block)
        if os.read(source, 1) or not hmac.compare_digest(digest.hexdigest(), expected):
            raise PilotProvingError("native_pin_mismatch")
        if executable:
            os.fchmod(target, 0o700)
        _seal(target)
        os.lseek(target, 0, os.SEEK_SET)
        return target
    finally:
        os.close(source)


@contextmanager
def _memory_files():
    descriptors = []
    try:
        yield descriptors
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _private_file(descriptors):
    fd = _memfd("clearproof-private-job")
    descriptors.append(fd)
    return fd


def _read(fd, limit):
    if not 0 < os.fstat(fd).st_size <= limit:
        raise PilotProvingError("native_output_limit")
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), "rb") as stream:
        return stream.read(limit + 1)


async def _settled(task):
    """Repeated cancellation cannot abandon a spawn or a reap in flight."""
    cancelled = False
    while True:
        try:
            result = await asyncio.shield(task)
            return result, cancelled
        except asyncio.CancelledError:
            if task.done():
                return task.result(), True
            cancelled = True


async def _run(command, *, descriptors, cpus, directory, payload=b""):
    proc = None
    try:
        creation = asyncio.create_task(
            asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-c",
                _GUARD,
                str(os.getpid()),
                json.dumps(cpus),
                *command,
                pass_fds=tuple(descriptors),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={"LANG": "C", "TZ": "UTC", "OMP_NUM_THREADS": str(len(cpus)), "OMP_THREAD_LIMIT": str(len(cpus))},
                cwd=directory,
                start_new_session=True,
            )
        )
        proc, cancelled = await _settled(creation)
        if cancelled:
            raise asyncio.CancelledError
        proc.stdin.write(payload)
        await proc.stdin.drain()
        proc.stdin.close()
        output = await bounded_output(proc.stdout)
        await proc.wait()
        if proc.returncode != 0:
            raise PilotProvingError("native_runtime_failed")
        return output
    finally:
        if proc is not None and proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, cancelled = await _settled(asyncio.create_task(proc.wait()))
            if cancelled:
                raise asyncio.CancelledError


@dataclass(frozen=True)
class PilotNativeProver:
    """Bounded Linux backend; the independently pinned JS runtime still pairs proofs.

    CPU affinity bounds execution capacity. Upstream's std::thread pools ignore
    OMP_NUM_THREADS, so that variable alone is not a CPU or thread-count bound.
    Anonymous RAM can still swap; the operator must enforce host/container policy.
    """

    javascript: PilotProver = field(repr=False)
    binary: Path = field(repr=False)
    binary_sha256: str
    cpus: tuple[int, ...]

    @classmethod
    def load(cls, javascript, *, binary, binary_sha256, cpus=None):
        if sys.platform != "linux":
            raise PilotProvingError("linux_native_prover_required")
        if not isinstance(javascript, PilotProver):
            raise PilotProvingError("invalid_native_javascript_backend")
        allowed = os.sched_getaffinity(0)
        cpus = tuple(sorted(allowed)[:4]) if cpus is None else cpus
        if (
            type(cpus) is not tuple
            or not 1 <= len(cpus) <= 4
            or any(type(cpu) is not int or cpu not in allowed for cpu in cpus)
            or len(set(cpus)) != len(cpus)
        ):
            raise PilotProvingError("invalid_native_cpu_affinity")
        binary = Path(binary).absolute()
        try:
            with _memory_files() as fds:
                _snapshot(binary, binary_sha256, MAX_BINARY, fds, executable=True)
        except OSError:
            raise PilotProvingError("native_binary_unavailable") from None
        return cls(javascript, binary, binary_sha256, cpus)

    @property
    def verifier(self):
        return self.javascript.verifier

    @property
    def runtime_digest(self):
        return hashlib.sha256(
            json.dumps(
                {
                    "backend": "rapidsnark-memory-v1",
                    "binary": self.binary_sha256,
                    "javascript": hashlib.sha256(self.verifier.bundle).hexdigest(),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()

    async def prove(self, witness, *, expected_signals, timeout=120):
        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise PilotProvingError("invalid_proving_timeout")
        expected = public_signals(expected_signals)
        if type(witness) is not dict:
            raise PilotProvingError("invalid_proving_input")
        try:
            payload = json.dumps({"witness": witness}, allow_nan=False).encode("utf-8")
        except (ValueError, TypeError, RecursionError):
            raise PilotProvingError("invalid_proving_input") from None
        if len(payload) > MAX_INPUT:
            raise PilotProvingError("proving_input_limit")
        try:
            async with asyncio.timeout(timeout):
                with (
                    _memory_files() as fds,
                    tempfile.TemporaryDirectory(prefix="clearproof-native-runtime-") as directory,
                ):
                    executable = _snapshot(self.binary, self.binary_sha256, MAX_BINARY, fds, executable=True)
                    artifacts = self.verifier.artifacts.manifest
                    files = {}
                    for name, maximum in (("wasm", MAX_KEY), ("proving_key", MAX_KEY)):
                        entry = getattr(artifacts, name)
                        files[name] = _snapshot(
                            self.javascript.root / entry.filename, entry.sha256, maximum, fds, size=entry.size
                        )
                    private = {name: _private_file(fds) for name in ("witness", "proof", "public")}
                    script = Path(directory) / "runtime.cjs"
                    script.write_bytes(self.verifier.bundle + b"\n" + _RUNNER.encode("ascii"))
                    node_command = [
                        str(self.verifier.node),
                        f"--max-old-space-size={self.javascript.heap_mb}",
                        str(script),
                    ]
                    pins = {"mode": "witness", "wasm": files["wasm"], "witness": private["witness"]}
                    if (
                        await _run(
                            [*node_command, json.dumps(pins)],
                            descriptors=[files["wasm"], private["witness"]],
                            cpus=self.cpus,
                            directory=directory,
                            payload=payload,
                        )
                        != b"1"
                    ):
                        raise PilotProvingError("native_witness_failed")
                    if not 0 < os.fstat(private["witness"]).st_size <= MAX_WITNESS:
                        raise PilotProvingError("native_witness_limit")
                    _seal(private["witness"])
                    await _run(
                        [
                            f"/proc/self/fd/{executable}",
                            f"/proc/self/fd/{files['proving_key']}",
                            *(f"/proc/self/fd/{private[name]}" for name in ("witness", "proof", "public")),
                        ],
                        descriptors=[executable, files["proving_key"], *private.values()],
                        cpus=self.cpus,
                        directory=directory,
                    )
                    for name in ("proof", "public"):
                        _seal(private[name])
                    proof = strict_json(_read(private["proof"], 8192), limit=8192)
                    if type(proof) is not dict:
                        raise PilotProvingError("invalid_proving_result")
                    # Upstream omits curve metadata. Pairing against the pinned
                    # BN254 key establishes it; supplied conflicting metadata fails.
                    proof.setdefault("curve", "bn128")
                    encoded = json.dumps(proof).encode("ascii")
                    PilotProof.parse(encoded)
                    actual = public_signals(strict_json(_read(private["public"], 2048), limit=2048))
                    if actual != expected:
                        raise PilotProvingError("proving_signal_mismatch")
                    verified = await _run(
                        [*node_command, json.dumps({"mode": "verify"})],
                        descriptors=[],
                        cpus=self.cpus,
                        directory=directory,
                        payload=json.dumps(
                            {
                                "proof": proof,
                                "signals": actual,
                                "key": strict_json(self.verifier.artifacts.verification_key_bytes),
                            }
                        ).encode("ascii"),
                    )
                    if verified != b"1":
                        raise PilotProvingError("native_pairing_failed")
                    return ProvingResult(encoded, actual)
        except TimeoutError:
            raise PilotProvingError("proving_timeout") from None
        except OSError:
            raise PilotProvingError("native_runtime_unavailable") from None
        except ValueError as exc:
            if isinstance(exc, PilotProvingError):
                raise
            raise PilotProvingError("invalid_proving_result") from None


def select_pilot_backend(javascript: PilotProver, *, binary=None, binary_sha256=None, cpus=None):
    """Operator factory helper: optional discovery never trusts an unpinned binary.

    Existing JS development paths remain the fallback outside Linux or when
    discovery finds no binary/pin. An explicit bad configuration fails closed.
    """
    if sys.platform != "linux":
        return javascript
    configured = binary or os.getenv("CLEARPROOF_RAPIDSNARK_BIN")
    pin = binary_sha256 or os.getenv("CLEARPROOF_RAPIDSNARK_SHA256")
    candidate = configured or shutil.which("rapidsnark") or shutil.which("prover")
    if not candidate or (not configured and not pin):
        return javascript
    if not pin:
        raise PilotProvingError("native_binary_pin_required")
    return PilotNativeProver.load(javascript, binary=Path(candidate), binary_sha256=pin, cpus=cpus)
