"""Pinned, memory-only development pilot proving for the durable job worker.

No request selects executable paths, keys or source code. The operator supplies
an independently pinned runtime and artifact manifest. Current trust, enrollment,
revocation, policy, time and authorization are separate service checks.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from src.policy.model import POLICY_SCHEMA_DIGEST
from src.prover.generated_signals import PROFILE
from src.prover.pilot_artifacts import InspectedArtifacts, inspect_artifacts, strict_json
from src.prover.pilot_verifier import PilotPairingVerifier, PilotProof, public_signals

MAX_INPUT = 65536
MAX_OUTPUT = 16384


class PilotProvingError(ValueError):
    """Stable diagnostics, never customer inputs or subprocess output."""


@dataclass(frozen=True)
class ProvingResult:
    proof: bytes = field(repr=False)
    public_signals: tuple[str, ...] = field(repr=False)


# The public launcher sets Linux parent-death protection before replacing itself
# with Node. A crash/SIGKILL of the worker cannot leave its prover consuming a slot.
# No private data enters arguments, environments or temporary source files.
_PARENT_GUARD = r"""
import ctypes, os, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
parent = os.getppid()
if parent == 1 or ctypes.CDLL(None, use_errno=True).prctl(1, 9, 0, 0, 0) != 0:
    sys.exit(2)
if os.getppid() != parent:
    sys.exit(2)
os.execv(sys.argv[1], sys.argv[1:])
"""

_RUNNER = r"""
const fs = require('node:fs');
const crypto = require('node:crypto');
const pins = JSON.parse(process.argv[2]);
function artifact(pin) {
    const meta = fs.fstatSync(pin.fd);
    if (!meta.isFile() || meta.size !== pin.size) throw new Error('artifact');
    const bytes = fs.readFileSync(pin.fd);
    fs.closeSync(pin.fd);
    if (bytes.length !== pin.size || crypto.createHash('sha256').update(bytes).digest('hex') !== pin.sha256) {
        throw new Error('artifact');
    }
    return bytes;
}
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
    input += chunk;
    if (Buffer.byteLength(input, 'utf8') > 65536) process.exit(2);
});
process.stdin.on('end', async () => {
    try {
        const data = JSON.parse(input);
        const {proof, publicSignals} = await snarkjs.groth16.fullProve(
            data.witness, artifact(pins.wasm), artifact(pins.proving_key));
        if (JSON.stringify(publicSignals) !== JSON.stringify(data.expected)) process.exit(2);
        if (!await snarkjs.groth16.verify(data.key, publicSignals, proof)) process.exit(2);
        const output = JSON.stringify({proof, public_signals: publicSignals});
        if (Buffer.byteLength(output, 'utf8') > 16384) process.exit(2);
        process.stdout.write(output, () => process.exit(0));
    } catch { process.exit(2); }
});
"""


@contextmanager
def artifact_descriptors(root: Path, artifacts: InspectedArtifacts):
    """Open bounded regular basenames, without symlinks; child hashes its snapshots."""
    descriptors = []
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        pins = {}
        for role in ("wasm", "proving_key"):
            entry = getattr(artifacts.manifest, role)
            fd = os.open(entry.filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            descriptors.append(fd)
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_size != entry.size:
                raise PilotProvingError("proving_artifact_changed")
            pins[role] = {"fd": fd, "size": entry.size, "sha256": entry.sha256}
        yield pins
    except OSError:
        raise PilotProvingError("proving_artifact_unavailable") from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


async def bounded_output(stream: asyncio.StreamReader) -> bytes:
    output = bytearray()
    while chunk := await stream.read(4096):
        if len(output) + len(chunk) > MAX_OUTPUT:
            raise PilotProvingError("proving_output_limit")
        output.extend(chunk)
    return bytes(output)


@dataclass(frozen=True)
class PilotProver:
    """Linux worker backend; private witness and proving intermediates stay in RAM.

    Node's heap limit is a heap bound, not an RSS or container-memory guarantee.
    Set an independent worker/container memory limit and keep queue concurrency
    within measured host capacity. The parent must not swap or dump private RAM.
    """

    verifier: PilotPairingVerifier = field(repr=False)
    root: Path = field(repr=False)
    heap_mb: int = 1536

    @classmethod
    def load(cls, root: Path, *, trusted_digest: str, bundle_path: Path, bundle_sha256: str, node: Path, heap_mb=1536):
        if sys.platform != "linux":
            raise PilotProvingError("linux_proving_worker_required")
        if type(heap_mb) is not int or not 256 <= heap_mb <= 4096:
            raise PilotProvingError("invalid_proving_heap_limit")
        artifacts = inspect_artifacts(root, trusted_digest=trusted_digest)
        if (
            artifacts.manifest.proof_profile != PROFILE
            or artifacts.manifest.policy_schema_digest != POLICY_SCHEMA_DIGEST
        ):
            raise PilotProvingError("unsupported_proving_profile")
        verifier = PilotPairingVerifier.load(artifacts, bundle_path=bundle_path, bundle_sha256=bundle_sha256, node=node)
        return cls(verifier, root, heap_mb)

    async def prove(self, witness: dict, *, expected_signals: list[str] | tuple[str, ...], timeout: int = 120):
        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise PilotProvingError("invalid_proving_timeout")
        expected = public_signals(expected_signals)
        if type(witness) is not dict:
            raise PilotProvingError("invalid_proving_input")
        try:
            payload = json.dumps(
                {
                    "witness": witness,
                    "expected": list(expected),
                    "key": strict_json(self.verifier.artifacts.verification_key_bytes),
                },
                allow_nan=False,
            ).encode("utf-8")
        except (ValueError, TypeError, RecursionError):
            raise PilotProvingError("invalid_proving_input") from None
        if len(payload) > MAX_INPUT:
            raise PilotProvingError("proving_input_limit")
        proc = None
        with artifact_descriptors(self.root, self.verifier.artifacts) as pins:
            with tempfile.TemporaryDirectory(prefix="clearproof-proving-runtime-") as directory:
                script = Path(directory) / "runtime.cjs"
                script.write_bytes(self.verifier.bundle + b"\n" + _RUNNER.encode("ascii"))
                try:
                    async with asyncio.timeout(timeout):
                        creation = asyncio.create_task(
                            asyncio.create_subprocess_exec(
                                sys.executable,
                                "-I",
                                "-c",
                                _PARENT_GUARD,
                                str(self.verifier.node),
                                f"--max-old-space-size={self.heap_mb}",
                                str(script),
                                json.dumps(pins),
                                pass_fds=tuple(pin["fd"] for pin in pins.values()),
                                stdin=asyncio.subprocess.PIPE,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.DEVNULL,
                                env={"LANG": "C", "TZ": "UTC"},
                                cwd=directory,
                                start_new_session=True,
                            )
                        )
                        try:
                            proc = await asyncio.shield(creation)
                        except asyncio.CancelledError:
                            proc = await creation
                            raise
                        proc.stdin.write(payload)
                        await proc.stdin.drain()
                        proc.stdin.close()
                        output = await bounded_output(proc.stdout)
                        await proc.wait()
                        if proc.returncode != 0:
                            raise PilotProvingError("proving_runtime_failed")
                        value = strict_json(output, limit=MAX_OUTPUT)
                        if type(value) is not dict or set(value) != {"proof", "public_signals"}:
                            raise PilotProvingError("invalid_proving_result")
                        proof = json.dumps(value["proof"]).encode("ascii")
                        PilotProof.parse(proof)
                        actual = public_signals(value["public_signals"])
                        if actual != expected:
                            raise PilotProvingError("proving_signal_mismatch")
                        return ProvingResult(proof, actual)
                except TimeoutError:
                    raise PilotProvingError("proving_timeout") from None
                except (OSError, BrokenPipeError):
                    raise PilotProvingError("proving_runtime_unavailable") from None
                except ValueError as exc:
                    if isinstance(exc, PilotProvingError):
                        raise
                    raise PilotProvingError("invalid_proving_result") from None
                finally:
                    if proc is not None and proc.returncode is None:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        await proc.wait()
