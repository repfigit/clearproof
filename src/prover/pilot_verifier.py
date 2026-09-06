"""Read-only pairing inspection with a pinned key and self-contained JS bundle.

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
import signal
import stat
import tempfile
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
    proof_profile: Literal["pilot-transfer-v1"] = "pilot-transfer-v1"


_RUNNER = r"""
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => {
    input += chunk;
    if (input.length > 131072) process.exit(2);
});
process.stdin.on("end", async () => {
    try {
        const {key, signals, proof} = JSON.parse(input);
        const valid = await snarkjs.groth16.verify(key, signals, proof);
        process.stdout.write(valid === true ? "1" : "0", () => process.exit(0));
    } catch (_) { process.exit(2); }
});
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

    @classmethod
    def load(cls, artifacts: InspectedArtifacts, *, bundle_path: Path, bundle_sha256: str, node: Path):
        if not node.is_absolute() or not node.is_file() or not os.access(node, os.X_OK):
            raise ProofInspectionError("invalid_node_runtime")
        return cls(artifacts, pinned_bundle(bundle_path, bundle_sha256), node)

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
        proc = None
        with tempfile.TemporaryDirectory(prefix="clearproof-pairing-") as directory:
            script = Path(directory) / "runtime.cjs"
            script.write_bytes(self.bundle + b"\n" + _RUNNER.encode("ascii"))
            try:
                creation = asyncio.create_task(
                    asyncio.create_subprocess_exec(
                        str(self.node),
                        "--max-old-space-size=256",
                        str(script),
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
                    # Retain ownership even if cancellation races process creation.
                    proc = await creation
                    raise
                # The pinned runtime is trusted; its wrapper emits exactly one byte.
                stdout, _ = await asyncio.wait_for(proc.communicate(payload), timeout=timeout)
                if proc.returncode != 0 or stdout not in (b"0", b"1"):
                    raise ProofInspectionError("pairing_runtime_failed")
                return PairingInspection(stdout == b"1", self.artifacts.manifest.digest)
            except asyncio.TimeoutError:
                raise ProofInspectionError("pairing_timeout") from None
            except OSError:
                raise ProofInspectionError("pairing_runtime_unavailable") from None
            finally:
                # Timeout and task cancellation both reap the owned process group.
                if proc is not None and proc.returncode is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await proc.wait()
