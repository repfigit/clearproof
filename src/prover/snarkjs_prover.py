"""
Python wrapper around SnarkJS for VASP-local proof generation.
No external network required — proofs generated entirely on VASP infrastructure.

SnarkJS is invoked via subprocess (Node.js).
Circuit artifacts (wasm, zkey) are compiled once and reused.

NOTE: All subprocess calls use asyncio.create_subprocess_exec (argument-list
form, no shell) to prevent command injection.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class ProverError(Exception):
    """Raised when proof generation or verification fails."""


class SnarkJSProver:
    """
    Local Groth16 prover using SnarkJS.

    Requires pre-compiled circuit artifacts:
      - compliance.wasm: compiled Circom circuit (WASM)
      - compliance_final.zkey: proving key (from trusted setup)
      - verification_key.json: verification key
    """

    def __init__(
        self,
        artifacts_dir: str | None = None,
        wasm_path: str | None = None,
        zkey_path: str | None = None,
        vkey_path: str | None = None,
        prove_timeout: int = 60,
        witness_timeout: int = 30,
    ) -> None:
        base = Path(
            artifacts_dir
            or os.environ.get("ZK_ARTIFACTS_DIR", "./artifacts")
        )
        self.wasm_path = Path(wasm_path or os.environ.get(
            "ZK_WASM_PATH", str(base / "compliance_js" / "compliance.wasm")
        ))
        self.zkey_path = Path(zkey_path or os.environ.get(
            "ZK_ZKEY_PATH", str(base / "compliance_final.zkey")
        ))
        self.vkey_path = Path(vkey_path or os.environ.get(
            "ZK_VKEY_PATH", str(base / "verification_key.json")
        ))
        self.witness_js = self.wasm_path.parent / "generate_witness.js"
        self.prove_timeout = prove_timeout
        self.witness_timeout = witness_timeout

    def _check_artifacts(self) -> None:
        """Validate that all required circuit artifacts exist on disk."""
        for label, path in [
            ("WASM circuit", self.wasm_path),
            ("Proving key (zkey)", self.zkey_path),
            ("Verification key", self.vkey_path),
        ]:
            if not path.exists():
                raise FileNotFoundError(f"{label} not found: {path}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fullprove(self, inputs: dict[str, Any]) -> tuple[dict, list]:
        """
        Generate a Groth16 proof from circuit input signals.

        Writes input.json to a temp file, invokes snarkjs witness generation
        and proving, and returns ``(proof_json, public_signals)``.
        """
        self._check_artifacts()
        start = time.monotonic()

        input_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        proof_file = tempfile.NamedTemporaryFile(
            suffix="_proof.json", delete=False
        )
        public_file = tempfile.NamedTemporaryFile(
            suffix="_public.json", delete=False
        )
        input_path = Path(input_file.name)
        proof_path = Path(proof_file.name)
        public_path = Path(public_file.name)
        proof_file.close()
        public_file.close()

        try:
            json.dump(inputs, input_file)
            input_file.close()

            # --- witness generation (uses create_subprocess_exec, no shell) ---
            witness_path = Path(tempfile.mktemp(suffix=".wtns"))
            proc = await asyncio.create_subprocess_exec(
                "node",
                str(self.witness_js),
                str(self.wasm_path),
                str(input_path),
                str(witness_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.witness_timeout
            )
            if proc.returncode != 0:
                raise ProverError(
                    f"Witness generation failed (rc={proc.returncode}): "
                    f"{stderr.decode().strip()}"
                )

            # --- groth16 prove (uses create_subprocess_exec, no shell) ---
            proc = await asyncio.create_subprocess_exec(
                "npx", "snarkjs", "groth16", "prove",
                str(self.zkey_path),
                str(witness_path),
                str(proof_path),
                str(public_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.prove_timeout
            )
            if proc.returncode != 0:
                raise ProverError(
                    f"Proof generation failed (rc={proc.returncode}): "
                    f"{stderr.decode().strip()}"
                )

            with open(proof_path) as f:
                proof = json.load(f)
            with open(public_path) as f:
                public_signals = json.load(f)

            elapsed_ms = int((time.monotonic() - start) * 1000)
            proof["_meta"] = {"proving_time_ms": elapsed_ms}

            return proof, public_signals

        except asyncio.TimeoutError as exc:
            raise ProverError("Proof generation timed out") from exc

        finally:
            for p in [input_path, proof_path, public_path]:
                p.unlink(missing_ok=True)
            if "witness_path" in locals():
                witness_path.unlink(missing_ok=True)

    async def verify(self, proof: dict[str, Any], public_signals: list[str]) -> bool:
        """
        Verify a Groth16 proof locally using the verification key.
        Deterministic, typically <50 ms.
        """
        self._check_artifacts()

        proof_clean = {k: v for k, v in proof.items() if k != "_meta"}

        proof_fd = tempfile.NamedTemporaryFile(
            mode="w", suffix="_proof.json", delete=False
        )
        public_fd = tempfile.NamedTemporaryFile(
            mode="w", suffix="_public.json", delete=False
        )
        proof_path = Path(proof_fd.name)
        public_path = Path(public_fd.name)

        try:
            json.dump(proof_clean, proof_fd)
            proof_fd.close()
            json.dump(public_signals, public_fd)
            public_fd.close()

            # Uses create_subprocess_exec (argument-list, no shell injection)
            proc = await asyncio.create_subprocess_exec(
                "npx", "snarkjs", "groth16", "verify",
                str(self.vkey_path),
                str(public_path),
                str(proof_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=10
            )
            return "OK" in stdout.decode()

        except asyncio.TimeoutError:
            return False

        finally:
            proof_path.unlink(missing_ok=True)
            public_path.unlink(missing_ok=True)
