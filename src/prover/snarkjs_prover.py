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

from src.prover._subprocess import run_tool
from src.prover.verifier import verify_proof


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
        base = Path(artifacts_dir or os.environ.get("ZK_ARTIFACTS_DIR", "./artifacts"))
        self.wasm_path = Path(
            wasm_path or os.environ.get("ZK_WASM_PATH", str(base / "compliance_js" / "compliance.wasm"))
        )
        self.zkey_path = Path(zkey_path or os.environ.get("ZK_ZKEY_PATH", str(base / "compliance_final.zkey")))
        self.vkey_path = Path(vkey_path or os.environ.get("ZK_VKEY_PATH", str(base / "verification_key.json")))
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

        with tempfile.TemporaryDirectory(prefix="clearproof-prove-") as directory:
            base = Path(directory)
            input_path = base / "input.json"
            witness_path = base / "witness.wtns"
            proof_path = base / "proof.json"
            public_path = base / "public.json"
            input_path.write_text(json.dumps(inputs))
            try:
                code = await run_tool(
                    "node",
                    str(self.witness_js),
                    str(self.wasm_path),
                    str(input_path),
                    str(witness_path),
                    timeout=self.witness_timeout,
                )
                if code != 0:
                    raise ProverError(f"Witness generation failed (rc={code})")
                code = await run_tool(
                    "npx",
                    "--no-install",
                    "snarkjs",
                    "groth16",
                    "prove",
                    str(self.zkey_path),
                    str(witness_path),
                    str(proof_path),
                    str(public_path),
                    timeout=self.prove_timeout,
                )
                if code != 0:
                    raise ProverError(f"Proof generation failed (rc={code})")
                proof = json.loads(proof_path.read_text())
                public_signals = json.loads(public_path.read_text())
                proof["_meta"] = {"proving_time_ms": int((time.monotonic() - start) * 1000)}
                return proof, public_signals
            except asyncio.TimeoutError as exc:
                raise ProverError("Proof generation timed out") from exc

    async def verify(self, proof: dict[str, Any], public_signals: list[str]) -> bool:
        """
        Verify a Groth16 proof locally using the verification key.
        Deterministic, typically <50 ms.
        """
        return await verify_proof(proof, public_signals, str(self.vkey_path))
