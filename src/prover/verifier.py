"""
Standalone Groth16 verifier — wraps ``snarkjs groth16 verify``.

This module is intentionally decoupled from SnarkJSProver so that
verification can be performed by any party (beneficiary VASP, auditor)
without access to the proving key or WASM circuit.

NOTE: All subprocess calls use asyncio.create_subprocess_exec (argument-list
form, no shell) to prevent command injection.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any


async def verify_proof(
    proof_json: dict[str, Any],
    public_json: list[str],
    vkey_path: str,
    timeout: int = 10,
) -> bool:
    """
    Verify a Groth16 proof against a verification key.

    Args:
        proof_json: The Groth16 proof object (pi_a, pi_b, pi_c, protocol, curve).
        public_json: List of public signal strings.
        vkey_path: Filesystem path to the verification key JSON.
        timeout: Maximum seconds to wait for snarkjs.

    Returns:
        ``True`` if verification succeeds, ``False`` otherwise.
    """
    vk = Path(vkey_path)
    if not vk.exists():
        raise FileNotFoundError(f"Verification key not found: {vk}")

    # Strip any metadata we may have injected
    proof_clean = {k: v for k, v in proof_json.items() if not k.startswith("_")}

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
        json.dump(public_json, public_fd)
        public_fd.close()

        # Uses create_subprocess_exec (argument-list, no shell injection)
        proc = await asyncio.create_subprocess_exec(
            "npx", "snarkjs", "groth16", "verify",
            str(vk),
            str(public_path),
            str(proof_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return "OK" in stdout.decode()

    except asyncio.TimeoutError:
        return False

    finally:
        proof_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
