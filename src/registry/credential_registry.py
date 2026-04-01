"""
zkKYC credential management.

Credentials are issued off-chain by trusted KYC providers.  Only the
Poseidon commitment is ever stored on-chain.  The full record is held
by the user's wallet.

NOTE: All subprocess calls use asyncio.create_subprocess_exec (argument-list
form, no shell) to prevent command injection.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Poseidon hash helper (delegates to circomlibjs via Node.js)
# ---------------------------------------------------------------------------

_POSEIDON_SCRIPT = os.environ.get(
    "POSEIDON_HASH_SCRIPT",
    os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "poseidon_hash.js"),
)


async def _poseidon_hash(inputs: list[int | str]) -> str:
    """
    Compute a Poseidon hash that is compatible with circomlib's
    in-circuit implementation.

    Delegates to ``scripts/poseidon_hash.js`` via subprocess
    (create_subprocess_exec — no shell).
    """
    proc = await asyncio.create_subprocess_exec(
        "node", _POSEIDON_SCRIPT,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    payload = json.dumps([str(v) for v in inputs]).encode()
    stdout, stderr = await asyncio.wait_for(proc.communicate(input=payload), timeout=10)
    if proc.returncode != 0:
        raise RuntimeError(f"Poseidon hash failed: {stderr.decode().strip()}")
    return stdout.decode().strip()


# ---------------------------------------------------------------------------
# Credential model
# ---------------------------------------------------------------------------

class zkKYCCredential(BaseModel):
    """
    Off-chain credential issued by a trusted KYC provider.

    Only the ``commitment`` is ever stored on-chain.
    The full record is held by the user's wallet.
    """

    credential_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    issuer_did: str
    subject_wallet: str  # wallet address — NOT stored in proof
    jurisdiction: str  # ISO 3166-1 alpha-2
    kyc_tier: Literal["retail", "professional", "institutional"]
    sanctions_clear: bool  # issuer attests sanctions check passed
    issued_at: int  # Unix timestamp
    expires_at: int  # Unix timestamp
    revoked: bool = False

    # ------------------------------------------------------------------
    # Encode fields as integers for Poseidon hashing inside the circuit.
    # ------------------------------------------------------------------

    _KYC_TIER_MAP: dict[str, int] = {
        "retail": 1,
        "professional": 2,
        "institutional": 3,
    }

    def _field_ints(self) -> list[int]:
        """Return an ordered list of integer-encoded credential fields.

        MUST match the circuit's Poseidon(5) input ordering in
        credential_validity.circom:
          Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
        """
        import hashlib as _hashlib
        return [
            int.from_bytes(_hashlib.sha256(self.issuer_did.encode()).digest()[:16], "big"),
            self._KYC_TIER_MAP[self.kyc_tier],
            1 if self.sanctions_clear else 0,
            self.issued_at,
            self.expires_at,
        ]


# ---------------------------------------------------------------------------
# Registry (in-memory MVP)
# ---------------------------------------------------------------------------

class CredentialRegistry:
    """
    In-memory credential registry.

    Stores credentials keyed by ``credential_id``.
    Commitments are Poseidon hashes computed via circomlibjs.
    """

    def __init__(self) -> None:
        self._credentials: dict[str, zkKYCCredential] = {}
        self._commitments: dict[str, str] = {}  # credential_id -> commitment
        self._revoked: set[str] = set()

    async def issue(self, credential: zkKYCCredential) -> str:
        """
        Register a new credential and compute its Poseidon commitment.

        Returns the commitment hash string.
        """
        self._credentials[credential.credential_id] = credential
        commitment = await _poseidon_hash(credential._field_ints())
        self._commitments[credential.credential_id] = commitment
        return commitment

    def revoke(self, credential_id: str) -> None:
        """Mark a credential as revoked."""
        if credential_id not in self._credentials:
            raise KeyError(f"Unknown credential: {credential_id}")
        self._credentials[credential_id].revoked = True
        self._revoked.add(credential_id)

    def get_commitment(self, credential_id: str) -> str:
        """Return the Poseidon commitment for a credential."""
        if credential_id not in self._commitments:
            raise KeyError(f"No commitment for credential: {credential_id}")
        return self._commitments[credential_id]

    def is_revoked(self, credential_id: str) -> bool:
        """Check whether a credential has been revoked."""
        return credential_id in self._revoked

    def get(self, credential_id: str) -> zkKYCCredential | None:
        """Retrieve a credential by ID, or ``None`` if not found."""
        return self._credentials.get(credential_id)
