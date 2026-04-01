"""
Trusted issuer registry backed by a Poseidon Merkle tree.

Maintains a set of trusted KYC-provider DIDs.  The Merkle root is used
inside the compliance circuit to verify that a credential was issued by
a recognised provider.

NOTE: All subprocess calls use asyncio.create_subprocess_exec (argument-list
form, no shell) to prevent command injection.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
from typing import Any

# ---------------------------------------------------------------------------
# Poseidon helper
# ---------------------------------------------------------------------------

_POSEIDON_SCRIPT = os.environ.get(
    "POSEIDON_HASH_SCRIPT",
    os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "poseidon_hash.js"),
)


async def _poseidon_hash(inputs: list[int | str]) -> str:
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


def _did_to_int(did: str) -> int:
    """Deterministically convert a DID string to an integer for Poseidon.

    Uses SHA-256 of the full DID to avoid collision risk from truncating
    raw UTF-8 bytes (M-3 fix).
    """
    import hashlib
    return int.from_bytes(hashlib.sha256(did.encode()).digest()[:16], "big")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class IssuerRegistry:
    """
    Merkle tree of trusted issuer DIDs.

    Provides membership witnesses that the compliance circuit uses to verify
    a credential's issuer is in the trusted set.
    """

    def __init__(self) -> None:
        self._issuers: list[str] = []  # ordered list of DIDs
        self._leaf_hashes: list[str] = []
        self._tree: list[list[str]] = []
        self.root: str | None = None
        self.depth: int = 0

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------

    async def add_issuer(self, did: str) -> str:
        """
        Add a trusted issuer DID and rebuild the tree.

        Returns the new root hash.
        """
        if did in self._issuers:
            raise ValueError(f"Issuer already registered: {did}")
        self._issuers.append(did)
        return await self._rebuild()

    async def remove_issuer(self, did: str) -> str:
        """
        Remove an issuer DID and rebuild the tree.

        Returns the new root hash.
        """
        if did not in self._issuers:
            raise KeyError(f"Issuer not found: {did}")
        self._issuers.remove(did)
        return await self._rebuild()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_root(self) -> str:
        """Return the current Merkle root."""
        if self.root is None:
            raise RuntimeError("Registry is empty — add at least one issuer")
        return self.root

    async def generate_membership_witness(self, did: str) -> dict[str, Any]:
        """
        Generate a Merkle membership witness for the given issuer DID.

        Returns:
            {
                "leaf": <Poseidon hash of DID>,
                "siblings": [...],
                "indices": [...],
                "root": <current root>,
            }

        Raises ``KeyError`` if the DID is not a registered issuer.
        """
        if did not in self._issuers:
            raise KeyError(f"Issuer not in registry: {did}")

        idx = self._issuers.index(did)
        path = self._get_merkle_path(idx)
        return {
            "leaf": self._leaf_hashes[idx],
            "siblings": path["siblings"],
            "indices": path["indices"],
            "root": self.root,
        }

    # ------------------------------------------------------------------
    # Internal tree building
    # ------------------------------------------------------------------

    async def _rebuild(self) -> str:
        """Rebuild the full Merkle tree from the current issuer list."""
        if not self._issuers:
            self._tree = []
            self._leaf_hashes = []
            self.root = None
            self.depth = 0
            return "0"

        # Compute leaf hashes with domain tag 2 (M-1: matches circuit's Poseidon(2, issuer_did))
        self._leaf_hashes = []
        for did in self._issuers:
            h = await _poseidon_hash([2, _did_to_int(did)])
            self._leaf_hashes.append(h)

        n = len(self._leaf_hashes)
        self.depth = max(1, math.ceil(math.log2(n))) if n > 1 else 1
        padded_size = 2 ** self.depth

        # Pad with zeros
        leaves = list(self._leaf_hashes) + ["0"] * (padded_size - n)
        self._tree = [leaves]

        # Build bottom-up
        current = leaves
        for _ in range(self.depth):
            next_level: list[str] = []
            for i in range(0, len(current), 2):
                h = await _poseidon_hash([int(current[i]), int(current[i + 1])])
                next_level.append(h)
            self._tree.append(next_level)
            current = next_level

        self.root = current[0]
        return self.root

    def _get_merkle_path(self, index: int) -> dict[str, list]:
        """Return Merkle authentication path for the leaf at *index*."""
        siblings: list[str] = []
        indices: list[int] = []
        idx = index
        for level in range(self.depth):
            if idx % 2 == 0:
                sibling_idx = idx + 1
                indices.append(0)
            else:
                sibling_idx = idx - 1
                indices.append(1)
            layer = self._tree[level]
            siblings.append(
                layer[sibling_idx] if sibling_idx < len(layer) else "0"
            )
            idx //= 2
        return {"siblings": siblings, "indices": indices}
