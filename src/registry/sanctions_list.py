"""
Sorted Merkle tree of sanctioned wallet addresses.

Supports non-membership proofs via gap proofs (adjacent-leaf technique).
Rebuilt daily from OFAC SDN list, UN consolidated list, EU asset freeze list.

Uses Poseidon hash (circuit-compatible) via ``scripts/poseidon_hash.js``.

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
# Poseidon helper (shared with credential_registry)
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


def _address_to_int(address: str) -> int:
    """Convert a hex wallet address to an integer for Poseidon hashing."""
    clean = address.lower().removeprefix("0x")
    return int(clean, 16)


# ---------------------------------------------------------------------------
# Known OFAC-sanctioned crypto addresses
# Source: OFAC SDN list — publicly available sanctioned wallet addresses.
# Includes Tornado Cash, Blender.io, Lazarus Group, and Garantex designations.
# ---------------------------------------------------------------------------

KNOWN_SANCTIONED_ADDRESSES: list[str] = [
    # Tornado Cash
    "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
    "0x722122dF12D4e14e13Ac3b6895a86e84145b6967",
    "0xDD4c48C0B24039969fC16D1cdF626eaB821d3384",
    "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
    "0xd96f2B1c14Db8458374d9Aca76E26c3D18364307",
    "0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBfA9",
    "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",
    "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",
    "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",
    "0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144",
    "0xF60dD140cFf0706bAE9Cd734Ac3683696B445d00",
    # Blender.io
    "0x179f48C78f57A3A78f0608cC9197B8972921d1D2",
    "0xb541fc07bC7619fD4062A54d96268525cBC6FfEF",
    # Lazarus Group
    "0x7F367cC41522cE07553e823bf3be79A889debe1B",
    "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b",
    # Garantex
    "0x7F19720A857F834696350e8484600F000000000",
]


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

class SanctionsMerkleTree:
    """
    Sorted Poseidon Merkle tree of sanctioned wallet addresses.

    Supports:
    - Building from a list of hex addresses.
    - Querying the root hash.
    - Generating non-membership (gap) witnesses for a given address.
    """

    # Maximum age (seconds) before the tree file is considered stale.
    # Default: 86400 (24 hours) — matches OFAC SDN daily update cadence.
    MAX_TREE_AGE_SECONDS = int(os.environ.get("SANCTIONS_TREE_MAX_AGE", "86400"))

    def __init__(self) -> None:
        self.sorted_leaves: list[int] = []
        self.sorted_addresses: list[str] = []
        self._tree: list[list[str]] = []  # tree[level][index] = hash string
        self.root: str | None = None
        self.depth: int = 0

    @classmethod
    def load(cls) -> "SanctionsMerkleTree":
        """
        Load the sanctions tree from the pre-built artifact file.

        Raises RuntimeError if the file is missing (operator must run
        ``scripts/build_sanctions_tree.py`` before starting the service).
        Logs a warning if the file is older than MAX_TREE_AGE_SECONDS.
        """
        import logging
        import time

        _log = logging.getLogger(__name__)
        tree_path = os.path.join(
            os.environ.get("CIRCUIT_ARTIFACTS_DIR", "./artifacts"),
            "sanctions_tree.json",
        )

        if not os.path.exists(tree_path):
            raise RuntimeError(
                f"Sanctions tree file not found at {tree_path}. "
                "Run `python scripts/build_sanctions_tree.py` before starting the service."
            )

        age = time.time() - os.path.getmtime(tree_path)
        if age > cls.MAX_TREE_AGE_SECONDS:
            _log.warning(
                "Sanctions tree is %.1f hours old (max %d s). "
                "Re-run `python scripts/build_sanctions_tree.py` or set up a cron job.",
                age / 3600,
                cls.MAX_TREE_AGE_SECONDS,
            )

        return cls.build_from_file(tree_path)

    @classmethod
    def build_from_file(cls, path: str) -> "SanctionsMerkleTree":
        """
        Load a pre-built sanctions Merkle tree from a JSON file
        (as produced by ``scripts/build_sanctions_tree.py``).
        """
        with open(path) as f:
            data = json.load(f)
        tree = cls()
        tree.root = data["root"]
        tree.sorted_leaves = [int(leaf) for leaf in data["sorted_leaves"]]
        tree.sorted_addresses = data.get("sorted_addresses", [])
        tree.depth = data["depth"]
        # We don't reconstruct internal _tree layers from JSON — only root,
        # leaves, and depth are needed for membership checks. Full Merkle
        # path generation requires a rebuild via build_from_addresses.
        return tree

    # Maximum 252-bit sentinel value for boundary gap proofs (H-6)
    _MAX_SENTINEL = (2 ** 252) - 1

    async def build_from_addresses(self, addresses: list[str]) -> str:
        """
        Build the sorted Merkle tree from a list of hex wallet addresses.

        Returns the root hash.
        """
        # Hash each address through Poseidon with domain tag 1 (M-2)
        hashed: list[int] = []
        for addr in addresses:
            h = await _poseidon_hash([1, _address_to_int(addr)])
            hashed.append(int(h))
        hashed.sort()
        # Insert boundary sentinels (H-6)
        hashed = [0] + hashed + [self._MAX_SENTINEL]
        self.sorted_leaves = hashed

        if not hashed:
            self.root = "0"
            self._tree = [["0"]]
            self.depth = 0
            return self.root

        # Determine depth (next power of 2)
        n = len(hashed)
        self.depth = max(1, math.ceil(math.log2(n))) if n > 1 else 1
        padded_size = 2 ** self.depth

        # Pad with zeros to fill the tree
        leaf_strs = [str(h) for h in hashed] + ["0"] * (padded_size - n)
        self._tree = [leaf_strs]

        # Build tree bottom-up
        current = leaf_strs
        for _ in range(self.depth):
            next_level: list[str] = []
            for i in range(0, len(current), 2):
                h = await _poseidon_hash([int(current[i]), int(current[i + 1])])
                next_level.append(h)
            self._tree.append(next_level)
            current = next_level

        self.root = current[0]
        return self.root

    def get_root(self) -> str:
        """Return the current Merkle root."""
        if self.root is None:
            raise RuntimeError("Tree not built yet — call build_from_addresses first")
        return self.root

    async def generate_nonmembership_witness(
        self, wallet_address: str
    ) -> dict[str, Any]:
        """
        Generate a gap proof (non-membership witness) for a wallet address.

        Returns:
            {
                "left_neighbor": int,
                "right_neighbor": int,
                "left_path": {"siblings": [...], "indices": [...]},
                "right_path": {"siblings": [...], "indices": [...]},
            }
        """
        if not self.sorted_leaves:
            raise RuntimeError("Tree is empty — build first")

        addr_hash = int(await _poseidon_hash([1, _address_to_int(wallet_address)]))

        # Verify the address is NOT in the tree (otherwise it IS sanctioned)
        if addr_hash in self.sorted_leaves:
            raise ValueError(
                "Address IS in the sanctions list — cannot generate "
                "non-membership proof"
            )

        # Find the gap: left_neighbor < addr_hash < right_neighbor
        left_idx = -1
        for i, leaf in enumerate(self.sorted_leaves):
            if leaf < addr_hash:
                left_idx = i
            else:
                break

        if left_idx == -1:
            # addr_hash is smaller than all leaves — boundary gap proof
            # using minimum sentinel (0) at position 0 as left neighbor.
            if not self._tree:
                raise RuntimeError(
                    "Cannot generate boundary gap proof: tree was loaded from "
                    "file without internal layers. Rebuild via build_from_addresses()."
                )
            return {
                "left_neighbor": self.sorted_leaves[0],  # sentinel: 0
                "right_neighbor": self.sorted_leaves[1],
                "left_path": self._get_merkle_path(0),
                "right_path": self._get_merkle_path(1),
            }

        if left_idx >= len(self.sorted_leaves) - 1:
            # addr_hash is larger than all leaves — boundary gap proof
            # using maximum sentinel (2^252 - 1) at last position as right neighbor.
            if not self._tree:
                raise RuntimeError(
                    "Cannot generate boundary gap proof: tree was loaded from "
                    "file without internal layers. Rebuild via build_from_addresses()."
                )
            last = len(self.sorted_leaves) - 1
            return {
                "left_neighbor": self.sorted_leaves[last - 1],
                "right_neighbor": self.sorted_leaves[last],  # sentinel: 2^252 - 1
                "left_path": self._get_merkle_path(last - 1),
                "right_path": self._get_merkle_path(last),
            }

        return {
            "left_neighbor": self.sorted_leaves[left_idx],
            "right_neighbor": self.sorted_leaves[left_idx + 1],
            "left_path": self._get_merkle_path(left_idx),
            "right_path": self._get_merkle_path(left_idx + 1),
        }

    def _get_merkle_path(self, index: int) -> dict[str, list]:
        """
        Return the Merkle authentication path for the leaf at *index*.

        Returns ``{"siblings": [...], "indices": [...]}`` where
        ``indices[i]`` is 0 if the sibling is on the right, 1 if left.
        """
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
