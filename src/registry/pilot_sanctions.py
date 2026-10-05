"""Versioned raw-address sanctions tree for the pilot proof profile."""

import re
from bisect import bisect_left

from src.protocol.canonical import record_digest
from src.registry.pilot_tree import MAX_TREE_DEPTH, SANCTIONS_TREE_DEPTH, PilotTree
from src.registry.poseidon import poseidon_hash

ARTIFACT_SCHEMA = "clearproof-pilot-sanctions-tree-v1"
PROFILE = "pilot-raw-address-sanctions-v1"
LEAF_DOMAIN_TAG = 301
ORDERING = "ascending-uint160-address-key"
SENTINELS = ("0", str(2**160))


class PilotSanctionsTree:
    def __init__(self, addresses: list[str], *, depth: int = SANCTIONS_TREE_DEPTH):
        # Two leaves are reserved for the 0 and 2^160 sentinels.
        if (
            type(depth) is not int
            or not 1 <= depth <= MAX_TREE_DEPTH
            or type(addresses) is not list
            or len(addresses) > 2**depth - 2
        ):
            raise ValueError("Sanctions input exceeds tree capacity")
        keys = [self.address_key(address) for address in addresses]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate sanctions address")
        self._keys = tuple(sorted([0, *keys, 2**160]))
        self._tree = PilotTree(
            [(f"{key:064x}", str(poseidon_hash([LEAF_DOMAIN_TAG, key]))) for key in self._keys], depth=depth
        )

    @staticmethod
    def address_key(address: str) -> int:
        if type(address) is not str or not re.fullmatch(r"0x[0-9a-f]{40}", address) or int(address, 16) == 0:
            raise ValueError("Expected nonzero canonical raw EVM address")
        return int(address, 16)

    @property
    def root(self) -> str:
        return self._tree.root

    @property
    def depth(self) -> int:
        return self._tree.depth

    @property
    def source_digest(self) -> str:
        return record_digest(
            "clearproof/pilot-sanctions-source/v1",
            {
                "profile": PROFILE,
                "depth": self.depth,
                "keys": [str(key) for key in self._keys],
            },
        )

    @property
    def addresses(self) -> tuple[str, ...]:
        """Canonical addresses in leaf order (ascending key), excluding both sentinels."""
        return tuple(f"0x{key:040x}" for key in self._keys[1:-1])

    def artifact(self) -> dict:
        """Public, re-verifiable description: anyone can rebuild the root from the address list."""
        return {
            "schema_version": ARTIFACT_SCHEMA,
            "profile": PROFILE,
            "depth": self.depth,
            "root": self.root,
            "source_digest": self.source_digest,
            "leaf_domain_tag": LEAF_DOMAIN_TAG,
            "ordering": ORDERING,
            "sentinels": list(SENTINELS),
            "address_count": len(self._keys) - 2,
            "leaf_count": len(self._keys),
            "sorted_addresses": list(self.addresses),
        }

    @classmethod
    def from_artifact(cls, data: dict, *, depth: int = SANCTIONS_TREE_DEPTH) -> "PilotSanctionsTree":
        """Rebuild from a published artifact and reject any ordering, count or root mismatch.

        The circuit checks gap adjacency only, so non-membership is sound only for a tree
        whose leaves are sorted by key. Re-verifying from the published list checks that.
        """
        if type(data) is not dict or data.get("schema_version") != ARTIFACT_SCHEMA or data.get("profile") != PROFILE:
            raise ValueError("Unsupported pilot sanctions artifact")
        addresses = data.get("sorted_addresses")
        if type(addresses) is not list:
            raise ValueError("Pilot sanctions artifact requires an address list")
        keys = [cls.address_key(address) for address in addresses]
        if any(left >= right for left, right in zip(keys, keys[1:])):
            raise ValueError("Pilot sanctions addresses are not strictly sorted by key")
        tree = cls(addresses, depth=depth)
        if tree.artifact() != {name: data.get(name) for name in tree.artifact()}:
            raise ValueError("Pilot sanctions artifact does not match its rebuilt tree")
        return tree

    def gap(self, address: str) -> dict:
        key = self.address_key(address)
        index = bisect_left(self._keys, key)
        if self._keys[index] == key:
            raise ValueError("Wallet is present in sanctions tree")
        left, right = self._keys[index - 1], self._keys[index]
        lp, rp = self._tree.membership(f"{left:064x}"), self._tree.membership(f"{right:064x}")
        return {
            "left_key": str(left),
            "right_key": str(right),
            "left_siblings": lp["siblings"],
            "right_siblings": rp["siblings"],
            "left_indices": lp["indices"],
            "right_indices": rp["indices"],
        }
