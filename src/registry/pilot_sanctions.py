"""Versioned raw-address sanctions tree for the bounded development pilot."""

import re
from bisect import bisect_left

from src.protocol.canonical import record_digest
from src.registry.pilot_tree import PilotTree
from src.registry.poseidon import poseidon_hash


class PilotSanctionsTree:
    def __init__(self, addresses: list[str], *, depth: int = 8):
        if type(addresses) is not list or len(addresses) > 254:
            raise ValueError("Pilot sanctions input requires at most 254 addresses")
        keys = [self.address_key(address) for address in addresses]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate sanctions address")
        self._keys = tuple(sorted([0, *keys, 2**160]))
        self._tree = PilotTree([(f"{key:064x}", str(poseidon_hash([301, key]))) for key in self._keys], depth=depth)

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
                "profile": "pilot-raw-address-sanctions-v1",
                "depth": self.depth,
                "keys": [str(key) for key in self._keys],
            },
        )

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
