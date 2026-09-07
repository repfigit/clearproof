"""Deterministic bounded sparse Poseidon tree, compatible with MerkleTreeVerifier."""

import re
from functools import lru_cache

from src.protocol.credential import scalar
from src.registry.poseidon import poseidon_hash


@lru_cache(maxsize=21)
def zero_root(depth: int) -> int:
    if depth == 0:
        return 0
    zero = zero_root(depth - 1)
    return poseidon_hash([zero, zero])


class PilotTree:
    def __init__(self, entries: list[tuple[str, str]], *, depth: int):
        if type(depth) is not int or not 1 <= depth <= 20:
            raise ValueError("Tree depth must be 1–20")
        if len(entries) > min(256, 2**depth):
            raise ValueError("Pilot tree capacity exceeded")
        for record_id, leaf in entries:
            if type(record_id) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", record_id):
                raise ValueError("Invalid tree entry ID")
            scalar(leaf, nonzero=True)
        if len({entry[0] for entry in entries}) != len(entries):
            raise ValueError("Duplicate tree entry ID")
        if len({entry[1] for entry in entries}) != len(entries):
            raise ValueError("Duplicate tree leaf")
        self._entries = tuple(sorted(entries))
        self._depth = depth
        layers = [{index: int(leaf) for index, (_, leaf) in enumerate(self._entries)}]
        for level in range(depth):
            previous = layers[-1]
            layers.append(
                {
                    parent: poseidon_hash(
                        [previous.get(parent * 2, zero_root(level)), previous.get(parent * 2 + 1, zero_root(level))]
                    )
                    for parent in {index // 2 for index in previous}
                }
            )
        self._layers = tuple(layers)

    @property
    def root(self) -> str:
        return str(self._layers[-1].get(0, zero_root(self._depth)))

    @property
    def entries(self) -> tuple[tuple[str, str], ...]:
        return self._entries

    @property
    def depth(self) -> int:
        return self._depth

    def membership(self, record_id: str) -> dict:
        indices_by_id = {key: index for index, (key, _) in enumerate(self._entries)}
        if record_id not in indices_by_id:
            raise KeyError("Tree entry not found")
        index = indices_by_id[record_id]
        siblings, indices = [], []
        for level in range(self._depth):
            siblings.append(str(self._layers[level].get(index ^ 1, zero_root(level))))
            indices.append(index & 1)
            index //= 2
        return {"root": self.root, "siblings": siblings, "indices": indices}
