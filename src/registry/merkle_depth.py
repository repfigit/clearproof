"""Extend a constructed tree with zero subtrees without allocating all leaves."""

from collections.abc import Awaitable, Callable


def validate_depth(depth: int | None) -> None:
    if depth is not None and (type(depth) is not int or not 1 <= depth <= 32):
        raise ValueError("Merkle depth must be an integer between 1 and 32")


async def extend_depth(
    layers: list[list[str]], depth: int, hash_pair: Callable[[list[int]], Awaitable[str]]
) -> str:
    current_depth = len(layers) - 1
    if current_depth > depth:
        raise ValueError("Merkle tree exceeds configured depth")
    zero = "0"
    for _ in range(current_depth):
        zero = await hash_pair([int(zero), int(zero)])
    for _ in range(current_depth, depth):
        root = await hash_pair([int(layers[-1][0]), int(zero)])
        layers[-1].append(zero)
        layers.append([root])
        zero = await hash_pair([int(zero), int(zero)])
    return layers[-1][0]
