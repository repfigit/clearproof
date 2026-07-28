"""
Native Python Poseidon hash over the BN254 scalar field.

Drop-in replacement for the previous Node.js subprocess bridge
(``scripts/poseidon_hash.js`` + circomlibjs). Implements the standard
(reference) Poseidon permutation, so outputs match circomlib's in-circuit
``Poseidon(n)`` template bit-for-bit.

Round constants and MDS matrices in ``poseidon_constants.json`` are generated
clean-room by ``scripts/generate_poseidon_constants.py`` (Apache-2.0) from
the public Grain-LFSR parameter algorithm in the Poseidon paper
(https://eprint.iacr.org/2019/458.pdf). They are NOT vendored from
circomlibjs (GPL-3.0) — see ADR 0001 for the repository's no-GPL policy.
Regenerate/verify with:

    python scripts/generate_poseidon_constants.py --verify-only

Parity with circomlibjs is enforced by tests/unit/test_poseidon.py.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache

__all__ = ["BN254_SCALAR_FIELD", "poseidon_hash"]

# BN254 (alt_bn128) scalar field order.
BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

_CONSTANTS_PATH = os.path.join(os.path.dirname(__file__), "poseidon_constants.json")

_N_ROUNDS_F = 8
_N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]

_P = BN254_SCALAR_FIELD


@lru_cache(maxsize=1)
def _load_constants() -> dict[str, list]:
    """Load and pre-parse the generated round constants (cached process-wide)."""
    with open(_CONSTANTS_PATH) as f:
        raw = json.load(f)

    def to_int(v: str | int) -> int:
        if isinstance(v, int):
            return v
        return int(v, 16) if v.startswith("0x") else int(v)

    return {
        "C": [[to_int(x) for x in row] for row in raw["C"]],
        "M": [[[to_int(x) for x in row] for row in mat] for mat in raw["M"]],
    }


def _pow5(a: int) -> int:
    a2 = a * a % _P
    return a2 * a2 % _P * a % _P


def poseidon_hash(inputs: list[int | str]) -> int:
    """
    Compute Poseidon(inputs) over the BN254 scalar field.

    Matches circomlib's in-circuit ``Poseidon(len(inputs))`` template (and
    therefore circomlibjs) exactly.

    Args:
        inputs: 1 to 16 field elements as ints or decimal/hex strings.
            Values are reduced mod the BN254 scalar field order.

    Returns:
        The hash as an integer (state[0] after the permutation).

    Raises:
        ValueError: If inputs are empty or exceed 16 elements.
    """
    if not inputs:
        raise ValueError("Poseidon requires at least 1 input")
    if len(inputs) > len(_N_ROUNDS_P):
        raise ValueError(f"Poseidon supports at most {len(_N_ROUNDS_P)} inputs, got {len(inputs)}")

    def to_field(v: int | str) -> int:
        if isinstance(v, str):
            return (int(v, 16) if v.startswith("0x") else int(v)) % _P
        return int(v) % _P

    consts = _load_constants()
    t = len(inputs) + 1
    idx = t - 2
    n_rounds_f = _N_ROUNDS_F
    n_rounds_p = _N_ROUNDS_P[idx]
    C = consts["C"][idx]
    M = consts["M"][idx]

    state = [0] + [to_field(v) for v in inputs]

    half_f = n_rounds_f // 2
    for r in range(n_rounds_f + n_rounds_p):
        base = r * t
        state = [(a + C[base + i]) % _P for i, a in enumerate(state)]
        if r < half_f or r >= half_f + n_rounds_p:
            state = [_pow5(a) for a in state]
        else:
            state[0] = _pow5(state[0])
        state = [sum(M[i][j] * state[j] for j in range(t)) % _P for i in range(t)]

    return state[0]
