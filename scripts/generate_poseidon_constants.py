#!/usr/bin/env python3
"""
Clean-room Poseidon parameter (round constants + MDS matrix) generator.

Implements the Grain-LFSR-based parameter generation algorithm published in
the Poseidon paper ("Poseidon: A New Hash Function for Zero-Knowledge Proof
Systems", Grassi et al., https://eprint.iacr.org/2019/458.pdf) and its public
reference parameter script, for the BN254 scalar field with S-box x^5,
R_F = 8, and the per-t partial-round counts used by circomlib.

Why this exists: circomlibjs ships these constants in a GPL-3.0-licensed
package, and ADR 0001 established a no-GPL policy for this repository. The
constants are mathematical values fully determined by the public algorithm;
generating them independently with this Apache-2.0 script keeps provenance
clean. Byte-for-byte equality with the circomlibjs values is verified at
generation time (and re-verified by tests/unit/test_poseidon.py against
hardcoded hash vectors).

Usage:
    python scripts/generate_poseidon_constants.py [--verify-only]

Output:
    src/registry/poseidon_constants.json  {"C": [...], "M": [...]} indexed
    by (t - 2), matching the circomlibjs poseidon_constants.json layout.
"""

from __future__ import annotations

import argparse
import json
import os

# BN254 scalar field order (prime p).
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

FIELD_BITS = 254
SBOX_POWER = 5
N_ROUNDS_F = 8
# Partial rounds per state size t = 2..17 (circomlib parameterization,
# from the Poseidon paper's round-number bounds, rounded up to divide t).
N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]

OUTPUT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "registry", "poseidon_constants.json"
)


class GrainLFSR:
    """
    Grain-80 LFSR as specified for Poseidon parameter generation.

    State is initialized with the 80-bit sequence:
        field(2) | sbox(4) | n(12) | t(12) | R_F(10) | R_P(10) | 1x30
    (each integer MSB-first), followed by a 160-step warm-up. Output bits use
    the reference filter: draw a candidate bit; if it is 0, consume two more
    bits and use the second as the next candidate; if it is 1, draw one more
    bit and return it.
    """

    def __init__(self, t: int, n_rounds_p: int) -> None:
        def bits(value: int, width: int) -> list[int]:
            return [(value >> (width - 1 - i)) & 1 for i in range(width)]

        self._state: list[int] = (
            bits(1, 2)  # prime field
            + bits(0, 4)  # S-box: x^alpha (power map)
            + bits(FIELD_BITS, 12)
            + bits(t, 12)
            + bits(N_ROUNDS_F, 10)
            + bits(n_rounds_p, 10)
            + [1] * 30
        )
        assert len(self._state) == 80
        for _ in range(160):
            self._raw_bit()

    def _raw_bit(self) -> int:
        s = self._state
        new_bit = s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
        self._state.pop(0)
        self._state.append(new_bit)
        return new_bit

    def next_bit(self) -> int:
        """Filtered output bit, matching the reference grain_sr_generator."""
        candidate = self._raw_bit()
        while candidate == 0:
            self._raw_bit()  # consumed and discarded by the reference filter
            candidate = self._raw_bit()
        return self._raw_bit()

    def next_bits_as_int(self, n: int) -> int:
        """Sample n filtered bits, MSB first, as an integer (no reduction)."""
        value = 0
        for _ in range(n):
            value = (value << 1) | self.next_bit()
        return value

    def next_field_element(self) -> int:
        """Sample a FIELD_BITS-wide value; rejection-sample until < p."""
        while True:
            value = self.next_bits_as_int(FIELD_BITS)
            if value < P:
                return value


def generate_parameters(t: int, n_rounds_p: int) -> tuple[list[int], list[list[int]]]:
    """Generate (round_constants, mds_matrix) for state size t."""
    lfsr = GrainLFSR(t, n_rounds_p)

    # Round constants: (R_F + R_P) rounds x t elements.
    round_constants = [
        lfsr.next_field_element() for _ in range((N_ROUNDS_F + n_rounds_p) * t)
    ]

    # MDS matrix (Cauchy): draw 2t values reduced mod p (NO < p rejection);
    # if any of the 2t are duplicated, or any x_i + y_j == 0, redraw ALL 2t.
    # M[i][j] = 1 / (x_i + y_j).
    while True:
        rand_list = [lfsr.next_bits_as_int(FIELD_BITS) % P for _ in range(2 * t)]
        if len(set(rand_list)) != 2 * t:
            continue
        xs, ys = rand_list[:t], rand_list[t:]
        if any((xs[i] + ys[j]) % P == 0 for i in range(t) for j in range(t)):
            continue
        mds = [[pow((xs[i] + ys[j]) % P, P - 2, P) for j in range(t)] for i in range(t)]
        break

    return round_constants, mds


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="regenerate and compare against the committed file without writing",
    )
    args = parser.parse_args()

    constants: dict[str, list] = {"C": [], "M": []}
    for i, n_rounds_p in enumerate(N_ROUNDS_P):
        t = i + 2
        C, M = generate_parameters(t, n_rounds_p)
        constants["C"].append([hex(c) for c in C])
        constants["M"].append([[hex(v) for v in row] for row in M])
        print(f"t={t:2d}  R_P={n_rounds_p:2d}  constants={len(C)}  done")

    if args.verify_only:
        with open(OUTPUT_PATH) as f:
            committed = json.load(f)
        if committed == constants:
            print("VERIFY OK: regenerated parameters match the committed file")
        else:
            raise SystemExit("VERIFY FAILED: regenerated parameters differ from committed file")
        return

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(constants, f)
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
