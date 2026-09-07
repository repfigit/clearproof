#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2022 The go-ethereum Authors
# SPDX-FileCopyrightText: 2026 clearproof contributors
# SPDX-License-Identifier: LGPL-3.0-or-later
# FastLZ port: op-geth 647c346e2bef36219cc7b47d76b1cb87e7ca29e4/core/types/rollup_cost.go
"""
Price a compliance-proof verification on L2: execution gas *plus* the L1
data-availability charge (AIF-99).

This historical model uses the legacy 16-signal profile and dated assumptions.
It does not estimate the current pilot or fetch current network fees.
The earlier ADR 0003 gas table was an L1 table. On a rollup the L1 DA term is a separate,
often dominant, cost and it scales with the *compressed size of the signed
transaction* — which is exactly where fflonk loses: 24 proof words against
Groth16's 8, i.e. 512 extra high-entropy (incompressible) bytes on every
proof. Whether the 32% execution-gas saving survives that is fee-regime
dependent, so this model reports a range rather than a point.

Two rollup fee models are implemented, both from the sequencer's own source:

  OP Stack (Base, OP Mainnet), post-Fjord — op-geth core/types/rollup_cost.go
      l1FeeScaled   = baseFeeScalar*l1BaseFee*16 + blobFeeScalar*blobBaseFee
      estSizeScaled = max(100e6, -42_585_600 + 836_500 * fastlzSize)
      l1Fee         = estSizeScaled * l1FeeScaled / 1e12
  where fastlzSize is FlzCompressLen over the whole signed tx envelope.

  Arbitrum Nitro (Arbitrum One) — the poster surcharge is billed as extra L2
  gas at the L2 gas price:
      extraGas = l1BaseFeeEstimate * 16 * (compressedBytes + overheadBytes)
                 / l2GasPrice
  Nitro compresses with brotli; for the incompressible proof words this model
  charges them at full size (see `estimate_compressed_size`).

Usage:
    uv run python scripts/l2_cost_model.py                    # built-in inputs
    uv run python scripts/l2_cost_model.py --inputs /tmp/l2-cost-inputs.json
    uv run python scripts/l2_cost_model.py --format json

Regenerate the measured inputs with:
    cd packages/contracts && npx hardhat test test/L2Cost.bench.ts
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

GWEI = 10**9
ETHER = 10**18

# --- op-geth Fjord constants (core/types/rollup_cost.go) ---------------------
L1_COST_INTERCEPT = -42_585_600
L1_COST_FASTLZ_COEF = 836_500
MIN_TRANSACTION_SIZE_SCALED = 100 * 1_000_000
FJORD_DIVISOR = 1_000_000_000_000

# --- Arbitrum Nitro ---------------------------------------------------------
# Nitro charges the batch poster's recoverable L1 spend as extra L2 gas:
#   posterCost = l1BaseFeeEstimate * 16 * (compressedBytes + overhead)
# The 16 is the EIP-2028 non-zero calldata rate the model is written in terms
# of; post-4844 the poster actually buys blobs, and Nitro compensates by
# tracking `l1BaseFeeEstimate` well below the L1 execution base fee.
ARBITRUM_L1_GAS_PER_BYTE = 16
# Flat per-tx allowance for the share of the batch envelope and the poster's
# own L1 execution gas that cannot be amortised away.
ARBITRUM_TX_OVERHEAD_BYTES = 140


# --------------------------------------------------------------------------- #
# FastLZ
# --------------------------------------------------------------------------- #
def flz_compress_len(ib: bytes) -> int:
    """Length of `ib` after FastLZ compression.

    A faithful port of op-geth's `FlzCompressLen`, including its uint32
    wraparound in `hash` and the off-by-one in `cmp`'s mismatch exit. Fidelity
    matters more than clarity here: this number is multiplied by 836_500 and
    charged to every proof, so a divergence from the sequencer's arithmetic is
    a divergence in the answer.
    """
    n = 0
    ht = [0] * 8192

    def u24(i: int) -> int:
        return ib[i] | (ib[i + 1] << 8) | (ib[i + 2] << 16)

    def cmp(p: int, q: int, e: int) -> int:
        # Note: `matched` is incremented even on the mismatch that zeroes `e`,
        # so a mismatch at offset k returns k+1. Matches op-geth.
        matched = 0
        e -= q
        while matched < e:
            if ib[p + matched] != ib[q + matched]:
                e = 0
            matched += 1
        return matched

    def literals(r: int) -> None:
        nonlocal n
        n += 0x21 * (r // 0x20)
        r %= 0x20
        if r != 0:
            n += r + 1

    def match(length: int) -> None:
        nonlocal n
        length = (length - 1) & 0xFFFFFFFF
        n += 3 * (length // 262)
        n += 3 if length % 262 >= 6 else 2

    def hash_(v: int) -> int:
        return (((2654435769 * v) & 0xFFFFFFFF) >> 19) & 0x1FFF

    def set_next_hash(ip: int) -> int:
        ht[hash_(u24(ip))] = ip
        return ip + 1

    size = len(ib)
    a = 0
    ip_limit = size - 13 if size >= 13 else 0

    ip = a + 2
    while ip < ip_limit:
        r = 0
        d = 0
        while True:
            s = u24(ip)
            h = hash_(s)
            r = ht[h]
            ht[h] = ip
            d = ip - r
            if ip >= ip_limit:
                break
            ip += 1
            if d <= 0x1FFF and s == u24(r):
                break
        if ip >= ip_limit:
            break
        ip -= 1
        if ip > a:
            literals(ip - a)
        length = cmp(r + 3, ip + 3, ip_limit + 9)
        match(length)
        ip = set_next_hash(set_next_hash(ip + length))
        a = ip

    literals(size - a)
    return n


def estimate_compressed_size(tx: bytes) -> int:
    """Brotli-compressed size of a signed tx, for the Arbitrum model.

    Arbitrum batches are brotli-compressed. We approximate with FastLZ, which
    is the weaker algorithm, so this over-states Arbitrum's DA cost slightly —
    conservative in the direction that *favours* fflonk, and therefore safe for
    a finding that goes against it. The dominant term either way is the ~500
    incompressible proof bytes, which neither algorithm can shrink.
    """
    return flz_compress_len(tx)


# --------------------------------------------------------------------------- #
# Inputs
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ProofSystem:
    name: str
    execution_gas: int
    signed_tx: bytes

    @property
    def fastlz_size(self) -> int:
        return flz_compress_len(self.signed_tx)


@dataclass(frozen=True)
class FeeRegime:
    """A named point in fee space. The answer is regime-dependent, so every
    figure this model emits is labelled with the regime that produced it."""

    name: str
    l1_base_fee_gwei: float
    blob_base_fee_wei: int
    eth_usd: float


@dataclass(frozen=True)
class Chain:
    name: str
    kind: str  # "op-stack" | "arbitrum"
    l2_gas_price_gwei: float
    # OP Stack
    base_fee_scalar: int = 0
    blob_base_fee_scalar: int = 0
    # Arbitrum: ArbGasInfo.getL1BaseFeeEstimate() expressed as a ratio of the
    # L1 blob base fee, so the surcharge tracks the regime instead of being
    # frozen at whatever it read on the day. Calibrated below.
    l1_estimate_per_blob_wei: float = 0.0
    notes: str = field(default="")


def op_stack_l1_fee(ps: ProofSystem, chain: Chain, regime: FeeRegime) -> int:
    """L1 DA fee in wei, per op-geth `NewL1CostFuncFjord`."""
    l1_base_fee = int(regime.l1_base_fee_gwei * GWEI)
    l1_fee_scaled = chain.base_fee_scalar * l1_base_fee * 16 + (chain.blob_base_fee_scalar * regime.blob_base_fee_wei)
    est_size_scaled = max(
        MIN_TRANSACTION_SIZE_SCALED,
        L1_COST_INTERCEPT + L1_COST_FASTLZ_COEF * ps.fastlz_size,
    )
    return est_size_scaled * l1_fee_scaled // FJORD_DIVISOR


def arbitrum_l1_fee(ps: ProofSystem, chain: Chain, regime: FeeRegime) -> int:
    """L1 poster surcharge in wei.

    Nitro bills this as extra L2 gas (`extraGas = posterCost / l2GasPrice`),
    but the wei amount is what we compare, so we skip the round-trip.
    """
    payload = estimate_compressed_size(ps.signed_tx) + ARBITRUM_TX_OVERHEAD_BYTES
    l1_estimate = int(chain.l1_estimate_per_blob_wei * regime.blob_base_fee_wei)
    return l1_estimate * ARBITRUM_L1_GAS_PER_BYTE * payload


def l1_fee_wei(ps: ProofSystem, chain: Chain, regime: FeeRegime) -> int:
    if chain.kind == "op-stack":
        return op_stack_l1_fee(ps, chain, regime)
    if chain.kind == "arbitrum":
        return arbitrum_l1_fee(ps, chain, regime)
    raise ValueError(f"unknown chain kind {chain.kind!r}")


@dataclass(frozen=True)
class CostBreakdown:
    chain: str
    regime: str
    system: str
    execution_gas: int
    execution_wei: int
    l1_wei: int

    @property
    def total_wei(self) -> int:
        return self.execution_wei + self.l1_wei

    def total_usd(self, eth_usd: float) -> float:
        return self.total_wei / ETHER * eth_usd

    @property
    def l1_share(self) -> float:
        return self.l1_wei / self.total_wei if self.total_wei else 0.0


def breakeven_blob_base_fee(
    baseline: ProofSystem,
    challenger: ProofSystem,
    chain: Chain,
    regime: FeeRegime,
    ceiling_wei: int = 10**12,
) -> int | None:
    """Blob base fee (wei per blob-gas) at which `challenger` stops being
    cheaper than `baseline`, holding everything else at `regime`.

    This is the number the L2 question actually turns on: not "is fflonk
    cheaper today" but "how far would blob fees have to move before it
    isn't". Returns None if the crossover is above `ceiling_wei`.
    """

    def cheaper(blob_wei: int) -> bool:
        r = FeeRegime(regime.name, regime.l1_base_fee_gwei, blob_wei, regime.eth_usd)
        return cost(challenger, chain, r).total_wei < cost(baseline, chain, r).total_wei

    if not cheaper(0):
        return 0
    if cheaper(ceiling_wei):
        return None

    lo, hi = 0, ceiling_wei
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if cheaper(mid):
            lo = mid
        else:
            hi = mid
    return hi


def breakeven_l1_base_fee_gwei(
    baseline: ProofSystem,
    challenger: ProofSystem,
    chain: Chain,
    ceiling_gwei: float = 1000.0,
) -> float | None:
    """L1 execution base fee at which `challenger` stops being cheaper.

    This scenario couples blob and L1 fees at the explicitly assumed ratio.
    The threshold is conditional on that assumption, not a network forecast.
    """

    def cheaper(l1_gwei: float) -> bool:
        r = regime_at_l1("probe", l1_gwei)
        return cost(challenger, chain, r).total_wei < cost(baseline, chain, r).total_wei

    if not cheaper(0.0):
        return 0.0
    if cheaper(ceiling_gwei):
        return None

    lo, hi = 0.0, ceiling_gwei
    for _ in range(60):
        mid = (lo + hi) / 2
        if cheaper(mid):
            lo = mid
        else:
            hi = mid
    return hi


def cost(ps: ProofSystem, chain: Chain, regime: FeeRegime) -> CostBreakdown:
    execution_wei = int(ps.execution_gas * chain.l2_gas_price_gwei * GWEI)
    return CostBreakdown(
        chain=chain.name,
        regime=regime.name,
        system=ps.name,
        execution_gas=ps.execution_gas,
        execution_wei=execution_wei,
        l1_wei=l1_fee_wei(ps, chain, regime),
    )


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def markdown(systems: list[ProofSystem], chains: list[Chain], regimes: list[FeeRegime]) -> str:
    lines: list[str] = []
    for regime in regimes:
        lines.append(
            f"#### {regime.name} "
            f"(L1 base fee {regime.l1_base_fee_gwei:g} gwei, "
            f"blob base fee {regime.blob_base_fee_wei:,} wei, "
            f"ETH ${regime.eth_usd:,.0f})"
        )
        lines.append("")
        lines.append("| Chain | System | Exec gas | Exec (USD) | L1 DA (USD) | Total (USD) | L1 share | vs Groth16 |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for chain in chains:
            baseline = cost(systems[0], chain, regime)
            for ps in systems:
                c = cost(ps, chain, regime)
                delta = "baseline" if ps is systems[0] else f"{c.total_wei / baseline.total_wei:.2f}×"
                lines.append(
                    f"| {c.chain} | {c.system} | {c.execution_gas:,} "
                    f"| ${c.execution_wei / ETHER * regime.eth_usd:.5f} "
                    f"| ${c.l1_wei / ETHER * regime.eth_usd:.5f} "
                    f"| ${c.total_usd(regime.eth_usd):.5f} "
                    f"| {c.l1_share * 100:.0f}% | {delta} |"
                )
        lines.append("")

    lines.append("#### Inversion thresholds")
    lines.append("")
    lines.append(
        f"How far L1 fees have to move before {systems[-1].name} stops being "
        f"cheaper than {systems[0].name}. This scenario couples blob base fee and L1 execution base "
        f"fee at an assumed fixed ratio; the thresholds are conditional."
    )
    lines.append("")
    lines.append("| Chain | Breakeven blob base fee | Breakeven L1 base fee | Headroom vs observed |")
    lines.append("|---|---|---|---|")
    observed = regimes[0]
    for chain in chains:
        blob = breakeven_blob_base_fee(systems[0], systems[-1], chain, observed)
        l1 = breakeven_l1_base_fee_gwei(systems[0], systems[-1], chain)
        blob_cell = "never" if blob is None else "already inverted" if blob == 0 else f"{blob:,} wei"
        l1_cell = "never" if l1 is None else f"{l1:.1f} gwei"
        headroom = "—" if l1 is None or l1 == 0 else f"{l1 / observed.l1_base_fee_gwei:.0f}×"
        lines.append(f"| {chain.name} | {blob_cell} | {l1_cell} | {headroom} |")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #
# Groth16: measured in packages/contracts/test/L2Cost.bench.ts against the
# committed vector (tests/vectors/compliance).
# fflonk: execution gas from the AIF-86 L1 spike; the signed tx is synthesised
# at fflonk's shape (24 proof words) and entropy. See FFLONK_BENCHMARK.md.
DEFAULT_INPUTS = {
    "groth16": {"execution_gas": 341_504, "signed_tx_bytes": 886},
    "fflonk": {"execution_gas": 232_646, "signed_tx_bytes": 1_398},
}


def _synthetic_tx(n: int, salt: int) -> bytes:
    """High-entropy filler standing in for a signed proof tx of `n` bytes.

    Proof words are uniform over ~254 bits, so a compressor gets nothing from
    them; a deterministic PRNG reproduces that. Only used when the caller has
    not supplied real bytes via --inputs.
    """
    import hashlib

    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{salt}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:n])


def load_systems(inputs_path: str | None) -> list[ProofSystem]:
    if not inputs_path:
        print(
            "warning: no --inputs, using all-high-entropy placeholder transactions.\n"
            "         The Groth16↔fflonk delta is right (528 B either way) but the\n"
            "         absolute DA costs are overstated, because a real tx's public\n"
            "         signals are mostly zero padding and do compress. Run\n"
            "         `npx hardhat test test/L2Cost.bench.ts` and pass --inputs.\n",
            file=sys.stderr,
        )
    if inputs_path:
        with open(inputs_path) as fh:
            data = json.load(fh)
        return [
            ProofSystem(
                name=key,
                execution_gas=data[key]["execution_gas"],
                signed_tx=bytes.fromhex(data[key]["signed_tx"]["hex"][2:]),
            )
            for key in ("groth16", "fflonk")
        ]
    return [
        ProofSystem(
            name=key,
            execution_gas=spec["execution_gas"],
            signed_tx=_synthetic_tx(spec["signed_tx_bytes"], salt=i),
        )
        for i, (key, spec) in enumerate(DEFAULT_INPUTS.items())
    ]


# Chain parameters sampled from mainnet on 2026-08-02:
#   OP Stack scalars   — GasPriceOracle predeploy 0x420...0F
#   L2 gas prices      — eth_gasPrice
#   Arbitrum ratio     — ArbGasInfo.getL1BaseFeeEstimate() 789,325 wei against
#                        an L1 blob base fee of 2,270,161 wei
# These are operator-set and drift; re-sample before quoting.
CHAINS = [
    Chain(
        name="Base",
        kind="op-stack",
        l2_gas_price_gwei=0.006,
        base_fee_scalar=2269,
        blob_base_fee_scalar=1_055_762,
    ),
    Chain(
        name="OP Mainnet",
        kind="op-stack",
        l2_gas_price_gwei=0.001,
        base_fee_scalar=5227,
        blob_base_fee_scalar=1_014_725,
    ),
    Chain(
        name="Arbitrum One",
        kind="arbitrum",
        l2_gas_price_gwei=0.02,
        l1_estimate_per_blob_wei=0.348,
    ),
]

ETH_USD = 1864.0  # Coinbase spot, 2026-08-02

# Historical sensitivity scenario: assume a fixed blob/L1 base-fee ratio.
# This is not a protocol identity and does not model independent blob demand.
# Resample independent fees and chain parameters before using estimates.
BLOB_FEE_L1_DIVISOR = 17


def blob_fee_for(l1_base_fee_gwei: float) -> int:
    return int(l1_base_fee_gwei * GWEI / BLOB_FEE_L1_DIVISOR)


def regime_at_l1(name: str, l1_base_fee_gwei: float) -> FeeRegime:
    """Build a regime from the one number that drives both fee terms."""
    return FeeRegime(
        name,
        l1_base_fee_gwei=l1_base_fee_gwei,
        blob_base_fee_wei=blob_fee_for(l1_base_fee_gwei),
        eth_usd=ETH_USD,
    )


REGIMES = [
    # Measured on-chain 2026-08-02: L1 base fee 42.5 Mwei, blob base fee
    # ~2.4 Mwei (Base) / ~2.3 Mwei (OP Mainnet). Note 42.5/17 = 2.5 Mwei,
    # so the coupling above reproduces the observation.
    FeeRegime("Observed 2026-08-02", 0.0425, 2_400_000, ETH_USD),
    # L1 demand recovering to 2025 levels.
    regime_at_l1("L1 at 2 gwei", 2.0),
    # A higher-fee scenario with the same assumed blob/L1 coupling.
    regime_at_l1("L1 at 20 gwei", 20.0),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inputs",
        help="JSON emitted by packages/contracts/test/L2Cost.bench.ts",
    )
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args()

    systems = load_systems(args.inputs)

    if args.format == "json":
        rows = [
            {
                **cost(ps, chain, regime).__dict__,
                "total_wei": cost(ps, chain, regime).total_wei,
                "total_usd": cost(ps, chain, regime).total_usd(regime.eth_usd),
            }
            for regime in REGIMES
            for chain in CHAINS
            for ps in systems
        ]
        print(json.dumps(rows, indent=2))
        return

    for ps in systems:
        print(f"{ps.name}: {ps.execution_gas:,} gas, {len(ps.signed_tx)} B signed tx, {ps.fastlz_size} B after FastLZ")
    print()
    print(markdown(systems, CHAINS, REGIMES))


if __name__ == "__main__":
    main()
