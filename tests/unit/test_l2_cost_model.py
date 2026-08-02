"""Tests for the L2 verification cost model (AIF-99).

The FastLZ port is the load-bearing part: its output is multiplied by 836_500
and charged to every proof, so it is pinned against op-geth's own behaviour
rather than against itself.
"""

import hashlib

import pytest

from scripts.l2_cost_model import (
    ARBITRUM_TX_OVERHEAD_BYTES,
    CHAINS,
    Chain,
    FeeRegime,
    ProofSystem,
    arbitrum_l1_fee,
    breakeven_blob_base_fee,
    breakeven_l1_base_fee_gwei,
    cost,
    flz_compress_len,
    op_stack_l1_fee,
)


def entropy(n: int, salt: str = "x") -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{salt}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


class TestFastLZ:
    @pytest.mark.parametrize("size", [256, 512, 1024, 4096])
    def test_incompressible_input_expands_by_one_thirty_second(self, size):
        """FastLZ level 1 spends one control byte per 32-byte literal run, so
        random input comes out at ~33/32. This is the mechanism by which
        fflonk's extra proof words cost real money.

        The bound is one-sided: a long enough random string will occasionally
        contain a 3-byte repeat the matcher can encode, shaving a byte or two.
        """
        ceiling = size + size // 32
        assert ceiling - 4 <= flz_compress_len(entropy(size)) <= ceiling

    def test_zeroes_collapse(self):
        assert flz_compress_len(bytes(512)) == 15

    def test_short_input_is_all_literals(self):
        # Below the 13-byte limit the match loop never runs.
        assert flz_compress_len(b"abcdefgh") == 9

    def test_empty(self):
        assert flz_compress_len(b"") == 0

    def test_sixteen_extra_proof_words_cost_exactly_528_bytes(self):
        """The Groth16 → fflonk delta is 16 field elements. They are uniform
        over ~254 bits, so the compressor returns 16 * 33 and nothing else."""
        base = entropy(886, "tx")
        extended = base[:100] + entropy(512, "proof") + base[100:]
        assert flz_compress_len(extended) - flz_compress_len(base) == 16 * 33


class TestOpStackFee:
    """Pinned against op-geth `NewL1CostFuncFjord`."""

    chain = Chain(
        name="test",
        kind="op-stack",
        l2_gas_price_gwei=0.01,
        base_fee_scalar=2269,
        blob_base_fee_scalar=1_055_762,
    )
    regime = FeeRegime("t", l1_base_fee_gwei=1.0, blob_base_fee_wei=10**7, eth_usd=3000)

    def _fee(self, tx: bytes) -> int:
        return op_stack_l1_fee(ProofSystem("p", 0, tx), self.chain, self.regime)

    def test_matches_hand_evaluated_formula(self):
        tx = entropy(886)
        fastlz = flz_compress_len(tx)
        expected_size = -42_585_600 + 836_500 * fastlz
        expected_fee_scaled = 2269 * 10**9 * 16 + 1_055_762 * 10**7
        assert self._fee(tx) == expected_size * expected_fee_scaled // 10**12

    def test_minimum_transaction_size_floor_applies(self):
        """intercept + coef*fastlzSize goes negative for tiny payloads; the
        100-byte floor is what stops the fee going negative."""
        tiny = bytes(4)
        assert -42_585_600 + 836_500 * flz_compress_len(tiny) < 100 * 1_000_000
        assert self._fee(tiny) > 0

    def test_fee_scales_with_incompressible_size(self):
        assert self._fee(entropy(1398)) > self._fee(entropy(886))

    def test_blob_floor_still_charges_the_calldata_term(self):
        floor = FeeRegime("floor", l1_base_fee_gwei=1.0, blob_base_fee_wei=1, eth_usd=3000)
        fee = op_stack_l1_fee(ProofSystem("p", 0, entropy(886)), self.chain, floor)
        assert fee > 0


class TestArbitrumFee:
    chain = Chain(name="arb", kind="arbitrum", l2_gas_price_gwei=0.02, l1_estimate_per_blob_wei=0.348)
    regime = FeeRegime("t", l1_base_fee_gwei=1.0, blob_base_fee_wei=10**7, eth_usd=3000)

    def test_matches_hand_evaluated_formula(self):
        tx = entropy(886)
        payload = flz_compress_len(tx) + ARBITRUM_TX_OVERHEAD_BYTES
        assert arbitrum_l1_fee(ProofSystem("p", 0, tx), self.chain, self.regime) == (int(0.348 * 10**7) * 16 * payload)

    def test_tracks_blob_base_fee(self):
        """Post-4844 the poster buys blobs, so its recoverable cost moves with
        the blob base fee and not with the L1 execution base fee."""
        tx = entropy(886)
        ps = ProofSystem("p", 0, tx)
        hot_l1 = FeeRegime("hot-l1", l1_base_fee_gwei=100.0, blob_base_fee_wei=10**7, eth_usd=3000)
        hot_blob = FeeRegime("hot-blob", l1_base_fee_gwei=1.0, blob_base_fee_wei=10**8, eth_usd=3000)
        assert arbitrum_l1_fee(ps, self.chain, hot_l1) == arbitrum_l1_fee(ps, self.chain, self.regime)
        assert arbitrum_l1_fee(ps, self.chain, hot_blob) > arbitrum_l1_fee(ps, self.chain, self.regime)


class TestCostBreakdown:
    regime = FeeRegime("t", l1_base_fee_gwei=1.0, blob_base_fee_wei=10**7, eth_usd=3000)

    def test_total_is_execution_plus_l1(self):
        ps = ProofSystem("groth16", 341_504, entropy(886))
        c = cost(ps, CHAINS[0], self.regime)
        assert c.total_wei == c.execution_wei + c.l1_wei
        assert 0.0 < c.l1_share < 1.0

    def test_da_penalty_grows_with_blob_fee(self):
        fflonk = ProofSystem("fflonk", 232_646, entropy(1398, "f"))
        cheap = cost(fflonk, CHAINS[0], self.regime)
        dear = cost(
            fflonk,
            CHAINS[0],
            FeeRegime("dear", 1.0, 10**10, 3000),
        )
        assert dear.l1_wei > cheap.l1_wei
        assert dear.execution_wei == cheap.execution_wei

    def test_op_mainnet_inverts_at_a_lower_l1_fee_than_base(self):
        """Cheap L2 gas is what exposes a chain: it shrinks the execution
        saving fflonk spends its DA budget out of. OP Mainnet's gas is ~6x
        cheaper than Base's, so it crosses over first."""
        groth16 = ProofSystem("groth16", 341_504, entropy(886, "g"))
        fflonk = ProofSystem("fflonk", 232_646, entropy(1398, "f"))
        base, op = CHAINS[0], CHAINS[1]
        assert op.l2_gas_price_gwei < base.l2_gas_price_gwei
        assert breakeven_l1_base_fee_gwei(groth16, fflonk, op) < breakeven_l1_base_fee_gwei(groth16, fflonk, base)

    def test_ranking_inverts_only_above_a_breakeven_blob_fee(self):
        """The AIF-99 question, made falsifiable: fflonk's 108,858-gas
        execution saving buys it a finite DA budget. Below the crossover it
        wins on L2; above it, ADR 0003's L1 ranking is the wrong one."""
        groth16 = ProofSystem("groth16", 341_504, entropy(886, "g"))
        fflonk = ProofSystem("fflonk", 232_646, entropy(1398, "f"))
        base = CHAINS[0]

        crossover = breakeven_blob_base_fee(groth16, fflonk, base, self.regime)
        assert crossover is not None

        below = FeeRegime("below", self.regime.l1_base_fee_gwei, crossover - 1, 3000)
        above = FeeRegime("above", self.regime.l1_base_fee_gwei, crossover, 3000)
        assert cost(fflonk, base, below).total_wei < cost(groth16, base, below).total_wei
        assert cost(fflonk, base, above).total_wei >= cost(groth16, base, above).total_wei
