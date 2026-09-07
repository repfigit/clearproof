> Historical exploratory model, August 2, 2026. This concerns the legacy
> 16-signal proof, uses modeled fee regimes and synthetic fflonk transactions,
> and is not a current network quote or an eight-signal pilot benchmark.
> The current proof-system decision remains Groth16; no production migration
> follows from this model. The original L1 exploration is preserved separately
> in [FFLONK_BENCHMARK.md](FFLONK_BENCHMARK.md).

# fflonk vs Groth16 — L2 Verification Cost

**Date:** 2026-08-02
**Issue:** AIF-99 (follow-up to the AIF-86 fflonk spike)
**Circuit:** Compliance (30,164 constraints), 16 public signals

## Review limits added September 7, 2026

The blob/L1 ratio of 1/17 is a scenario assumption, not an exact protocol
identity. The Arbitrum FastLZ proxy is not the actual batch Brotli calculation
and has no proven bound on either absolute cost or the relative proof-system
ranking. The fflonk execution-gas assumption materially affects every reported
crossover. Historical prose and figures below must be read with these limits;
use independently sampled parameters and real receipts before quoting costs.
The op-geth-derived model is separately attributed under LGPL-3.0-or-later.

## Why this exists

The fflonk spike measured on-chain verification at **232,646 gas against
Groth16's 341,467** — 32% cheaper — and that number carries a lot of weight in
the argument for pausing the MPC ceremony.

It is an L1 number. On a rollup a transaction is billed twice: L2 execution gas
*plus* an L1 data-availability charge that scales with the compressed size of
the transaction. fflonk's proof is 24 field elements against Groth16's 8, so it
posts 512 extra bytes on every verification. Five of the ten chains on the
roadmap are L2s. If the DA term is large enough, the 32% saving is an artefact
of measuring on the wrong chain.

## Answer

**Confirmed at today's fees; not robust to L1 fees recovering. The exposed
chain is OP Mainnet, and its crossover sits inside the fee range L1 occupied as
recently as late 2025.**

- At fees observed on 2026-08-02, fflonk is **0.68–0.69× Groth16's total cost
  on Base, OP Mainnet and Arbitrum One** — indistinguishable from the L1 ratio.
  The DA term is 0–2% of the total. The ranking does not invert.
- **OP Mainnet inverts at an L1 base fee of ~1.7 gwei.** That is 40× today's
  0.0425 gwei, but it is *below* the monthly averages of Aug–Nov 2025
  (1.38–2.11 gwei). The inversion is not a tail scenario; it is the fee
  environment of nine months ago.
- Base (~15 gwei) and Arbitrum One (~12.6 gwei) have real headroom, ~300×.
- The issue's premise that "calldata dominates on rollups" is true for a
  21k-gas transfer and **false for a 341k-gas pairing check**. Verification is
  execution-heavy, so 512 extra DA bytes amortise against a large execution
  cost. That is why the ranking survives at all.

**Bottom line for the ceremony decision:** L2 does not reverse ADR 0003's gas
table today, so the fflonk case does not collapse. But the L1 measurement
overstates fflonk's margin on cheap-gas L2s, and post-Fusaka that margin is now
coupled to L1 fees in a way it was not before (see below). If the ceremony
decision rests on gas alone, it should rest on the OP Mainnet number, not the
L1 one.

## The Fusaka change that makes this matter

Before Fusaka (2025-12-03), the blob base fee sat at the 1-wei floor almost
always — blob space was under-contended and its price was decoupled from L1
execution. Under those rules an L1 fee spike left rollup DA costs untouched and
this whole question would have been moot.

EIP-7918 changed that: the blob base fee now has a reserve floor derived from
the L1 execution base fee, and because blob space remains structurally
under-contended (mean ~5.7 blobs/block against a target of 14 after BPO2), that
floor *is* the price in practice. Observed ratio is ~1/17 of the L1 base fee.

So the two terms of the OP Stack fee function now move together, and a single
observable — the L1 execution base fee — decides the ranking. The model
parameterises regimes on that number rather than varying blob fees
independently.

## What was measured vs. assumed

Two of the four inputs are not reproduced here. Being explicit:

| Input | Source |
|---|---|
| Groth16 execution gas — 341,504 | **Measured.** `packages/contracts/test/L2Cost.bench.ts` against the committed vector, this repo, this run. Matches ADR 0003's 341,504. |
| Groth16 signed tx — 886 B (591 B after FastLZ) | **Measured.** Same bench, real ABI encoding of the real proof. |
| fflonk execution gas — 232,646 | **Taken from AIF-86.** Not reproduced. See below. |
| fflonk signed tx — 1,398 B (1,119 B after FastLZ) | **Synthesised** at fflonk's shape (24 proof words + the same 16 public signals) and entropy. Proof words are uniform over ~254 bits, so their compressed size is fixed by their count, not their value — the synthetic figure is exact for any real fflonk proof. |
| Chain scalars, L2 gas prices, blob base fees | **Measured.** Sampled from mainnet RPC on 2026-08-02. |

### Reproduction gap

AIF-86's harness is not in this repo. There is no `FFLONK_BENCHMARK.md` prior
to this file, no fflonk verifier contract, no fflonk zkey, and no pinned
snarkjs invocations to re-run — the spike's artefacts appear to live only in
PR #19. The 232,646 figure is carried forward on AIF-86's authority rather than
re-derived.

This does not weaken the conclusion. The L2 question turns entirely on the
512-byte DA delta, which is fixed by fflonk's proof shape and independent of
the execution-gas figure. An error in 232,646 in fflonk's favour would widen
its margin; an error against it would move the crossover down.

## Method

`scripts/l2_cost_model.py`. Both rollup fee functions come from the sequencer's
own implementation rather than from documentation summaries.

**OP Stack (Base, OP Mainnet), post-Fjord** — op-geth
`core/types/rollup_cost.go`, `NewL1CostFuncFjord`:

```
l1FeeScaled   = baseFeeScalar * l1BaseFee * 16  +  blobFeeScalar * blobBaseFee
estSizeScaled = max(100e6, -42_585_600 + 836_500 * fastlzSize)
l1Fee         = estSizeScaled * l1FeeScaled / 1e12
```

`fastlzSize` is `FlzCompressLen` over the **whole signed transaction**
(`Transaction.RollupCostData` compresses `MarshalBinary()`), so the bench emits
a serialised signed tx rather than bare calldata. `FlzCompressLen` is ported to
Python verbatim — uint32 wraparound in the hash, off-by-one in the mismatch
exit and all — and pinned by `tests/unit/test_l2_cost_model.py`.

**Arbitrum One** — Nitro charges the batch poster's recoverable L1 spend as
extra L2 gas:

```
posterCost = l1BaseFeeEstimate * 16 * (compressedBytes + 140)
```

`l1BaseFeeEstimate` is an adaptive controller output, not a read of Ethereum's
base fee; it is modelled as a fixed ratio of the L1 blob base fee (0.348,
calibrated from `ArbGasInfo.getL1BaseFeeEstimate()` = 789,325 wei against a
blob base fee of 2,270,161 wei on 2026-08-02) so that it tracks the regime
instead of freezing at the value it happened to read. Nitro compresses with
brotli; the model approximates with FastLZ, which is weaker and therefore
*overstates* Arbitrum's DA cost — conservative in the direction that favours
fflonk.

### Why 512 bytes costs exactly what it costs

FastLZ level 1 emits one control byte per run of up to 32 literals, so
incompressible input comes out at 33/32. The 16 extra proof words are uniform
field elements; nothing compresses them. The delta is therefore
**16 × 33 = 528 bytes of `fastlzSize`, exactly** — verified in
`test_sixteen_extra_proof_words_cost_exactly_528_bytes`.

The public signals are identical between the two systems and mostly small
integers, so they compress well and cancel out of the comparison entirely. The
whole L2 penalty is `528 × 836_500 × l1FeeScaled / 1e12` wei.

### Parameters (sampled 2026-08-02)

| Parameter | Base | OP Mainnet | Arbitrum One |
|---|---|---|---|
| `eth_gasPrice` | 0.006 gwei | 0.001 gwei | 0.02 gwei |
| `baseFeeScalar` | 2,269 | 5,227 | — |
| `blobBaseFeeScalar` | 1,055,762 | 1,014,725 | — |
| `l1BaseFee` (GPO) | 37.5 Mwei | 40.4 Mwei | — |
| `blobBaseFee` (GPO) | 2.43 Mwei | 2.27 Mwei | — |
| `getL1BaseFeeEstimate()` | — | — | 789,325 wei |

L1 `baseFeePerGas` 42.5 Mwei (block 25,666,592). ETH $1,864 (Coinbase spot).
Base and Arbitrum sit at or near their protocol gas floors (5 Mwei and 20 Mwei
respectively).

Scalars are operator-set and fee inputs move constantly. **Re-sample before
quoting these figures.**

## Results

Regenerate with:

```bash
cd packages/contracts && npx hardhat test test/L2Cost.bench.ts
uv run python scripts/l2_cost_model.py --inputs /tmp/l2-cost-inputs.json
```

```
groth16: 341,504 gas,  886 B signed tx,  591 B after FastLZ
fflonk:  232,646 gas, 1398 B signed tx, 1119 B after FastLZ
```

#### Observed 2026-08-02 (L1 base fee 0.0425 gwei, blob base fee 2,400,000 wei, ETH $1,864)

| Chain | System | Exec gas | Exec (USD) | L1 DA (USD) | Total (USD) | L1 share | vs Groth16 |
|---|---|---|---|---|---|---|---|
| Base | groth16 | 341,504 | $0.00382 | $0.00000 | $0.00382 | 0% | baseline |
| Base | fflonk | 232,646 | $0.00260 | $0.00001 | $0.00261 | 0% | 0.68× |
| OP Mainnet | groth16 | 341,504 | $0.00064 | $0.00001 | $0.00064 | 1% | baseline |
| OP Mainnet | fflonk | 232,646 | $0.00043 | $0.00001 | $0.00044 | 2% | 0.69× |
| Arbitrum One | groth16 | 341,504 | $0.01273 | $0.00002 | $0.01275 | 0% | baseline |
| Arbitrum One | fflonk | 232,646 | $0.00867 | $0.00003 | $0.00870 | 0% | 0.68× |

#### L1 at 2 gwei (blob base fee 117,647,058 wei, ETH $1,864)

| Chain | System | Exec gas | Exec (USD) | L1 DA (USD) | Total (USD) | L1 share | vs Groth16 |
|---|---|---|---|---|---|---|---|
| Base | groth16 | 341,504 | $0.00382 | $0.00017 | $0.00399 | 4% | baseline |
| Base | fflonk | 232,646 | $0.00260 | $0.00033 | $0.00293 | 11% | 0.74× |
| OP Mainnet | groth16 | 341,504 | $0.00064 | $0.00024 | $0.00088 | 27% | baseline |
| OP Mainnet | fflonk | 232,646 | $0.00043 | $0.00048 | $0.00091 | 52% | **1.04×** |
| Arbitrum One | groth16 | 341,504 | $0.01273 | $0.00089 | $0.01362 | 7% | baseline |
| Arbitrum One | fflonk | 232,646 | $0.00867 | $0.00154 | $0.01021 | 15% | 0.75× |

#### L1 at 20 gwei (blob base fee 1,176,470,588 wei, ETH $1,864)

| Chain | System | Exec gas | Exec (USD) | L1 DA (USD) | Total (USD) | L1 share | vs Groth16 |
|---|---|---|---|---|---|---|---|
| Base | groth16 | 341,504 | $0.00382 | $0.00166 | $0.00548 | 30% | baseline |
| Base | fflonk | 232,646 | $0.00260 | $0.00328 | $0.00588 | 56% | **1.07×** |
| OP Mainnet | groth16 | 341,504 | $0.00064 | $0.00241 | $0.00305 | 79% | baseline |
| OP Mainnet | fflonk | 232,646 | $0.00043 | $0.00477 | $0.00521 | 92% | **1.71×** |
| Arbitrum One | groth16 | 341,504 | $0.01273 | $0.00893 | $0.02166 | 41% | baseline |
| Arbitrum One | fflonk | 232,646 | $0.00867 | $0.01537 | $0.02405 | 64% | **1.11×** |

#### Inversion thresholds

| Chain | Breakeven blob base fee | Breakeven L1 base fee | Headroom vs observed |
|---|---|---|---|
| Base | 1,399,240,438 wei | 15.0 gwei | 354× |
| OP Mainnet | 239,388,610 wei | **1.7 gwei** | **40×** |
| Arbitrum One | 740,554,796 wei | 12.6 gwei | 296× |

Cheap L2 gas is what exposes a chain, not expensive DA. OP Mainnet's execution
gas is ~6× cheaper than Base's, so fflonk's 108,858-gas saving is worth ~6×
less there — a much smaller budget to spend on 528 extra DA bytes.

## Consequences

1. **ADR 0003's gas table holds for L2 at current fees, conditionally.** Added
   as an explicit L2 note in `docs/adr/0003-proof-system.md` rather than left
   to inference.

2. **Quote the OP Mainnet figure, not the L1 figure.** 40× headroom against a
   threshold L1 sat above for most of 2025 is a live risk, not a rounding
   error. If ClearProof is L2-first and OP-Stack-heavy, the honest statement of
   fflonk's advantage is "32% on L1, 31% on OP Mainnet today, negative if L1
   fees return to 2025 levels".

3. **Proof size is a recurring cost, not a one-off.** Any future proof system
   with a larger proof pays this on every verification on every L2. ADR 0003's
   no-go on UltraHonk (2–3 KB proofs, 4–6× fflonk's) is strengthened: its DA
   penalty compounds an execution-gas penalty that was already 5–10×.

4. **The ADR numbering in AIF-99 does not match this repo.** The issue refers
   to "ADR 0004's gas table" and its recommendation to pause the MPC ceremony;
   ADR 0004 here is the versioned verifier registry, and no fflonk ADR exists.
   The gas table this work bears on is ADR 0003's. Whoever reconciles this
   should check whether the fflonk ADR is still unmerged alongside PR #19.

## Limitations

- fflonk's execution gas is not reproduced (see "Reproduction gap").
- No transaction was submitted to Base, OP Mainnet or Arbitrum One. Costs are
  computed from the sequencers' own fee functions applied to a real signed
  transaction, not read from a receipt. Worth a live submission before these
  figures are quoted externally.
- The Arbitrum model treats `l1BaseFeeEstimate` as proportional to the blob
  base fee from a single calibration point. Nitro's estimator is an adaptive
  controller with hysteresis, so behaviour far from that point is approximate.
- Fee inputs are a single-block snapshot; the regime ranges are illustrative
  brackets, not a measured distribution.
- The ~1/17 blob-to-L1 coupling is an observed ratio (EIP-7918 implies 1/16;
  lagged `L1Block` reads likely explain the gap), not a guaranteed invariant.
