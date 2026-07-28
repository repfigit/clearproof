# ADR 0002: Groth16 Curve Migration — BN254 vs BLS12-381

- **Status:** DRAFT — gas benchmark and chain matrix COMPLETE (see below); remaining: Sepolia confirmation deploy (operator-gated)
- **Date:** 2026-07-24
- **Deciders:** clearproof maintainers
- **Related:** ADR 0001 (verifier licensing), `docs/internal/CEREMONY_RUNBOOK.md`, `docs/internal/SOTA_PLAN_2026.md` item #2

## Context

clearproof's Groth16 circuits run on BN254 (alt_bn128), which offers
approximately **100 bits of security** — adequate today but below the 128-bit
level regulated counterparties and their counsel typically expect for
long-lived financial infrastructure. Until 2025, BN254 was the *only* curve
with EVM pairing precompiles, so the choice was forced.

**That changed with Pectra.** EIP-2537 (BLS12-381 curve operations) activated
on Ethereum mainnet on 2025-05-07 (epoch 364032) and on Sepolia earlier in
2025. BLS12-381 offers ~128 bits of security. Groth16 verification on
BLS12-381 is now possible on L1 with precompile-backed gas costs.

The production MPC trusted-setup ceremony (see `CEREMONY_RUNBOOK.md`) has not
yet run. **The ceremony is curve-specific: whatever curve we choose at
ceremony time is the curve we live with until the next ceremony.** This makes
"before the ceremony" the only cheap decision point — the same logic ADR 0001
used for the verifier regeneration.

## Facts

- EIP-2537 precompiles (final gas schedule): `G1ADD` 375, `G1MSM`
  12000·k·discount, `G2ADD` 600, `G2MSM` 22500·k·discount, `PAIRING`
  32600·k + 37700 (k = pair count).
- A Groth16 verification with 16 public signals needs one G1 MSM of size 17
  (vk_x computation) and a 4-pairing product check.
  - MSM(17) ≈ 12000 × 17 × 0.496 ≈ **101k gas**
  - Pairing(4) = 32600 × 4 + 37700 ≈ **168k gas**
  - Estimated total ≈ **300–330k gas** including calldata/overhead —
    versus ~285–350k measured for the current BN254 verifier with 16 public
    inputs (Base engineering benchmarks put BN254 Groth16 at ~348k for a
    comparable public-input count; the thirdweb 2026 guide cites ~230k for
    small input counts).
  - **Indicative conclusion: the security upgrade is roughly gas-neutral
    (±15%) on L1.** Must be confirmed empirically (Open Task 1).
- A consensus bug in the EIP-2537 pairing precompile (infinity-point
  handling, Geth/Nethermind divergence) was found during the Pectra audit
  competition and fixed before mainnet. Verifier implementations should still
  reject infinity points at the boundary as defense-in-depth.
- snarkjs supports `bls12381` for `powersoftau`, `groth16 setup`, `zkey`
  operations, and witness generation — the proving pipeline is unchanged
  apart from the curve flag. Circom is curve-agnostic; the circuit compiles
  for any scalar field, and Circomspect (now in CI) accepts
  `--curve BLS12_381`.
- **L2 availability is uneven.** EIP-2537 shipped with Pectra on Ethereum L1
  and Sepolia; rollup adoption (Arbitrum, Base, OP Stack chains, Polygon
  PoS/zkEVM) must be verified per target chain before committing to
  BLS12-381 for those deployments (Open Task 2).
- The Python prover path (`src/registry/poseidon.py`, sanctions tree builder)
  hashes over the BN254 scalar field. **Migrating curves requires re-deriving
  all Poseidon parameters** (round constants depend on the field): the
  clean-room generator (`scripts/generate_poseidon_constants.py`) is
  parameterized by prime and can regenerate for BLS12-381's scalar field —
  but circuit, Python, and TS sides must all switch together, and every
  committed test vector and Sepolia deployment becomes stale.

## Benchmark Results (Open Task 1 — DONE 2026-07-23)

Measured on Hardhat's Prague EVM with real proofs over `compliance.circom`
(30,164 constraints, 16 public signals), same measurement method both sides
(`estimateGas` on `verifyProof`):

| Verifier | Gas | Notes |
|----------|-----|-------|
| BN128 (production `Groth16Verifier.sol`) | **341,504** | committed parity vector |
| BLS12-381 (`contracts/bench/Groth16VerifierBLS.sol`) | **363,588** | EIP-2537 precompiles |
| **Delta** | **+6.5%** | within the ±15% estimate band |

Artifacts: `tests/vectors/compliance-bls/` (dev-only single-party setup),
benchmark test `packages/contracts/test/Groth16VerifierBLS.bench.ts` (valid
proof verifies, tampered proof rejected), generator
`scripts/generate_verifier_bls.mjs`. The EIP-2537 verifier path lands in
clearproof-owned Apache-2.0 code, as anticipated.

**New finding — Poseidon constants are curve-bound.** circomlib's
`poseidon.circom` implements the optimized (Neptune) algorithm whose derived
S/P constants satisfy their algebraic identities only mod BN254. Compiled
for bls12381, the circuit computes a **non-standard hash variant** (opt
algorithm, BN254-derived constants mod BLS_r) — verified bit-exactly against
the compiled wasm (`scripts/make_bls_input.py`). The security analysis of
standard Poseidon does not cleanly transfer to this variant. A production
BLS12-381 migration SHOULD regenerate Poseidon parameters for the BLS scalar
field (the clean-room generator is prime-parameterized) and patch the circuit
to match, rather than accepting the accidental variant. This adds modest
circuit work to Option B and strengthens the case for deciding before the
ceremony.

## Chain Matrix (Open Task 2 — DONE 2026-07-24)

`scripts/check_eip2537.mjs` probes the PAIRING precompile (`0x0f`) on every
target chain in `packages/contracts/scripts/networks.ts`. **All ten networks
have EIP-2537 live**, mainnet and testnet alike:

| Chain | EIP-2537 | Chain | EIP-2537 |
|-------|----------|-------|----------|
| ethereum | ✓ | optimism | ✓ |
| sepolia | ✓ | optimism-sepolia | ✓ |
| base | ✓ | polygon | ✓ |
| base-sepolia | ✓ | polygon-amoy | ✓ |
| arbitrum | ✓ | arbitrum-sepolia | ✓ |

Consequence: the "L2 availability is uneven" caveat is **resolved**. Option B
is viable on every deployment target, and the dual-curve operational concern
(BN254 for L2s, BLS12-381 for L1) largely evaporates — a single curve can be
used everywhere. The script exits non-zero if any chain regresses, so it can
gate releases.

## Options

### A. Stay on BN254 (status quo)

- ✅ Zero engineering cost; Sepolia pilot deployments remain valid
- ✅ Cheapest verification on every EVM chain today (BN254 precompiles are
  universally deployed; BLS12-381 is L1-only for now)
- ❌ ~100-bit security — will be flagged in diligence by regulated VASPs;
  margin erodes over the 10+ year archival horizon of compliance records
- ❌ Re-deciding later means a second ceremony (the exact cost this ADR
  exists to avoid)

### B. Migrate L1 deployment to BLS12-381 at the production ceremony

- ✅ ~128-bit security for the canonical deployment
- ✅ Roughly gas-neutral on L1 per the estimate above
- ✅ Ceremony happens once, on the stronger curve — no re-do
- ✅ snarkjs/circom tooling unchanged in practice
- ❌ New verifier contract needed: snarkjs does not ship a BLS12-381
  Solidity template; we would extend `scripts/generate_verifier.mjs`
  (ADR 0001, Apache-2.0) to emit EIP-2537-based verification — real but
  bounded work, and it lands in code we already own
- ❌ L2 deployments blocked until each target chain ships the precompiles;
  likely means BN254 on L2s + BLS12-381 on L1 (dual-curve operation)
- ❌ All Poseidon parameters, test vectors, and domain-separated leaf hashes
  must be regenerated; Sepolia pilot deployments retired

### C. Dual-curve from day one

Run BN254 (L2s, current pilot) and BLS12-381 (L1) with two ceremonies and
two verifier deployments, unified behind the domain-binding signals
(`domain_chain_id` already separates them cryptographically).

- ✅ Every chain gets the strongest curve available on it
- ❌ Two ceremonies, two artifact sets, two oracle/relay configurations —
  roughly doubles ceremony and release-engineering cost
- ❌ Confusing assurance story for auditors and counsel

## Recommendation

**Option B, on ALL target chains** — the chain matrix shows EIP-2537 is live
everywhere we deploy, so there is no need for the dual-curve compromise.
Hold only **one** ceremony (BLS12-381) as canonical; BN254 artifacts remain
explicitly dev/pilot-grade, never production.

Rationale: measured gas penalty is +6.5%, the security margin doubles
(~100 → ~128 bits), the ceremony is the point of no return, the verifier
template is in code we already own post-ADR-0001, and the Poseidon
re-parameterization is mechanical thanks to the clean-room generator.

**Conditions status:** gas benchmark ✓ (+6.5%), chain matrix ✓ (all chains).
One confirmation remains — a live Sepolia deploy of `Groth16VerifierBLS.sol`
(operator-gated: needs `DEPLOYER_PRIVATE_KEY`). The Poseidon finding adds
circuit work but no fundamental obstacle.

## Open Tasks (blocking "DECIDED" status)

1. ~~**Empirical gas benchmark.**~~ **DONE 2026-07-23** — +6.5% vs BN128.
2. ~~**Chain matrix.**~~ **DONE 2026-07-24** — all 10 networks PRESENT.
   Remaining: live Sepolia confirmation deploy (operator with deployer key).
3. **Poseidon parameter regeneration.** Run
   `scripts/generate_poseidon_constants.py` against the BLS12-381 scalar
   field, patch the circuit's Poseidon instantiation to curve-correct
   parameters (do NOT ship the accidental BN254-constants-mod-BLS variant),
   and regenerate all committed test vectors.
4. **Infinity-point rejection** checks in the new verifier template.
5. Update `CEREMONY_RUNBOOK.md` with the chosen curve before any ceremony
   announcement.

## Consequences

- Decision must land before the production ceremony is scheduled; after the
  ceremony this ADR is immutable history.
- If B: `tests/vectors/`, Sepolia deployments, `sanctions_tree.json`
  artifacts, and the oracle roots are all invalidated and must be rebuilt —
  the same "surgical redeploy" playbook used for ADR 0001 applies.
- The domain-binding design (`domain_chain_id`, `domain_contract_hash`)
  already isolates deployments per chain, so a mixed BN254-L2 / BLS12-381-L1
  interim creates no cross-chain replay surface.
