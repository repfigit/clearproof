# ADR 0003: Proof System Selection (Groth16 vs Noir/UltraHonk)

## Status

Accepted (2026-07-28)

## Context

Clearproof's ZK compliance circuit proves FATF Travel Rule compliance without revealing PII. The circuit has been implemented in Circom targeting Groth16 proofs over BN254 (and optionally BLS12-381).

The per-circuit MPC trusted-setup ceremony required by Groth16 is the project's #1 production blocker. Every circuit change requires a new multi-party ceremony (6-12 months, $100k+), which severely limits iteration speed during the development phase.

Noir/UltraHonk offers an alternative: a universal setup (one-time ceremony shared by all circuits) that eliminates the per-circuit ceremony requirement. The tradeoff is higher on-chain verification gas costs.

This ADR evaluates whether to migrate from Groth16 to Noir/UltraHonk based on benchmark data collected in a spike (see `docs/internal/NOIR_BENCHMARK.md`).

## Decision

**Stay with Groth16 (BN254).** Do not migrate to Noir/UltraHonk at this time.

### Go/No-Go Criteria

The go threshold was: on-chain verification gas ≤ 2× Groth16 baseline.

| System | Verify Gas | Ratio to Groth16 BN254 |
|--------|-----------|----------------------|
| Groth16 BN254 | 341,504 | 1.0× (baseline) |
| Groth16 BLS12-381 | 363,588 | 1.06× |
| Noir/UltraHonk (estimated) | 1,500,000 - 3,000,000 | 4.4× - 8.8× |

UltraHonk exceeds the 2× threshold by 2-4×. **No-go.**

## Consequences

### Positive

- **Low on-chain gas cost** (341k gas, ~$3-4 per proof at 10 gwei)
- **Mature, audited tooling** (Circom + snarkjs, multiple production deployments)
- **Small proof size** (256 bytes)
- **Established ceremony infrastructure** (PSE, Hermez)

### Negative

- **Per-circuit ceremony required** for every circuit change (6-12 months, $100k+)
- **Slow iteration** during development phase
- **Ceremony coordination overhead** (trusted participants, public verification)

### Mitigations

1. **Stabilize the circuit before ceremony.** The compliance circuit is relatively mature. Finalize the signal interface, run the full audit, then proceed with ceremony.

2. **Use a ceremony-as-a-service provider.** PSE and Hermez offer turnkey ceremony coordination, reducing operational burden.

3. **Plan for a single ceremony.** Design the circuit to accommodate foreseeable compliance rule changes (new jurisdictions, threshold adjustments) without structural changes that would require re-compilation.

4. **Re-evaluate in 12-18 months.** Monitor UltraHonk development:
   - EIP-7849 precompile finalization
   - Gas cost optimization (target: <2× Groth16)
   - Noir ecosystem maturity (Poseidon library, production audits)
   - L2 deployment (gas costs are lower on L2s, may change the calculus)

## Alternatives Considered

### 1. PLONK (universal setup, moderate gas)

PLONK offers a universal setup with lower gas than UltraHonk (~500k-700k gas), but:
- Still 1.5-2× Groth16 gas
- Less mature proving infrastructure than UltraHonk
- No clear advantage over Groth16 for this use case

### 2. STARKs (no trusted setup, high gas)

STARKs eliminate the trusted setup entirely but have even higher gas costs than UltraHonk (~5-20M gas). Not viable for on-chain verification.

### 3. Hybrid: Groth16 on-chain, UltraHonk off-chain

Use Groth16 for on-chain verification (low gas) and UltraHonk for off-chain verification (faster proving, no ceremony). This preserves the option to migrate later but adds complexity. Not pursued because:
- The off-chain verification path already uses Groth16 (snarkjs)
- Dual proof systems increase maintenance burden
- No clear benefit until UltraHonk matures

## Implementation Plan

1. **Finalize circuit interface** (Q3 2026)
   - Lock public signal ordering
   - Complete audit fixes
   - Freeze test vectors

2. **Coordinate MPC ceremony** (Q4 2026 - Q1 2027)
   - Select ceremony provider (PSE or Hermez)
   - Recruit 50-100 trusted participants
   - Run ceremony (2-4 weeks)
   - Publish verification keys

3. **Deploy verifier contracts** (Q1 2027)
   - Deploy Groth16Verifier to Ethereum mainnet + L2s
   - Integrate with ComplianceRegistry
   - Run end-to-end tests

## References

- [Noir Benchmark Results](../internal/NOIR_BENCHMARK.md)
- [ADR 0002: BLS12-381 Migration](./0002-bls12381-migration.md)
- [UltraHonk Paper](https://aztec.network/blog/ultra-honk)
- [EIP-7849: UltraHonk Precompile](https://eips.ethereum.org/EIPS/eip-7849)
