# fflonk vs Groth16 benchmark (AIF-86)

**Date:** 2026-07-31
**Circuit:** `circuits/compliance.circom`, compiled from `main` @ `a54f3a0`
**Constraints:** 30,164 (15,333 non-linear + 14,831 linear), 30,192 wires, 16 public signals
**Toolchain:** circom 2.2.2 (CI-pinned binary, SHA256 `f3d8d1fd…fe9d5`), snarkjs 0.7.6
**Machine:** shared Linux x86-64 container. Absolute timings are indicative; **ratios are the finding.**

## Why this benchmark exists

ADR 0003 evaluated Noir/UltraHonk as the escape from Groth16's per-circuit MPC ceremony and rejected it on gas (4.4–8.8× Groth16). It did not evaluate **fflonk**, which is the missing middle: a universal-setup scheme that runs on the *existing* Circom source, the *existing* R1CS, the *existing* BN254 curve and the *existing* snarkjs toolchain. No circuit rewrite, no new language, no new proving stack.

The question this answers: **can we delete the ceremony without paying for it in gas?**

## Headline result

**Yes on gas — fflonk verification is 32% cheaper than Groth16. The cost lands on proving instead: 20× slower, 4.8× more memory.**

## Measurements

All figures are from one session, same circuit, same witness, same Hardhat harness (`estimateGas`, matching the method used by the ADR 0002 BLS benchmark).

| Metric | Groth16 | fflonk | Ratio |
|---|---:|---:|---:|
| **On-chain `verifyProof` gas** | **341,467** | **232,646** | **0.68×** |
| Verifier deploy gas | 1,158,691 | 4,156,740 | 3.59× |
| Verifier bytecode | 5,115 B | 19,015 B | 3.72× |
| Proving time (run 1) | 1.86 s | 30.19 s | |
| Proving time (run 2) | 1.74 s | 39.40 s | |
| Proving time (run 3) | 1.88 s | 42.74 s | |
| **Proving time (mean)** | **1.83 s** | **37.44 s** | **20.5×** |
| Peak RSS while proving | 1.21 GB | 5.79 GB | 4.79× |
| Setup wall time | 10.34 s + 2.56 s contribute | 6.68 s | — |
| Peak RSS during setup | — | 3.46 GB | — |
| zkey size | 13.2 MB | 307 MB | 23.2× |
| Proof calldata | 8 × 32 B = 256 B | 24 × 32 B = 768 B | 3× |
| ptau power required | 2^15 | **2^19** | 16× (in domain size) |
| ptau file size | 289 MB (2^18 used) | 577 MB (2^19) | — |
| **Phase-2 ceremony** | **Required, per circuit** | **None** | — |
| Verifier licence | Apache-2.0 (our own `generate_verifier.mjs`) | **GPL-3.0** (snarkjs template) | — |

Both proofs verified: `snarkjs fflonk verify` → `PROOF VERIFIED SUCCESSFULLY`; `snarkjs groth16 verify` → `OK!`. Both verified on-chain (`verifyProof` returned `true`), and both rejected a tampered proof.

### Harness validation

The Groth16 figure measured here, **341,467**, reproduces ADR 0003's published baseline of **341,504** to within 37 gas. The two were produced by different vectors on different days, so the harness is measuring what the ADR measured. The fflonk number is comparable on the same basis.

## The five findings that matter

### 1. Universal setup does not cost gas here — it saves it

The intuition behind ADR 0003 ("universal setup is cheaper to operate, more expensive to verify") is correct for UltraHonk and **wrong for fflonk on this circuit**.

Groth16's verifier cost scales with the number of public inputs: one `ecMul` + one `ecAdd` per signal to accumulate the linear combination, plus a fixed 4-pairing check. With 16 public signals that is ~16 `ecMul` (6,000 gas each) + 16 `ecAdd` — roughly 110k gas of the 341k total spent purely on public-input accumulation.

fflonk's verifier is dominated by a fixed set of pairings and field operations that does not grow the same way. **Our 16-signal interface is precisely what makes fflonk win.** A circuit with 2 public signals would likely show the opposite ordering — so this result is specific to clearproof's signal design and should not be generalised.

### 2. Proving time is the real cost, and it is severe

37 seconds versus 1.8. The measured variance on fflonk (30.2–42.7 s) reflects a contended shared machine; the ratio is stable enough to act on.

This matters more than it first appears because of an asymmetry in the tooling: **Groth16 has a production-grade native prover (rapidsnark, typically 10–50× faster than snarkjs), and fflonk does not.** So the realistic production gap is wider than 20×, not narrower. A VASP proving on server-class hardware could plausibly get Groth16 under 200 ms while fflonk stays in the tens of seconds.

Whether that matters is a product question, not a cryptographic one. Travel Rule proof generation is not an interactive, sub-second path — it happens once per transfer, ahead of settlement. 37 s per transfer is survivable for a pilot; it is a poor fit for a VASP doing thousands of transfers an hour, and it is a bad fit for the `/proof/generate` request/response API shape (it would need to become a job queue).

### 3. fflonk needs a 2^19 ptau, and pot18 silently is not enough

Groth16 on this circuit needs 2^15. fflonk needs **2^19** — `snarkjs fflonk setup` against the CI-pinned `powersOfTau28_hez_final_18.ptau` fails with:

```
Error: Powers of Tau is not big enough for this circuit size. Section 2 too small.
```

fflonk requires ~9 × domainSize G1 points; 9 × 2^15 = 294,912 > 2^18 = 262,144. Adopting fflonk means re-pinning CI to `powersOfTau28_hez_final_19.ptau` (577 MB, up from 289 MB), with the checksum updated.

The pot19 file used here was verified against iden3's published ceremony transcript hash:

```
blake2b: bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff66486
         00eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887   ✓ matches
sha256:  3f428d1a407e4704ef906960e000b03089e5e6ec29bf65b07bb5e3de005f4700
```

Note that CI currently pins by SHA-256 while iden3 publishes blake2b. Both are recorded above.

### 4. The snarkjs fflonk verifier is GPL-3.0, and re-implementing it is not a weekend job

ADR 0001 replaced the GPL-3.0 snarkjs Groth16 template with our own Apache-2.0 implementation (`scripts/generate_verifier.mjs`), specifically so the patent grant and licence story work for enterprise adoption. `snarkjs zkey export solidityverifier` on an fflonk zkey emits a Solidity file whose SPDX header declares **GPL-3.0**.

> Note for future editors: do not write that header's literal tag in this repo's Markdown. `reuse lint` scans every file for the bare identifier token and will read it as a real licence declaration for the containing file, then fail on the surrounding Markdown punctuation. An earlier draft of this line broke the `license-compliance` CI job exactly that way.

Scale of the problem: our Apache Groth16 verifier is ~300 lines against a shared `Pairing.sol`. The fflonk template is **1,566 lines** of hand-optimised Yul-heavy Solidity. Re-implementing it cleanly is a substantial, security-critical project — not comparable to the Groth16 rewrite.

**This is the single largest hidden cost of adopting fflonk, and it is a licensing/engineering cost rather than a cryptographic one.**

### 5. Contract size is fine; deploy cost is not free

19,015 bytes is comfortably under the EIP-170 limit of 24,576, so fflonk deploys as a single contract with room to spare. Deploy costs 4.16 M gas versus 1.16 M — a one-time cost per chain, irrelevant next to per-proof economics, but worth knowing for the 10-chain deployment matrix.

## What this does not measure

- **BLS12-381.** ADR 0002 recommends BLS12-381 at the production ceremony. fflonk was measured on BN254 only. If both migrations were pursued they interact, and that combination is unmeasured.
- **L2 gas.** All figures are L1-equivalent on a Prague-target local node. On L2s calldata dominates, and fflonk's 3× larger proof (768 B vs 256 B) would erode or reverse its advantage. **This flips the conclusion for an L2-first deployment and needs measuring before any L2 commitment.**
- **Recursive/aggregated verification**, which would change the calculus for both.
- **A native fflonk prover.** None is known to exist; the 20× figure is snarkjs-to-snarkjs and therefore *flattering* to fflonk relative to a rapidsnark-backed Groth16 deployment.

## Reproduction

The GPL-3.0 fflonk verifier is deliberately **not committed** (`packages/contracts/contracts/bench/` holds only the Apache/BLS bench contract; the fflonk template is generated locally and discarded). To reproduce:

```bash
# 1. Pinned circom (same binary and checksum as .github/workflows/ci.yml)
curl -L https://github.com/iden3/circom/releases/download/v2.2.2/circom-linux-amd64 -o build/bin/circom
chmod +x build/bin/circom
sha256sum build/bin/circom   # f3d8d1fdbc123779b80e210c909ee941d7a1e130c70365524646b48b8b0fe9d5

# 2. Compile the circuit from source (artifacts/ is gitignored and may be stale)
build/bin/circom circuits/compliance.circom --r1cs --wasm --output build/ -l node_modules

# 3. ptau — 2^19 for fflonk, NOT the 2^18 pinned in CI
curl -sSL -o build/pot19_final.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_19.ptau
b2sum build/pot19_final.ptau   # must match the blake2b above

# 4. Witness. tests/vectors/compliance/input.json is camelCase (SDK-facing);
#    the circuit takes snake_case. Map it per packages/proof/src/prover.ts.
node build/compliance_js/generate_witness.js \
     build/compliance_js/compliance.wasm build/input_snake.json build/witness.wtns

# 5. fflonk — no phase 2
npx snarkjs fflonk setup build/compliance.r1cs build/pot19_final.ptau build/fflonk.zkey
npx snarkjs fflonk prove build/fflonk.zkey build/witness.wtns build/fflonk_proof.json build/fflonk_public.json

# 6. Groth16 baseline — note the phase-2 contribute step, which is the thing under debate
npx snarkjs groth16 setup build/compliance.r1cs build/pot19_final.ptau build/g16_0000.zkey
npx snarkjs zkey contribute build/g16_0000.zkey build/g16_final.zkey -e="bench"
npx snarkjs groth16 prove build/g16_final.zkey build/witness.wtns build/g16_proof.json build/g16_public.json

# 7. Gas: export both verifiers, deploy to a local node, estimateGas on verifyProof.
#    Groth16 via our Apache generator; fflonk via snarkjs (GPL — do not commit).
node scripts/generate_verifier.mjs build/g16_vkey.json <dest>/Groth16VerifierBench.sol
npx snarkjs zkey export solidityverifier build/fflonk.zkey <dest>/FflonkVerifier.sol
```

The witness input used here is the committed vector with **policy-valid US thresholds** substituted (`tier2/3/4 = 250/3000/10000`, `actualAmount = 1000` → `amount_tier = 2`, `sar_review_flag = 0`), per `config/jurisdiction_thresholds.json`. The committed vector's own thresholds (25000/300000/1000000) match no jurisdiction — see AIF-89.

## Recommendation

See [ADR 0004](../adr/0004-fflonk-universal-setup.md).
