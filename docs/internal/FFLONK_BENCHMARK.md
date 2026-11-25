# fflonk vs Groth16 benchmark (AIF-86; `pilot-transfer-v3` update 2026-11-25)

**Updated:** 2026-11-25 (`pilot-transfer-v3`, branch `fix/fflonk-benchmark` @ `5fd315a`)
**Original baseline:** 2026-07-31 (legacy `circuits/compliance.circom` @ `a54f3a0`, preserved below)

## `pilot-transfer-v3` benchmark (2026-11-25)

**Circuit:** `circuits/pilot_compliance.circom` (`pilot-transfer-v3`: issuance depth 32, authorized issuers depth 20, sanctions depth 20)
**Constraints:** 95,408 R1CS (49,562 non-linear + 45,846 linear), 95,450 wires, 8 public signals, 334 private inputs (R1CS SHA-256 `4248cc7b67e7ead5a4ac7a4425acd0debffaee9642d540846be58daeae551aa8`)
**fflonk PLONKish expansion:** 128,976 PLONK constraints, 33,560 additions, 129,010 vars, circuit power 17 (domain size 2^17 = 131,072)
**Toolchain:** circom 2.2.2 (CI-pinned binary, SHA-256 `f3d8d1fdbc123779b80e210c909ee941d7a1e130c70365524646b48b8b0fe9d5`), snarkjs 0.7.6, Node.js v26.5.1, Hardhat local EVM (Prague hardfork, Solidity 0.8.24 optimizer runs=200)
**Machine:** Linux x86-64, AMD Ryzen AI 9 HX 470 (12 physical cores / 24 logical CPUs, 57 GiB RAM). Proving was measured in both 4-physical-core pinned mode (`taskset -c 0,1,2,3`, matching `docs/benchmarks/native_prover.py`) and unpinned mode (all 24 logical CPUs).

### Headline result (`pilot-transfer-v3`)

- **Verifier gas:** fflonk (`225,642` gas) is **37.8% cheaper** than the shipped `PilotGroth16Verifier` (`362,824` gas, storage-backed VK, ratio `0.62×`) and **20.0% cheaper** than a hardcoded-VK Apache Groth16 verifier (`282,218` gas, ratio `0.80×`). Note the narrower margin on hardcoded-VK Groth16 than in the legacy 16-signal benchmark (`0.68×`): halving public signals from 16 to 8 cuts Groth16's public-input `ecMul`/`ecAdd` overhead roughly in half.
- **Proving cost:** On 4 pinned physical cores, snarkjs fflonk proving takes **47.23 s mean / 47.35 s median** and **9.48 GiB peak RSS** vs **2.80 s** and **2.59 GiB** for snarkjs Groth16 (**16.9× slower, 3.66× memory**). Unpinned across all 24 logical CPUs, fflonk takes **38.41 s mean** (**10.39 GiB peak RSS**) vs **1.58 s** (**2.56 GiB**) for snarkjs Groth16 (**24.4× slower, 4.06× memory**). Relative to the separately measured rapidsnark native Groth16 prover on the same circuit (`1.05 s`, `86 MiB` on 4 cores; see [`2026-10-05-native-prover.md`](../benchmarks/2026-10-05-native-prover.md)), fflonk proving is **~45× slower and ~110× higher RSS**.
- **Phase-1 ptau jump:** `pilot-transfer-v3` expands to domain size 2^17 (`131,072`), requiring `9 × 2^17 + 18 = 1,179,666` G1 points — **2^21 ptau** (`ppot_0080_21.ptau`, **2.25 GiB / 2,416,012,434 B**), up from CI's 2^17 (`ppot_0080_17.ptau`) for Groth16. Both `pot18` and `pot20` fail `snarkjs fflonk setup`.
- **L2 calldata / DA impact:** With 8 public signals, `verifyProof` calldata is **1,028 B** (signed EIP-1559 tx **1,142 B**, **1,080 B** FastLZ) for fflonk vs **516 B** (signed tx **630 B**, **552 B** FastLZ) for Groth16 — the same incompressible **+512 B raw / +528 B FastLZ** penalty. At low L1 fees (2026-08-02 snapshot), fflonk remains cheaper (`0.62–0.63×` vs `PilotGroth16Verifier`, `0.80–0.81×` vs hardcoded Groth16). On OP Mainnet, the modeled inversion threshold is **~2.2 gwei** L1 base fee vs `PilotGroth16Verifier` and drops to **~0.9 gwei** vs hardcoded-VK Groth16.

### Measurements (`pilot-transfer-v3`)

All figures below come from one session on the identical compiled R1CS (`pilot_compliance.r1cs`) and identical synthetic witness (`synthetic.wtns`, 3,054,476 B, 8 public signals from `tests/unit/test_pilot_compliance.py:synthetic_case`). Both Groth16 verifier variants are shown so the storage-backed VK cost of `PilotGroth16Verifier` is not conflated with the proof-system difference.

| Metric | Groth16 (`PilotGroth16Verifier`, storage VK) | Groth16 (hardcoded VK, `generate_verifier.mjs`) | fflonk (snarkjs template, hardcoded VK) | fflonk vs Pilot G16 / Hardcoded G16 |
|---|---:|---:|---:|---:|
| **On-chain `verifyProof` gas (`estimateGas`)** | **362,824** | **282,218** | **225,642** | **0.62× / 0.80×** |
| On-chain `verifyProof` tx `gasUsed` | 360,012 | 279,489 | 225,642 | 0.63× / 0.81× |
| Verifier deploy gas | 2,097,861 | 953,770 | 3,639,905 | 1.74× / 3.82× |
| Verifier runtime bytecode | 3,739 B | 4,167 B | 16,619 B | 4.44× / 3.99× |
| Verifier source size | ~140 lines (+ `Pairing.sol`) | 117 lines (+ `Pairing.sol`) | 1,392 lines (Yul-heavy) | — |
| **Proving time — 4 pinned cores (run 1 / 2 / 3)** | 2.78 / 2.80 / 2.81 s | (same prover) | 47.35 / 47.68 / 46.65 s | — |
| **Proving time — 4 pinned cores (mean / median)** | **2.80 s / 2.80 s** | (same prover) | **47.23 s / 47.35 s** | **16.9× / 16.9×** |
| Peak RSS while proving (4 pinned cores, max of 3) | 2.59 GiB (2,655 MiB) | (same prover) | 9.48 GiB (9,708 MiB) | 3.66× |
| **Proving time — unpinned 24 vCPU (run 1 / 2 / 3)** | 1.60 / 1.53 / 1.60 s | (same prover) | 37.10 / 38.55 / 39.58 s | — |
| **Proving time — unpinned 24 vCPU (mean / median)** | **1.58 s / 1.60 s** | (same prover) | **38.41 s / 38.55 s** | **24.4× / 24.1×** |
| Peak RSS while proving (unpinned, max of 3) | 2.56 GiB (2,619 MiB) | (same prover) | 10.39 GiB (10,637 MiB) | 4.06× |
| Setup wall time (single-party dev G16 vs deterministic fflonk) | 8.65 s setup + 3.61 s contribute | (same setup) | 7.57 s | — |
| Peak RSS during setup | 1.18 GiB (setup) / 0.45 GiB (contrib) | (same setup) | 6.57 GiB (6,733 MiB) | 5.55× |
| Proving key (`zkey`) size | 41.8 MiB (43,818,940 B) | (same zkey) | 427.8 MiB (448,562,104 B) | 10.24× |
| Proof JSON size | 805 B | 805 B | 2,252 B | 2.80× |
| Proof payload (excluding 8 public signals) | 8 × 32 B = 256 B | 8 × 32 B = 256 B | 24 × 32 B = 768 B | 3.00× |
| `verifyProof` calldata (4 B selector + proof + 8 signals) | 516 B (98 zero / 418 non-zero) | 516 B (98 zero / 418 non-zero) | 1,028 B (102 zero / 926 non-zero) | 1.99× (+512 B) |
| Signed EIP-1559 tx size (raw / FastLZ) | 630 B / 552 B | 630 B / 552 B | 1,142 B / 1,080 B | +512 B / +528 B |
| Phase-1 ptau power required | **2^17** (CI `ppot_0080_17.ptau`) | **2^17** | **2^21** (`ppot_0080_21.ptau`) | 16× domain (2.25 GiB file) |
| **Trusted setup & trust model** | **Universal Phase-1 SRS (PSE PPOT) + per-circuit Phase-2 MPC ceremony** (toxic waste per circuit revision; dev keys used here are UNAPPROVED single-party) | Same as Pilot G16 | **Universal Phase-1 SRS only (PSE PPOT 2^21, 80 contributors)**; **no per-circuit Phase-2 ceremony** (circuit compilation is deterministic; security still depends on 1-of-N honesty in Phase-1 SRS) | Eliminates per-circuit Phase-2 MPC; retains Phase-1 SRS trust |
| **Verifier licence & readiness** | **Apache-2.0** (shipped `PilotGroth16Verifier.sol`) | **Apache-2.0** (`scripts/generate_verifier.mjs`) | **GPL-3.0** (snarkjs export, **not committed**; requires greenfield Apache-2.0 rewrite + audit) | Major licensing/audit blocker |

All measured proofs (6 Groth16 + 6 fflonk across 4-core and unpinned runs) verified off-chain (`snarkjs groth16 verify` → `OK!`; `snarkjs fflonk verify` → `PROOF VERIFIED SUCCESSFULLY`) and matched all 8 expected public signals. On the local Hardhat EVM harness, all three verifier contracts returned `true` on the valid proof and `false` when `pubSignals[0]` was incremented by 1.

The Phase-1 parameter file used for both setups in this measurement was PSE Perpetual Powers of Tau `ppot_0080_21.ptau` (2,416,012,434 B):

```
url:     https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_21.ptau
sha256:  b4131202088141088d83fc05d654a142b51117df0960568613069e0719e7645a
blake2b: bdd12bbbad348efdf86fd9c9765ec2f59b407ba3fac0fd3f4f73083eac6a09a11e93cc7a12b9e468dde972a8b643cd1b1cf57aebb780d366932f2ddd07aeab47
```

*(Note: `storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_*.ptau` returned HTTP 403 at measurement time; PSE's public 80-contributor PPOT bucket is the same source already pinned by `.github/workflows/ci.yml` for `ppot_0080_17.ptau`.)*

### Modeled L2 verification cost (`pilot-transfer-v3`)

Using the measured signed transactions (`630 B` / `552 B` FastLZ for Groth16; `1,142 B` / `1,080 B` FastLZ for fflonk) with `scripts/l2_cost_model.py` (2026-08-02 mainnet chain scalars, ETH `$1,864`, assumed 1/17 blob/L1 coupling):

#### Observed 2026-08-02 (L1 base fee 0.0425 gwei, blob base fee 2,400,000 wei, ETH $1,864)

| Chain | System | Exec gas | Exec (USD) | L1 DA (USD) | Total (USD) | L1 share | vs Pilot G16 | vs Hardcoded G16 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Base | Groth16 (`PilotGroth16Verifier`) | 362,824 | $0.00406 | $0.00000 | $0.00406 | 0% | baseline | — |
| Base | Groth16 (hardcoded VK) | 282,218 | $0.00316 | $0.00000 | $0.00316 | 0% | — | baseline |
| Base | fflonk | 225,642 | $0.00252 | $0.00001 | $0.00253 | 0% | **0.62×** | **0.80×** |
| OP Mainnet | Groth16 (`PilotGroth16Verifier`) | 362,824 | $0.00068 | $0.00000 | $0.00068 | 1% | baseline | — |
| OP Mainnet | Groth16 (hardcoded VK) | 282,218 | $0.00053 | $0.00000 | $0.00053 | 1% | — | baseline |
| OP Mainnet | fflonk | 225,642 | $0.00042 | $0.00001 | $0.00043 | 2% | **0.63×** | **0.81×** |
| Arbitrum One | Groth16 (`PilotGroth16Verifier`) | 362,824 | $0.01353 | $0.00002 | $0.01354 | 0% | baseline | — |
| Arbitrum One | Groth16 (hardcoded VK) | 282,218 | $0.01052 | $0.00002 | $0.01054 | 0% | — | baseline |
| Arbitrum One | fflonk | 225,642 | $0.00841 | $0.00003 | $0.00844 | 0% | **0.62×** | **0.80×** |

#### Modeled L2 inversion thresholds (`pilot-transfer-v3`, real signed tx bytes)

| Chain | Breakeven blob base fee (vs Pilot G16 / Hardcoded G16) | Breakeven L1 base fee (vs Pilot G16 / Hardcoded G16) | Headroom vs 2026-08-02 |
|---|---:|---:|---:|
| Base | 1,763,692,106 wei / 726,515,467 wei | 18.9 gwei / 7.8 gwei | 446× / 184× |
| OP Mainnet | 302,587,050 wei / 122,733,447 wei | **2.2 gwei / 0.9 gwei** | **51× / 21×** |
| Arbitrum One | 933,241,360 wei / 384,883,317 wei | 15.9 gwei / 6.5 gwei | 373× / 154× |

`scripts/l2_cost_model.py` has been updated so its built-in profiles (`--profile pilot`, `--profile pilot-hardcoded`, and `--profile legacy`) carry these measured constants directly (defaulting to `pilot`).

### `pilot-transfer-v3` reproduction commands

The GPL-3.0 fflonk verifier is deliberately **not committed**. Generate it in a gitignored directory (`packages/contracts/contracts/bench/local/`), measure, and remove it afterwards:

```bash
# 0. Prerequisites: circom 2.2.2 (SHA-256 f3d8d1fd...fe9d5), npm ci, uv sync --all-extras
BENCH=/tmp/fflonk-pilot-bench
mkdir -p "$BENCH"

# 1. Compile pilot-transfer-v3 from source
circom circuits/pilot_compliance.circom --r1cs --wasm --sym -l node_modules -o "$BENCH"
node node_modules/snarkjs/build/cli.cjs r1cs info "$BENCH/pilot_compliance.r1cs"

# 2. Download PSE Perpetual Powers of Tau 2^21 (required for domain size 2^17 in fflonk)
curl --fail --location --max-time 600 \
  https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_21.ptau \
  -o "$BENCH/ppot_0080_21.ptau"
echo "b4131202088141088d83fc05d654a142b51117df0960568613069e0719e7645a  $BENCH/ppot_0080_21.ptau" | sha256sum --check

# 3. Generate the synthetic pilot-transfer-v3 witness
uv run python -c '
import json, runpy
from pathlib import Path
from src.prover.pilot_compliance import PUBLIC_SIGNALS
out = Path("/tmp/fflonk-pilot-bench")
fixture = runpy.run_path("tests/unit/test_pilot_compliance.py")
witness, _, _ = fixture["synthetic_case"](artifact_manifest_digest="0"*64, with_trust=True)
(out / "synthetic.json").write_text(json.dumps(witness))
(out / "expected-public.json").write_text(json.dumps([witness[name] for name in PUBLIC_SIGNALS]))
'
node "$BENCH/pilot_compliance_js/generate_witness.js" \
  "$BENCH/pilot_compliance_js/pilot_compliance.wasm" \
  "$BENCH/synthetic.json" "$BENCH/synthetic.wtns"

# 4. Setup: fflonk (universal, no Phase 2) and Groth16 (dev-only single-party Phase 2)
/usr/bin/time -f "fflonk_setup wall=%e user=%U sys=%S rss_kib=%M" \
  node node_modules/snarkjs/build/cli.cjs fflonk setup \
  "$BENCH/pilot_compliance.r1cs" "$BENCH/ppot_0080_21.ptau" "$BENCH/pilot_fflonk.zkey"
node node_modules/snarkjs/build/cli.cjs zkey export verificationkey \
  "$BENCH/pilot_fflonk.zkey" "$BENCH/pilot_fflonk_vkey.json"
node node_modules/snarkjs/build/cli.cjs zkey export solidityverifier \
  "$BENCH/pilot_fflonk.zkey" "$BENCH/PilotFflonkVerifier.sol"

/usr/bin/time -f "g16_setup wall=%e user=%U sys=%S rss_kib=%M" \
  node node_modules/snarkjs/build/cli.cjs groth16 setup \
  "$BENCH/pilot_compliance.r1cs" "$BENCH/ppot_0080_21.ptau" "$BENCH/pilot_g16_0000.zkey"
/usr/bin/time -f "g16_contrib wall=%e user=%U sys=%S rss_kib=%M" \
  node node_modules/snarkjs/build/cli.cjs zkey contribute \
  "$BENCH/pilot_g16_0000.zkey" "$BENCH/pilot_g16_final.zkey" \
  --name="Bench dev only" -e="pilot-v3-bench-unapproved"
node node_modules/snarkjs/build/cli.cjs zkey export verificationkey \
  "$BENCH/pilot_g16_final.zkey" "$BENCH/pilot_g16_vkey.json"
node scripts/generate_verifier.mjs \
  "$BENCH/pilot_g16_vkey.json" "$BENCH/PilotGroth16VerifierHardcoded.sol"

# 5. Proving (1 warmup + 3 measured runs on 4 distinct physical cores, matching native_prover.py)
for i in 0 1 2 3; do
  /usr/bin/time -f "g16_4c_${i} wall=%e user=%U sys=%S rss_kib=%M" \
    taskset -c 0,1,2,3 node node_modules/snarkjs/build/cli.cjs groth16 prove \
    "$BENCH/pilot_g16_final.zkey" "$BENCH/synthetic.wtns" \
    "$BENCH/g16_4c_${i}_proof.json" "$BENCH/g16_4c_${i}_public.json"
  /usr/bin/time -f "fflonk_4c_${i} wall=%e user=%U sys=%S rss_kib=%M" \
    taskset -c 0,1,2,3 node node_modules/snarkjs/build/cli.cjs fflonk prove \
    "$BENCH/pilot_fflonk.zkey" "$BENCH/synthetic.wtns" \
    "$BENCH/fflonk_4c_${i}_proof.json" "$BENCH/fflonk_4c_${i}_public.json" >/dev/null
done

# 6. Verify off-chain and export fflonk Solidity calldata
node node_modules/snarkjs/build/cli.cjs groth16 verify \
  "$BENCH/pilot_g16_vkey.json" "$BENCH/g16_4c_1_public.json" "$BENCH/g16_4c_1_proof.json"
node node_modules/snarkjs/build/cli.cjs fflonk verify \
  "$BENCH/pilot_fflonk_vkey.json" "$BENCH/fflonk_4c_1_public.json" "$BENCH/fflonk_4c_1_proof.json"
node node_modules/snarkjs/build/cli.cjs zkey export soliditycalldata \
  "$BENCH/fflonk_4c_1_public.json" "$BENCH/fflonk_4c_1_proof.json" > "$BENCH/fflonk_calldata.txt"

# 7. Local EVM gas & calldata measurement (copy verifiers into gitignored bench/local/, compile, run, clean up)
mkdir -p packages/contracts/contracts/bench/local
cp "$BENCH/PilotFflonkVerifier.sol" packages/contracts/contracts/bench/local/FflonkVerifier.sol
sed 's|"\./Pairing\.sol"|"../../Pairing.sol"|g; s|contract Groth16Verifier|contract Groth16VerifierPilotHardcoded|g' \
  "$BENCH/PilotGroth16VerifierHardcoded.sol" \
  > packages/contracts/contracts/bench/local/Groth16VerifierPilotHardcoded.sol
(cd packages/contracts && npx hardhat compile)
# Run local Hardhat script deploying PilotGroth16Verifier, Groth16VerifierPilotHardcoded, and FflonkVerifier,
# verifying valid + tampered proofs, recording estimateGas/gasUsed/deployGas/bytecode and writing signed tx JSON.
# Then price on L2 and discard uncommitted GPL verifier + typechain edits:
uv run python scripts/l2_cost_model.py --inputs "$BENCH/l2_inputs_pilot_contract.json"
uv run python scripts/l2_cost_model.py --inputs "$BENCH/l2_inputs_hardcoded_contract.json"
rm -rf packages/contracts/contracts/bench/local && git checkout -- packages/contracts/typechain-types/

# 8. Tests & static analysis
uv run python -m pytest tests/unit/test_l2_cost_model.py -v
bash scripts/circuit_lint.sh
```

### Risks and limitations (`pilot-transfer-v3`)

- **GPL-3.0 verifier template:** snarkjs exports a 1,392-line Yul-heavy Solidity verifier under GPL-3.0 (not committed here). Adopting fflonk still requires a greenfield Apache-2.0 verifier implementation and independent security audit per ADR 0001.
- **Proving latency and memory:** ~47 s and ~9.5 GiB RSS per proof on 4 cores (~38 s / ~10.4 GiB unpinned) makes synchronous HTTP proving non-viable and requires large worker RAM; unlike Groth16 (which has rapidsnark at 1.05 s / 86 MiB), no audited native fflonk prover is integrated.
- **Large universal SRS:** fflonk on `pilot-transfer-v3` requires a 2^21 ptau (`2.25 GiB`), which increases CI cache/download footprint and key-generation RAM (`6.57 GiB`).
- **Narrower L2 headroom vs hardcoded Groth16:** Against a hardcoded-VK Groth16 verifier (which eliminates `PilotGroth16Verifier`'s ~80.6k gas of storage VK reads), fflonk saves 56,576 gas instead of 137,182 gas, dropping OP Mainnet's modeled inversion threshold to ~0.9 gwei L1 base fee.
- **Not measured here:** BLS12-381 (tracked separately in C2 / ADR 0002), wallet-ownership circuit composition (AIF-67), live mainnet/testnet L2 receipts for `pilot-transfer-v3`, and recursive aggregation. All keys generated here are unapproved development/benchmark artifacts.

---

## Legacy 16-signal benchmark (AIF-86 — 2026-07-31)

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

Groth16 also has an optional native prover, rapidsnark. The
[October current-profile benchmark](../benchmarks/2026-10-05-native-prover.md)
measured a 4.7-fold prove-only improvement on a different, eight-signal circuit.
It does not establish a universal 10–50-fold improvement or sub-200 ms production
latency. The July figures above remain measurements of this legacy 16-signal
circuit; native timing and production throughput must be measured for the chosen
profile, host and complete pipeline.

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

## L2 live receipts (AIF-99 — 2026-10-08)

Live `verifyProof` transactions on Base Sepolia, Arbitrum Sepolia and Optimism
Sepolia. Script: `packages/contracts/scripts/ops/measure-l2-verify-cost.ts`.
Receipts: `packages/contracts/deployments/{base,arbitrum,optimism}-sepolia-l2-verify-cost.json`.
Ceremony / fflonk cutover path: see the **Panel path note (2026-10-08)** in
[`docs/adr/0004-fflonk-universal-setup.md`](../adr/0004-fflonk-universal-setup.md).

| Chain | System | `gasUsed` | Calldata | `l1Fee` (wei) | Exec fee (USD) | L1 fee (USD) | Total (USD) | vs G16 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Base Sepolia | Groth16 | 338,201 | 772 B | 763 | $0.00503 | ~$0 | $0.00503 | — |
| Base Sepolia | fflonk | 232,646 | 1,284 B | 1,508 | $0.00346 | ~$0 | $0.00346 | **0.69×** |
| OP Sepolia | Groth16 | 338,201 | 772 B | 1,822 | $0.00084 | ~$0 | $0.00084 | — |
| OP Sepolia | fflonk | 232,646 | 1,284 B | 3,601 | $0.00058 | ~$0 | $0.00058 | **0.69×** |
| Arb Sepolia | Groth16 | 338,201 | 772 B | `gasUsedForL1=0` | $0.0659 | $0 | $0.0659 | — |
| Arb Sepolia | fflonk | 232,646 | 1,284 B | `gasUsedForL1=0` | $0.0454 | $0 | $0.0454 | **0.69×** |

ETH/USD ≈ $2,477–$2,479 (Coinbase spot at measurement). OP Stack receipts also
expose `l1BlobBaseFee=2` wei and non-zero `l1BlobBaseFeeScalar` — i.e. post-4844
blob pricing is active; absolute DA cost is still negligible at these testnet
fee floors. fflonk's L1 fee is ~1.98× Groth16's on Base and OP (matches the
larger calldata), but DA is ≪1% of total cost, so the ranking does not invert.

Arbitrum Sepolia reported `gasUsedForL1=0` for both systems (Nitro field on the
receipt). Execution-gas ranking is unchanged; absolute DA was not separately
billable on that testnet snapshot.

**Conclusion for ADR 0004:** at current L2 testnet fee regimes, fflonk remains
~0.69× Groth16 total cost — the same ratio as L1 execution gas. The August
modeled warning still stands for high L1 base-fee regimes (see
`FFLONK_L2_COST_MODEL.md`: OP Mainnet crossover ~1.7 gwei). Live receipts close
the "unmeasured on L2" gap; they do not by themselves accept ADR 0004.

## What this does not measure

- **BLS12-381.** ADR 0002 recommends BLS12-381 at the production ceremony. fflonk was measured on BN254 only. If both migrations were pursued they interact, and that combination is unmeasured.
- **Recursive/aggregated verification**, which would change the calculus for both.
- **A native fflonk prover.** None is known to exist; the 20× figure is snarkjs-to-snarkjs and therefore *flattering* to fflonk relative to a rapidsnark-backed Groth16 deployment.
- **Mainnet L2 fees under congestion.** Receipts are Sepolia testnets at floor fees; use `FFLONK_L2_COST_MODEL.md` for high-fee regime sensitivity.

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
