# Groth16 development setup (BN254)

**Status:** development only. No ceremony has been run. Every proving and
verification key produced by the commands below is unapproved, and production
configuration rejects them. Nothing here is audited.

This document describes how the repository creates development keys for its two
proof profiles. The planned production ceremony is a separate document,
[CEREMONY_RUNBOOK.md](CEREMONY_RUNBOOK.md). It targets BLS12-381 (ADR 0002), so
no BN254 file or key named here can be reused for it, and its scheduling depends
on the open decision in ADR 0004.

## Circuits

| Profile | Circuit | Main instantiation | Constraints | Public signals | Phase-1 file |
|---------|---------|--------------------|-------------|----------------|--------------|
| `pilot-transfer-v3` (current) | `circuits/pilot_compliance.circom` | `PilotCompliance(32, 20, 20)`: issuance 32, authorized issuers 20, sanctions 20 | 95,408 (ADR 0011) | 8 | Needs 2^17 or larger |
| Legacy 16-signal demo | `circuits/compliance.circom` | `ComplianceProof(20, 10)`: sanctions 20, issuer 10 | 30,164 (measured 2026-07-31, [FFLONK_BENCHMARK.md](FFLONK_BENCHMARK.md)) | 16: 14 public inputs and 2 outputs (`is_compliant`, `sar_review_flag`) | CI uses the same 2^17 file; `compile_circuits.sh` uses a 2^18 file |

Signal order and meaning are in `specs/pilot-transfer-v3.md` (pilot) and
[CIRCUIT_SIGNALS.md](CIRCUIT_SIGNALS.md) (both). The two profiles have different
keys and verifiers. Never choose a profile by signal count.

Both use the BN254 (`bn128`) curve:

- **Scalar field (r)**: 21888242871839275222246405745257275088548364400416034343698204186575808495617
- **Base field (q)**: 21888242871839275222246405745257275088696311157297823662689037894645226208583

## Setup phases

Groth16 setup has two phases:

1. **Powers of tau (phase 1)** is independent of the circuit. A prepared `.ptau`
   file of power `n` supports circuits with up to 2^n constraints.
2. **Circuit-specific setup (phase 2)** derives a proving key and a verification
   key for one compiled circuit (`.r1cs`) from that file.

In every path below, phase 2 is a single local contribution. Whoever ran it could
forge proofs for those keys, which is why they are development keys regardless
of which phase-1 file was used.

## Path 1: both profiles (`scripts/test_development_circuits.py`)

This is the path CI and the local pilot acceptance guide use.

```bash
.venv/bin/python scripts/test_development_circuits.py /absolute/new-development-output \
  --prepared-ptau /absolute/ppot_0080_17.ptau
```

- Compiles `compliance.circom` and `pilot_compliance.circom`, runs phase 2 for
  each, exports the verification keys and performs real proof round trips. It
  refuses to write into an existing directory.
- Writes `<output>/legacy` (`compliance_final.zkey`, `verification_key.json`) and
  `<output>/pilot` (`UNAPPROVED-development.zkey`, `verification-key.json`,
  `manifest.json` and its digest in `development-manifest-pin.txt`).
- `--prepared-ptau` selects an existing prepared phase-1 file. CI passes the PSE
  perpetual powers of tau file `ppot_0080_17.ptau` (2^17), pinned by SHA-256
  `f807e065fde53f72f4bf4d57140fab85b26daa6cc95bdfec7cce93622b3a367c` in
  `.github/workflows/ci.yml`. The download command is in
  `docs/operations/local-pilot-acceptance.md`.
- Without `--prepared-ptau` the script generates a local single-party 2^17
  phase 1, which can take well over an hour.

See [PILOT_DEVELOPMENT_ARTIFACTS.md](PILOT_DEVELOPMENT_ARTIFACTS.md).

## Path 2: legacy circuit only (`scripts/compile_circuits.sh`)

```bash
bash scripts/compile_circuits.sh
```

This script builds the legacy 16-signal circuit only. It does not build
`pilot_compliance.circom`.

- Phase 1: downloads the Hermez `powersOfTau28_hez_final_18.ptau` (2^18) and
  checks it against a SHA-256 pinned in the script. This is a different file
  from the one CI uses. `CLEARPROOF_GENERATE_PTAU=1` generates a local
  single-party 2^18 file instead.
- Phase 2: one local contribution.
- Writes to `artifacts/` in the checkout:

```
artifacts/
├── pot18_final.ptau          # phase-1 file (downloaded or generated)
├── compliance.r1cs
├── compliance.sym
├── compliance_js/
│   └── compliance.wasm
├── compliance_final.zkey     # development proving key
└── verification_key.json     # development verification key
```

- Regenerates `packages/contracts/contracts/Groth16Verifier.sol` in place with
  `scripts/generate_verifier.mjs`.

Development keys are never byte-reproducible, because snarkjs mixes operating
system randomness into every contribution. The legacy proving key, verification
key, `Groth16Verifier.sol` and the vectors under `tests/vectors/` must therefore
be regenerated and committed together or not at all.

## Solidity verifiers

Do not use `snarkjs zkey export solidityverifier`. Its template is GPL-3.0
(ADR 0001). The repository has its own Apache-2.0 generators:

- `scripts/generate_verifier.mjs` renders the legacy `Groth16Verifier.sol` from a
  snarkjs verification key.
- `PilotGroth16Verifier.sol` is a fixed source file. It takes the verification
  key and the artifact-manifest digest as constructor arguments, so a new pilot
  key does not change the Solidity source.
- `scripts/generate_verifier_bls.mjs` renders the BLS12-381 benchmark verifier
  (ADR 0002).

## Checking a development key

```bash
# The proving key matches the circuit and the phase-1 file
npx snarkjs zkey verify compliance.r1cs pot18_final.ptau compliance_final.zkey

# The phase-1 file is well formed
npx snarkjs powersoftau verify pot18_final.ptau

# The verification key has one IC point per public signal, plus one
npx snarkjs zkey export verificationkey artifacts/compliance_final.zkey /tmp/vkey.json
jq '.IC | length' /tmp/vkey.json   # 17 for the legacy circuit, 9 for the pilot circuit
```

These checks show internal consistency only. They do not make a key trustworthy.

## CI

The `development-circuits` job in `.github/workflows/ci.yml` (the `circuits` job
is a required-check name that depends on it):

1. Installs the SHA-256-pinned Circom binary.
2. Restores or downloads `ppot_0080_17.ptau` and checks its SHA-256.
3. Runs `scripts/test_development_circuits.py` with `--prepared-ptau`, which
   builds development keys for both profiles in the runner's temporary directory
   and runs real proofs against them.
4. Runs the Python and contract suites against those artifacts.

CI does not run a powers-of-tau ceremony, does not use the Hermez file, and does
not commit or publish any key. The job list in the workflow file is authoritative.

## Changing a circuit

Any change to a public signal, a tree depth or a constraint changes the keys.

- Pilot: a new signal order, meaning or depth needs a new profile name
  (ADR 0011), regenerated constants (`scripts/generate_signal_constants.py`) and
  matching changes in every place listed in the root `CLAUDE.md` invariants.
- Legacy: rerun `scripts/compile_circuits.sh`, commit the regenerated
  `Groth16Verifier.sol` with its vectors, and update `ComplianceRegistry.sol` if
  the signal layout changed.

## Troubleshooting

**"Not enough points in the section"**: the phase-1 file is too small for the
circuit. The pilot circuit needs 2^17 or larger.

**Verifier mismatch**: the deployed verifier was generated from a different
verification key than the proving key in use. Regenerate the verifier, key and
test vectors together.

**WASM compilation failure**: check that `circomlib` resolves:

```bash
circom circuits/compliance.circom --r1cs --wasm --sym -l node_modules -o /tmp/build
```
