# Groth16 Trusted Setup Documentation

## Overview

This document describes the Groth16 trusted setup ceremony for the ZK Travel Rule Compliance Bridge circuits. The setup consists of two phases:

1. **Powers of Tau** (Phase 1) - Generates toxic waste for the BN128 curve
2. **Circuit-Specific Setup** (Phase 2) - Creates proving and verification keys for each circuit

## Circuit Configuration

| Circuit | Constraints | Tree Depths | Public Signals |
|---------|-------------|-------------|----------------|
| compliance | ~2^18 | sanctions=20, issuer=10 | 14 |

The circuit uses the BN128 elliptic curve pairing, with:
- **Scalar field (r)**: 21888242871839275222246405745257275088548364400416034343698204186575808495617
- **Base field (q)**: 21888242871839275222246405745257275088696311157297823662689037894645226208583

## Phase 1: Powers of Tau Ceremony

The Powers of Tau ceremony establishes the common reference string (CRS) for the BN128 curve. This phase is circuit-agnostic and can be reused across multiple circuits.

### Ceremony Steps

```bash
# Step 1: Start a new ceremony (2^18 constraints)
npx snarkjs powersoftau new bn128 18 pot18_0000.ptau -v

# Step 2: Single contribution (DEV ONLY - see Production section below)
npx snarkjs powersoftau contribute pot18_0000.ptau pot18_0001.ptau \
    --name="First contribution" \
    -e="$(head -c 32 /dev/urandom | xxd -p)"

# Step 3: Prepare phase 2 (convert to circuit-ready format)
npx snarkjs powersoftau prepare phase2 pot18_0001.ptau pot18_final.ptau -v

# Step 4: Clean up intermediate files
rm pot18_0000.ptau pot18_0001.ptau
```

### Security Levels by Power

| Power | Constraints | Use Case |
|-------|-------------|----------|
| 18 | 262,144 | Development |
| 20 | 1,048,576 | Small circuits |
| 21 | 2,097,152 | Production (recommended minimum) |
| 22 | 4,194,304 | High-security applications |

## Phase 2: Circuit-Specific Setup

After Powers of Tau, generate proving and verification keys for each circuit:

```bash
# Generate initial proving key
npx snarkjs groth16 setup compliance.r1cs pot18_final.ptau compliance_0000.zkey

# Single contribution (DEV ONLY)
npx snarkjs zkey contribute compliance_0000.zkey compliance_final.zkey \
    --name="Dev contribution" \
    -e="$(head -c 32 /dev/urandom | xxd -p)"

# Export verification key
npx snarkjs zkey export verificationkey compliance_final.zkey verification_key.json

# Generate Solidity verifier
npx snarkjs zkey export solidityverifier compliance_final.zkey \
    packages/contracts/contracts/Groth16Verifier.sol
```

## Production Trusted Setup Requirements

### Critical Security Considerations

1. **Multi-Party Computation (MPC)**: For production deployments, the Powers of Tau and Phase 2 ceremonies MUST be conducted as MPC ceremonies with contributions from multiple independent parties.

2. **Minimum Contributors**: Recommend at least 4-6 diverse contributors from different organizations.

3. **Toxic Waste Destruction**: Each contributor must securely destroy their random "toxic waste" after contributing. The ceremony is only trustworthy if at least one contributor destroys their randomness.

4. **Attestation**: Each contribution should include a signed attestation with the contributor's public key and a hash of their contribution.

### Recommended Production Tools

- [Perpetual Powers of Tau](https://github.com/iden3/perpetual-powers-of-tau) - For phase 1
- [SnarkJS ceremony](https://github.com/iden3/snarkjs#7-prepare-phase-2-ceremony) - For phase 2 with proper MPC

### Verification

After a ceremony, verify the final artifact:

```bash
# Verify the zkey file is well-formed
npx snarkjs zkey verify compliance.r1cs pot18_final.ptau compliance_final.zkey

# Verify the ceremony transcript (if using MPC)
npx snarkjs powersoftau verify pot18_final.ptau
```

## CI/CD Integration

The CI pipeline performs the following trusted setup steps:

1. Installs circom and snarkjs
2. Compiles circuits to .r1cs format with WASM witness generator
3. Runs Powers of Tau ceremony (dev mode)
4. Performs Groth16 phase 2 setup
5. Exports verification key and Solidity verifier
6. Uploads artifacts for downstream jobs

See `.github/workflows/ci.yml` for the full pipeline configuration.

## Artifact Locations

After running `scripts/compile_circuits.sh`:

```
artifacts/
├── pot18_final.ptau              # Powers of Tau ceremony output
├── compliance.r1cs              # Compiled circuit constraints
├── compliance.sym                # Symbol file for debugging
├── compliance_js/               # WASM witness generator
│   └── compliance.wasm
├── compliance_final.zkey        # Proving key
└── verification_key.json         # Verification key (JSON)
```

The Solidity verifier is written to:
```
packages/contracts/contracts/Groth16Verifier.sol
```

## Regenerating the Verifier

When circuits change (adding/removing signals), regenerate the verifier:

```bash
# 1. Recompile circuits
bash scripts/compile_circuits.sh

# 2. Export new verifier
npx snarkjs zkey export solidityverifier \
    artifacts/compliance_final.zkey \
    packages/contracts/contracts/Groth16Verifier.sol

# 3. Update the ComplianceRegistry to match new signal count
# (see CIRCUIT_SIGNALS.md for signal definitions)
```

## Signal Count Compatibility

The Groth16 verifier has a fixed number of public signal slots (16 for the current configuration). When adding new public inputs:

1. The circuit must be recompiled
2. A new Groth16Verifier.sol must be generated
3. The ComplianceRegistry.sol must be updated to handle the new signal layout

Currently, only 14 of 16 available signal slots are used. The remaining 2 slots are reserved for future use (e.g., additional domain binding or extension fields).

## Troubleshooting

### "Not enough points in the section" Error

This indicates the Powers of Tau ceremony does not have enough capacity for the circuit. Increase the power:

```bash
# If circuit has > 2^18 constraints, use power 20 or higher
npx snarkjs powersoftau new bn128 20 pot20_0000.ptau -v
```

### Verifier Mismatch

If verification fails, ensure the Groth16Verifier.sol matches the zkey file:

```bash
# Compare verification keys
npx snarkjs zkey export verificationkey artifacts/compliance_final.zkey /tmp/vkey.json
cat /tmp/vkey.json | jq '.IC | length'  # Should match public signal count + 1
```

### WASM Compilation Failures

Ensure circomlib is properly linked:

```bash
circom circuits/compliance.circom --r1cs --wasm --sym -l node_modules -o /tmp/build
```
