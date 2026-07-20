#!/usr/bin/env bash
# compile_circuits.sh — Compile ZK Travel Rule circuits and generate Groth16 proving/verification keys.
#
# Usage:
#   bash scripts/compile_circuits.sh
#
# Prerequisites:
#   - circom v2.x (https://docs.circom.io/getting-started/installation/)
#   - snarkjs v0.7.x (npm install snarkjs)
#
# Output artifacts are written to artifacts/.

set -euo pipefail

CIRCUITS_DIR="circuits"
BUILD_DIR="artifacts"
PTAU_POWER=18  # 2^18 constraints (dev; increase for production)
PTAU_FILE="$BUILD_DIR/pot${PTAU_POWER}_final.ptau"
CONTRACTS_DIR="packages/contracts/contracts"

# ---------------------------------------------------------------------------
# Dev key entropy
# ---------------------------------------------------------------------------
# zkey contributions use fresh randomness by default. NOTE: snarkjs mixes OS
# randomness into every contribution even when -e is given, so dev builds are
# NEVER byte-reproducible — the zkey, verification key, Solidity verifier,
# and tests/vectors/ must always be regenerated and committed TOGETHER.
# These keys are DEV-ONLY and insecure by construction; production keys must
# come from the documented MPC ceremony (docs/internal/CEREMONY_RUNBOOK.md).
DEV_ENTROPY="${CLEARPROOF_DEV_ENTROPY:-$(head -c 32 /dev/urandom | xxd -p)}"

# Powers of Tau: reuse the audited Hermez 2^18 ptau (same as CI; itself an
# MPC artifact with hundreds of independent contributions). Set
# CLEARPROOF_GENERATE_PTAU=1 to run a local single-party ceremony instead.
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau"
PTAU_SHA256="e970efa7774da80101e0ac336d083ef3339855c98112539338d706b2b89ac694"

echo "=== ZK Travel Rule Circuit Compilation ==="
echo ""

# ---------------------------------------------------------------------------
# Step 0: Check prerequisites
# ---------------------------------------------------------------------------

if ! command -v circom &>/dev/null; then
    echo "ERROR: circom not found in PATH."
    echo "Install: https://docs.circom.io/getting-started/installation/"
    exit 1
fi

if ! command -v npx &>/dev/null; then
    echo "ERROR: npx not found in PATH (need Node.js + npm)."
    exit 1
fi
# snarkjs --help exits 99 (help mode) but outputs to stdout.
# Using || true on the command so set -o pipefail doesn't abort on non-zero exit.
SNARKJS_VER=$(npx snarkjs --help 2>/dev/null | head -1 || true)
if [ -z "$SNARKJS_VER" ]; then
    echo "ERROR: snarkjs not found. Run: npm install snarkjs"
    exit 1
fi
echo "circom version: $(circom --version)"
echo "snarkjs version: $SNARKJS_VER"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Step 1: Powers of tau ceremony (dev: single party, 2^18)
# ---------------------------------------------------------------------------
# WARNING: For production, use a multi-party ceremony!
# See: https://github.com/iden3/perpetual-powers-of-tau

if [ ! -f "$PTAU_FILE" ]; then
    if [ "${CLEARPROOF_GENERATE_PTAU:-0}" = "1" ]; then
        echo "Running powers of tau ceremony (2^${PTAU_POWER}, dev single-party)..."
        echo "WARNING: locally generated ptau produces keys that differ from CI/committed artifacts."

        # Start a new ceremony
        npx snarkjs powersoftau new bn128 "$PTAU_POWER" \
            "$BUILD_DIR/pot${PTAU_POWER}_0000.ptau" \
            -v

        # Single contribution (dev only — use MPC ceremony for production)
        npx snarkjs powersoftau contribute \
            "$BUILD_DIR/pot${PTAU_POWER}_0000.ptau" \
            "$BUILD_DIR/pot${PTAU_POWER}_0001.ptau" \
            --name="Dev contribution" \
            -e="$DEV_ENTROPY"

        # Prepare phase 2
        npx snarkjs powersoftau prepare phase2 \
            "$BUILD_DIR/pot${PTAU_POWER}_0001.ptau" \
            "$PTAU_FILE" \
            -v

        # Clean up intermediate files
        rm -f "$BUILD_DIR/pot${PTAU_POWER}_0000.ptau" \
              "$BUILD_DIR/pot${PTAU_POWER}_0001.ptau"

        echo "Powers of tau ceremony complete."
    else
        echo "Downloading audited Hermez powers of tau (2^${PTAU_POWER})..."
        curl -L --fail --max-time 600 "$PTAU_URL" -o "$PTAU_FILE"
        ACTUAL_SHA256=$(sha256sum "$PTAU_FILE" | awk '{print $1}')
        if [ "$ACTUAL_SHA256" != "$PTAU_SHA256" ]; then
            echo "ERROR: ptau SHA256 mismatch!"
            echo "  Expected: $PTAU_SHA256"
            echo "  Actual:   $ACTUAL_SHA256"
            rm -f "$PTAU_FILE"
            exit 1
        fi
        echo "ptau checksum verified."
    fi
else
    echo "Using existing powers of tau: $PTAU_FILE"
fi

# ---------------------------------------------------------------------------
# Step 2: Compile the main compliance circuit
# ---------------------------------------------------------------------------

echo ""
echo "Compiling compliance circuit..."
circom "$CIRCUITS_DIR/compliance.circom" \
    --r1cs --wasm --sym \
    -l node_modules \
    -o "$BUILD_DIR"

echo "Circuit compiled. Constraints:"
npx snarkjs r1cs info "$BUILD_DIR/compliance.r1cs"

# Verify WASM was generated
if [ ! -f "$BUILD_DIR/compliance_js/compliance.wasm" ]; then
    echo "ERROR: WASM file not generated!"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Generate proving and verification keys (Groth16 phase 2)
# ---------------------------------------------------------------------------

echo ""
echo "Running Groth16 trusted setup (phase 2)..."

npx snarkjs groth16 setup \
    "$BUILD_DIR/compliance.r1cs" \
    "$PTAU_FILE" \
    "$BUILD_DIR/compliance_0000.zkey"

# Single contribution (dev only — use the documented MPC ceremony for production)
npx snarkjs zkey contribute \
    "$BUILD_DIR/compliance_0000.zkey" \
    "$BUILD_DIR/compliance_final.zkey" \
    --name="Dev contribution" \
    -e="$DEV_ENTROPY"

# Clean up intermediate zkey
rm -f "$BUILD_DIR/compliance_0000.zkey"

# Export verification key
npx snarkjs zkey export verificationkey \
    "$BUILD_DIR/compliance_final.zkey" \
    "$BUILD_DIR/verification_key.json"

# ---------------------------------------------------------------------------
# Step 4: Generate Solidity verifier
# ---------------------------------------------------------------------------

echo ""
echo "Generating Solidity verifier..."

# clearproof's own Apache-2.0 generator (the snarkjs exporter emits a
# GPL-3.0-licensed template — see docs/adr/0001-groth16-verifier-licensing.md)
node scripts/generate_verifier.mjs \
    "$BUILD_DIR/verification_key.json" \
    "$CONTRACTS_DIR/Groth16Verifier.sol"

echo "Solidity verifier written to: $CONTRACTS_DIR/Groth16Verifier.sol"

# ---------------------------------------------------------------------------
# Step 5: Verify all artifacts exist
# ---------------------------------------------------------------------------

echo ""
echo "=== Verifying artifacts ==="

ARTIFACTS=(
    "$BUILD_DIR/compliance.r1cs"
    "$BUILD_DIR/compliance.sym"
    "$BUILD_DIR/compliance_js/compliance.wasm"
    "$BUILD_DIR/compliance_final.zkey"
    "$BUILD_DIR/verification_key.json"
    "$CONTRACTS_DIR/Groth16Verifier.sol"
)

ALL_OK=true
for artifact in "${ARTIFACTS[@]}"; do
    if [ -f "$artifact" ]; then
        SIZE=$(stat -c%s "$artifact" 2>/dev/null || stat -f%z "$artifact" 2>/dev/null || echo "?")
        echo "  [OK] $artifact ($SIZE bytes)"
    else
        echo "  [MISSING] $artifact"
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = false ]; then
    echo ""
    echo "ERROR: Some artifacts are missing!"
    exit 1
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "=== Build Complete ==="
echo "Artifacts:"
echo "  $BUILD_DIR/compliance_js/compliance.wasm"
echo "  $BUILD_DIR/compliance_final.zkey"
echo "  $BUILD_DIR/verification_key.json"
echo "  $BUILD_DIR/compliance.r1cs"
echo "  $CONTRACTS_DIR/Groth16Verifier.sol"
