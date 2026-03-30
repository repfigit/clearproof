#!/usr/bin/env bash
# compile_circuits.sh — Compile ZK Travel Rule circuits and generate proving keys.
#
# Usage:
#   bash scripts/compile_circuits.sh
#
# Prerequisites:
#   - circom (https://docs.circom.io/getting-started/installation/)
#   - snarkjs (npm install snarkjs)
#
# Output artifacts are written to artifacts/.

set -euo pipefail

CIRCUITS_DIR="circuits"
BUILD_DIR="artifacts"
PTAU_POWER=18  # 2^18 constraints (dev; increase for production)
PTAU_FILE="$BUILD_DIR/pot${PTAU_POWER}_final.ptau"

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

# Verify snarkjs is available
if ! npx snarkjs --version &>/dev/null; then
    echo "ERROR: snarkjs not found. Run: npm install snarkjs"
    exit 1
fi

echo "circom version: $(circom --version)"
echo "snarkjs version: $(npx snarkjs --version)"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Step 1: Powers of tau ceremony (dev: single party, 2^18)
# ---------------------------------------------------------------------------

if [ ! -f "$PTAU_FILE" ]; then
    echo "Running powers of tau ceremony (2^${PTAU_POWER}, dev single-party)..."

    # Start a new ceremony
    npx snarkjs powersoftau new bn128 "$PTAU_POWER" \
        "$BUILD_DIR/pot${PTAU_POWER}_0000.ptau" \
        -v

    # Single contribution (dev only — use MPC ceremony for production)
    npx snarkjs powersoftau contribute \
        "$BUILD_DIR/pot${PTAU_POWER}_0000.ptau" \
        "$BUILD_DIR/pot${PTAU_POWER}_0001.ptau" \
        --name="Dev contribution" \
        -e="$(head -c 32 /dev/urandom | xxd -p)"

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

# ---------------------------------------------------------------------------
# Step 3: Generate proving and verification keys (Groth16 phase 2)
# ---------------------------------------------------------------------------

echo ""
echo "Running Groth16 trusted setup (phase 2)..."
npx snarkjs groth16 setup \
    "$BUILD_DIR/compliance.r1cs" \
    "$PTAU_FILE" \
    "$BUILD_DIR/compliance_0000.zkey"

# Single contribution (dev only — use MPC ceremony for production)
npx snarkjs zkey contribute \
    "$BUILD_DIR/compliance_0000.zkey" \
    "$BUILD_DIR/compliance_final.zkey" \
    --name="Dev contribution" \
    -e="$(head -c 32 /dev/urandom | xxd -p)"

# Clean up intermediate zkey
rm -f "$BUILD_DIR/compliance_0000.zkey"

# Export verification key
npx snarkjs zkey export verificationkey \
    "$BUILD_DIR/compliance_final.zkey" \
    "$BUILD_DIR/verification_key.json"

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
