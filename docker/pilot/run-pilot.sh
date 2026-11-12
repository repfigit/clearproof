#!/usr/bin/env bash
# Entry point of the local pilot acceptance image. DEVELOPMENT ONLY.
#
# Runs the same three steps as "Start from a source checkout" in the README:
#   1. fetch and SHA-256-check the pinned powers-of-tau file,
#   2. build fresh UNAPPROVED development circuits and keys for both profiles,
#   3. run the complete pilot acceptance (preflight, then the full run) with an
#      owned PostgreSQL 18 cluster and a loopback EVM.
#
# State lives under $PILOT_DATA (a volume): the ptau file and the development
# artifacts are reused by later runs; every run gets a new output directory.
set -euo pipefail

DATA="${PILOT_DATA:-/data}"
PTAU="$DATA/ppot_0080_17.ptau"
PTAU_URL="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_17.ptau"
PTAU_SHA256="f807e065fde53f72f4bf4d57140fab85b26daa6cc95bdfec7cce93622b3a367c"
ARTIFACTS="$DATA/development-artifacts"
POSTGRES_BIN="${POSTGRES_BIN:-/usr/lib/postgresql/18/bin}"
PYTHON="${PILOT_PYTHON:-.venv/bin/python}"

if [[ "$(id -u)" -eq 0 ]]; then
    echo "error: run as an unprivileged user; PostgreSQL refuses to start as root" >&2
    exit 2
fi
if [[ ! -d "$DATA" || ! -w "$DATA" ]]; then
    echo "error: $DATA must be a writable directory (mount a volume there)" >&2
    exit 2
fi

echo "==> Development-only run: keys generated here are UNAPPROVED and must never be used in production."

ptau_ok() { echo "$PTAU_SHA256  $PTAU" | sha256sum --check --status; }
if [[ ! -f "$PTAU" ]] || ! ptau_ok; then
    echo "==> Downloading the pinned powers-of-tau file"
    rm -f "$PTAU.partial"
    curl --fail --location --max-time 900 "$PTAU_URL" -o "$PTAU.partial"
    mv "$PTAU.partial" "$PTAU"
fi
if ! ptau_ok; then
    echo "error: powers-of-tau file does not match its pinned SHA-256" >&2
    exit 1
fi

# The builder requires a new directory. A finished build is marked so an
# interrupted one is never reused.
if [[ ! -f "$ARTIFACTS/.complete" ]]; then
    if [[ -e "$ARTIFACTS" ]]; then
        mv "$ARTIFACTS" "$ARTIFACTS.incomplete.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    echo "==> Building unapproved development circuits and keys (several minutes)"
    "$PYTHON" scripts/test_development_circuits.py "$ARTIFACTS" --prepared-ptau "$PTAU"
    touch "$ARTIFACTS/.complete"
else
    echo "==> Reusing development artifacts in $ARTIFACTS"
fi

RUN_DIR="$DATA/runs/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DATA/runs"
# A short TMPDIR keeps the private PostgreSQL socket path within its length limit.
export TMPDIR="${TMPDIR:-/tmp}"

echo "==> Preflight"
"$PYTHON" scripts/test_pilot_local.py "$ARTIFACTS/pilot" "$RUN_DIR" --postgres-bin "$POSTGRES_BIN" --preflight
echo "==> Pilot acceptance run"
"$PYTHON" scripts/test_pilot_local.py "$ARTIFACTS/pilot" "$RUN_DIR" --postgres-bin "$POSTGRES_BIN"

echo "==> Done. Synthetic reports: $RUN_DIR/pilot/reports and $RUN_DIR/pilot/run.json"
echo "    Keep $RUN_DIR/pilot/private and the PostgreSQL files private; share reports only."
