#!/usr/bin/env bash
# Regenerate the Python gRPC stubs in src/protocol/bridges/ from protos/.
#
# The committed *_pb2.py / *_pb2_grpc.py files are generated with a pinned
# grpcio-tools version and then post-processed:
#   1. Absolute imports rewritten to package-relative imports
#      (`import trisa_api_pb2` -> `from . import trisa_api_pb2`) so the stubs
#      work as part of the `src.protocol.bridges` package.
#   2. The hard `raise RuntimeError` grpcio version guard is downgraded to a
#      `warnings.warn(...)` so a newer/older grpcio runtime warns instead of
#      crashing at import time (pyproject allows grpcio>=1.62).
#
# NEVER hand-edit the generated files. Change this script instead so the
# artifacts stay reproducible. CI runs this script with --check to detect
# drift between protos/ and the committed stubs.
#
# Usage:
#   bash scripts/regen_protobufs.sh           # regenerate in place
#   bash scripts/regen_protobufs.sh --check   # verify committed stubs match protos/
set -euo pipefail

GRPCIO_TOOLS_VERSION="1.80.0"
PROTO_FILES=("trisa_api.proto" "trisa_errors.proto")
OUT_DIR="src/protocol/bridges"

MODE="write"
if [[ "${1:-}" == "--check" ]]; then
  MODE="check"
fi

cd "$(dirname "$0")/.."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
GEN_DIR="$WORK_DIR/gen"
mkdir -p "$GEN_DIR"

echo ">> Generating stubs with grpcio-tools==${GRPCIO_TOOLS_VERSION}"
uv run --quiet --with "grpcio-tools==${GRPCIO_TOOLS_VERSION}" python -m grpc_tools.protoc \
  -Iprotos \
  --python_out="$GEN_DIR" \
  --grpc_python_out="$GEN_DIR" \
  "${PROTO_FILES[@]/#/protos/}"

echo ">> Post-processing (relative imports, warn-only version guard)"
python3 - "$GEN_DIR" <<'PYEOF'
import pathlib
import sys

gen_dir = pathlib.Path(sys.argv[1])

def sub(path: pathlib.Path, old: str, new: str) -> None:
    text = path.read_text()
    if old not in text:
        raise SystemExit(f"post-process failed: pattern not found in {path.name}: {old!r}")
    path.write_text(text.replace(old, new))

# 1. Package-relative imports.
sub(gen_dir / "trisa_api_pb2.py", "import trisa_errors_pb2 as", "from . import trisa_errors_pb2 as")
sub(gen_dir / "trisa_api_pb2_grpc.py", "import trisa_api_pb2 as", "from . import trisa_api_pb2 as")

# 2. Downgrade the grpcio version guard from a hard failure to a warning.
grpc_stub = gen_dir / "trisa_api_pb2_grpc.py"
if "import warnings\n" not in grpc_stub.read_text():
    sub(grpc_stub, "import grpc\n", "import grpc\nimport warnings\n")
sub(grpc_stub, "    raise RuntimeError(\n", "    warnings.warn(\n")
sub(
    grpc_stub,
    "        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'\n    )\n",
    "        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.',\n"
    "        RuntimeWarning,\n"
    "        stacklevel=2,\n"
    "    )\n",
)
PYEOF

GENERATED=(
  "trisa_api_pb2.py"
  "trisa_api_pb2_grpc.py"
  "trisa_errors_pb2.py"
  "trisa_errors_pb2_grpc.py"
)

if [[ "$MODE" == "check" ]]; then
  FAILED=0
  for f in "${GENERATED[@]}"; do
    if ! diff -q "$GEN_DIR/$f" "$OUT_DIR/$f" >/dev/null 2>&1; then
      echo "::error file=$OUT_DIR/$f::$OUT_DIR/$f is stale — regenerate with 'bash scripts/regen_protobufs.sh'"
      FAILED=1
    fi
  done
  if [[ "$FAILED" -ne 0 ]]; then
    echo "Protobuf stubs are out of sync with protos/. Run: bash scripts/regen_protobufs.sh"
    exit 1
  fi
  echo ">> Protobuf stubs are in sync with protos/"
else
  for f in "${GENERATED[@]}"; do
    cp "$GEN_DIR/$f" "$OUT_DIR/$f"
    echo ">> wrote $OUT_DIR/$f"
  done
fi
