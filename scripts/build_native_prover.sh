#!/usr/bin/env bash
# Source-pinned development build; retains upstream sources and license notices.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo 'Usage: bash scripts/build_native_prover.sh /absolute/new/output-directory' >&2
    exit 2
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    echo 'This build recipe requires Linux x86_64; existing JavaScript paths remain available.' >&2
    exit 2
fi
for tool in git curl sha256sum gcc g++ make cmake nasm m4 python3 realpath; do
    command -v "$tool" >/dev/null || { echo "Missing build prerequisite: $tool" >&2; exit 2; }
done
if [[ "$1" != /* ]]; then
    echo 'Output must be an absolute path that does not already exist.' >&2
    exit 2
fi
output=$(realpath -m -- "$1")
if [[ -e "$output" || -L "$output" ]]; then
    echo 'Output must be an absolute path that does not already exist.' >&2
    exit 2
fi
repository=$(git rev-parse --show-toplevel)
case "$output/" in
    "$repository/"*) echo 'Keep unapproved native builds outside the repository.' >&2; exit 2 ;;
esac
git clone --no-checkout https://github.com/iden3/rapidsnark.git "$output"
git -C "$output" checkout --detach 81eddf1a536d26497b237c0b8a04fe90baf7e439
test "$(git -C "$output" rev-parse HEAD)" = 81eddf1a536d26497b237c0b8a04fe90baf7e439
git -C "$output" submodule update --init --depth 1 depends/ffiasm depends/json
test "$(git -C "$output/depends/ffiasm" rev-parse HEAD)" = aa90166dc4c5a075b835a398e15cc1e06ac90e95
test "$(git -C "$output/depends/json" rev-parse HEAD)" = 350ff4f7ced7c4117eae2fb93df02823c8021fcb
(
    cd "$output"
    # GCC 15 defaults to GNU23; upstream GMP's configure tests require GNU17.
    # The pinned script verifies GMP 6.3.0's source SHA before extraction.
    sed 's/^NPROC=8$/NPROC=1/' build_gmp.sh | CFLAGS='-O2 -std=gnu17' bash -s -- host
    # Upstream can exit successfully after a failed configure; require outputs.
    test -s depends/gmp/package/lib/libgmp.a
    test -s depends/gmp/package/include/gmp.h
    # Upstream relies on an incidental cstdint include, absent with GCC 15.
    cmake -S . -B build_prover -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS='-include cstdint'
    cmake --build build_prover --target prover --parallel 1
)
python3 - "$output" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
binary = root / "build_prover/src/prover"
receipt = {
    "assurance": "source-pinned development build; independent operator approval still required",
    "upstream_commit": "81eddf1a536d26497b237c0b8a04fe90baf7e439",
    "ffiasm_commit": "aa90166dc4c5a075b835a398e15cc1e06ac90e95",
    "json_commit": "350ff4f7ced7c4117eae2fb93df02823c8021fcb",
    "gmp_source_sha256": "a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898",
    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    "compiler": subprocess.check_output(["g++", "--version"], text=True).splitlines()[0],
    "assembler": subprocess.check_output(["nasm", "--version"], text=True).strip(),
    "gmp_cflags": "-O2 -std=gnu17",
    "cxxflags": "-include cstdint",
}
(root / "clearproof-build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
print("Built optional prover:", binary)
print("SHA256:", receipt["binary_sha256"])
print("Sources, license notices and build receipt retained in:", root)
PY
