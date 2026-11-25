# SPDX-License-Identifier: Apache-2.0
"""Build the optional native Poseidon C shared library (clearproof_poseidon).

Usage:
    uv run python scripts/build_native_poseidon.py [--output PATH] [--cc COMPILER]

Compiles ``src/registry/_poseidon_native.c`` into a platform shared library
placed next to ``src/registry/poseidon.py`` by default (or to ``--output``).
Zero external dependencies beyond a C compiler supporting ``unsigned __int128``
(GCC or Clang on 64-bit platforms).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = PROJECT_ROOT / "src" / "registry" / "_poseidon_native.c"


def default_library_name() -> str:
    if sys.platform == "darwin":
        return "_poseidon_native.dylib"
    if sys.platform == "win32":
        return "_poseidon_native.dll"
    return "_poseidon_native.so"


def default_output_path() -> Path:
    return PROJECT_ROOT / "src" / "registry" / default_library_name()


def select_compiler(explicit: str | None = None) -> str:
    if explicit:
        resolved = shutil.which(explicit)
        if not resolved:
            raise RuntimeError(f"Requested C compiler not found: {explicit}")
        return resolved
    for candidate in (os.getenv("CC"), "cc", "gcc", "clang"):
        if candidate:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
    raise RuntimeError("No C compiler (cc/gcc/clang) found on PATH")


def build_native_poseidon(
    *,
    source: Path = SOURCE_PATH,
    output: Path | None = None,
    compiler: str | None = None,
) -> Path:
    out_path = output if output is not None else default_output_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cc = select_compiler(compiler)
    shared_flag = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    cmd = [
        cc,
        "-O3",
        "-fPIC",
        shared_flag,
        "-Wall",
        "-Wextra",
        "-Werror",
        "-o",
        str(out_path),
        str(source),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"Native Poseidon build failed ({cc}):\n{proc.stderr.strip()}")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the optional native Poseidon C shared library.")
    parser.add_argument("--output", type=Path, default=None, help="Output shared library path.")
    parser.add_argument("--cc", default=None, help="Explicit C compiler executable.")
    args = parser.parse_args(argv)
    out_path = build_native_poseidon(output=args.output, compiler=args.cc)
    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    print(f"Built {out_path} (sha256={digest})")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
