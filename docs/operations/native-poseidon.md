# Optional Native Poseidon Accelerator

`src/registry/poseidon.py` implements the BN254 scalar-field Poseidon permutation
matching `circuits/` (`circomlib` `Poseidon(n)`) bit-for-bit. By default it runs
in pure Python (~190 µs per 2-input hash) and transparently uses an optional C
shared library (`src/registry/_poseidon_native.c`, loaded via `ctypes`) when
built (~11 µs per 2-input hash, ~15–20× speedup).

The C library carries **no hardcoded round constants or MDS matrices**: Python
loads `src/registry/poseidon_constants.json` once and pushes all 16 arity tables
(`t = 2..17`, `n_rounds_f = 8`, `n_rounds_p = [56..68]`) into the shared library
at initialization, ensuring the exact same field modulus and round parameters as
pure Python and the circuits.

## Build & Install

Prerequisites: a 64-bit C compiler supporting `unsigned __int128` (`gcc` or
`clang`). No third-party C libraries or headers beyond the C standard library
are required.

```bash
# Build next to src/registry/poseidon.py (Linux: _poseidon_native.so, macOS: .dylib)
make build-native-poseidon

# Or invoke the build helper directly with custom compiler / output path:
uv run python scripts/build_native_poseidon.py --cc gcc --output /opt/clearproof/_poseidon_native.so
```

The compiled binary is git-ignored (`src/registry/_poseidon_native.{so,dylib,dll}`).
Re-run `make build-native-poseidon` after upgrading Clearproof or switching host
architectures.

## Runtime Configuration

Select or inspect the backend via environment variables or Python API:

| Variable / API | Values | Default | Behavior |
| --- | --- | --- | --- |
| `CLEARPROOF_POSEIDON_BACKEND` | `auto`, `native`, `python` | `auto` | `auto` uses native if loadable, else pure Python; `native` requires the native library and fails closed if missing/unloadable; `python` forces pure Python |
| `CLEARPROOF_POSEIDON_LIB` | Filesystem path | `src/registry/_poseidon_native.{so,dylib,dll}` | Override shared library path |
| `configure_poseidon_backend(backend, lib_path=...)` | `"auto"`, `"native"`, `"python"`, or `None` (revert to env) | — | Programmatically switch backend and return `"native"` or `"python"` |
| `get_active_poseidon_backend()` | — | — | Returns `"native"` or `"python"` |
| `poseidon_hash_python(inputs)` | — | — | Always executes the pure-Python reference implementation |

## Failure Modes & Fail-Closed Guarantees

Silent fallback to pure Python occurs **only** on library load or ABI discovery
failure in `auto` mode — **never** on a hash or parity mismatch:

1. **Missing / unloadable shared library or missing ABI symbols / ABI version mismatch**:
   - `CLEARPROOF_POSEIDON_BACKEND=auto`: logs at `DEBUG` level and falls back
     to pure Python (`get_active_poseidon_backend() == "python"`).
   - `CLEARPROOF_POSEIDON_BACKEND=native`: raises `PoseidonBackendError` (fail-closed).
2. **Invalid `CLEARPROOF_POSEIDON_BACKEND` value**:
   - Always raises `PoseidonBackendError` (never silently falls back).
3. **Constant loading error or startup self-test hash mismatch**:
   - Immediately after loading constants into the shared library, Python runs a
     self-test (`Poseidon([0, 0])`) and compares the native output against both
     pure Python and the pinned reference scalar.
   - Any mismatch or non-zero return code raises `PoseidonIntegrityError` in
     **every** mode (including `auto`) — it does **not** fall back to pure Python.
4. **Runtime native error or out-of-field return value (`>= BN254_SCALAR_FIELD`)**:
   - Always raises `PoseidonIntegrityError` (never falls back).

## Parity Verification

Run the differential, boundary, incremental-tree, and fallback test suites:

```bash
make build-native-poseidon
uv run python -m pytest tests/unit/test_poseidon.py tests/unit/test_pilot_tree.py -v

# With PostgreSQL (includes incremental Merkle tree parity with native on vs off):
DATABASE_URL="postgresql:///clearproof_merkle_test" uv run python -m pytest \
  tests/integration/test_incremental_merkle.py -v
```
