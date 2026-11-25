# SPDX-License-Identifier: Apache-2.0
"""
Poseidon hash over the BN254 scalar field with optional native C acceleration.

Drop-in replacement for the previous Node.js subprocess bridge
(``scripts/poseidon_hash.js`` + circomlibjs). Implements the standard
(reference) Poseidon permutation, so outputs match circomlib's in-circuit
``Poseidon(n)`` template bit-for-bit.

Round constants and MDS matrices in ``poseidon_constants.json`` are generated
clean-room by ``scripts/generate_poseidon_constants.py`` (Apache-2.0) from
the public Grain-LFSR parameter algorithm in the Poseidon paper
(https://eprint.iacr.org/2019/458.pdf). They are NOT vendored from
circomlibjs (GPL-3.0) — see ADR 0001 for the repository's no-GPL policy.
Regenerate/verify with:

    python scripts/generate_poseidon_constants.py --verify-only

Optional native acceleration (``_poseidon_native.c`` loaded via ``ctypes``):
- ``CLEARPROOF_POSEIDON_BACKEND`` selects the backend: ``"auto"`` (default),
  ``"native"`` (require native or raise ``PoseidonBackendError``), or
  ``"python"`` (always pure Python).
- ``CLEARPROOF_POSEIDON_LIB`` overrides the shared library path.
- In ``"auto"`` mode, only *load/initialization* failures fall back silently to
  pure Python. Runtime errors or self-test/hash mismatches never fall back
  silently and raise ``PoseidonIntegrityError``.

Parity with circomlibjs and between native/Python backends is enforced by
``tests/unit/test_poseidon.py``.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import sys
import threading
from functools import lru_cache
from pathlib import Path
from typing import Literal

__all__ = [
    "BLS12_381_SCALAR_FIELD",
    "BN254_SCALAR_FIELD",
    "PoseidonBackendError",
    "PoseidonIntegrityError",
    "PoseidonBackend",
    "configure_poseidon_backend",
    "get_active_poseidon_backend",
    "poseidon_hash",
    "poseidon_hash_bls12381",
    "poseidon_hash_python",
]

logger = logging.getLogger(__name__)

# BN254 (alt_bn128) scalar field order.
BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# BLS12-381 scalar field order (ADR 0002).
BLS12_381_SCALAR_FIELD = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

_CONSTANTS_PATH = os.path.join(os.path.dirname(__file__), "poseidon_constants.json")
_BLS12_381_CONSTANTS_PATH = os.path.join(os.path.dirname(__file__), "poseidon_constants_bls12381.json")

_N_ROUNDS_F = 8
_N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]

_P = BN254_SCALAR_FIELD

_EXPECTED_ABI_VERSION = 1

PoseidonBackend = Literal["auto", "native", "python"]
_VALID_BACKENDS: frozenset[str] = frozenset({"auto", "native", "python"})

# Reference self-test vector: Poseidon([0, 0]) over BN254 scalar field.
_SELF_TEST_INPUTS = [0, 0]
_SELF_TEST_EXPECTED = 14744269619966411208579211824598458697587494354926760081771325075741142829156


class PoseidonBackendError(RuntimeError):
    """Raised when an explicit backend selection or native library load fails."""


class PoseidonIntegrityError(RuntimeError):
    """Raised when the native accelerator fails a hash or parity check (never falls back)."""


class _NativePoseidonHandle:
    """Loaded and verified ctypes wrapper around ``_poseidon_native``."""

    def __init__(self, lib: ctypes.CDLL, path: str) -> None:
        self.path = path
        self._lib = lib
        self._abi_fn = lib.clearproof_poseidon_abi_version
        self._abi_fn.argtypes = []
        self._abi_fn.restype = ctypes.c_int

        abi = self._abi_fn()
        if abi != _EXPECTED_ABI_VERSION:
            raise PoseidonBackendError(
                f"Unsupported native Poseidon ABI version {abi}; expected {_EXPECTED_ABI_VERSION}"
            )

        self._load_fn = lib.clearproof_poseidon_load_constants
        self._load_fn.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self._load_fn.restype = ctypes.c_int

        self._hash_fn = lib.clearproof_poseidon_hash_cached
        self._hash_fn.argtypes = [
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_void_p,
        ]
        self._hash_fn.restype = ctypes.c_int

        self._load_all_constants()
        self._self_test()

    def _load_all_constants(self) -> None:
        consts = _load_constants()
        for idx, n_rounds_p in enumerate(_N_ROUNDS_P):
            t = idx + 2
            c_bytes = b"".join(v.to_bytes(32, "little") for v in consts["C"][idx])
            m_bytes = b"".join(v.to_bytes(32, "little") for row in consts["M"][idx] for v in row)
            rc = self._load_fn(t, _N_ROUNDS_F, n_rounds_p, c_bytes, m_bytes)
            if rc != 0:
                raise PoseidonIntegrityError(f"Native Poseidon failed to load constants for t={t} (rc={rc})")

    def _self_test(self) -> None:
        actual = self.hash_field_elements(_SELF_TEST_INPUTS)
        expected = _poseidon_hash_python_fields(_SELF_TEST_INPUTS)
        if actual != expected or actual != _SELF_TEST_EXPECTED:
            raise PoseidonIntegrityError(f"Native Poseidon self-test hash mismatch: got {actual}, expected {expected}")

    def hash_field_elements(self, field_inputs: list[int]) -> int:
        t = len(field_inputs) + 1
        in_bytes = b"".join(v.to_bytes(32, "little") for v in field_inputs)
        out_buf = (ctypes.c_uint8 * 32)()
        rc = self._hash_fn(t, in_bytes, out_buf)
        if rc != 0:
            raise PoseidonIntegrityError(f"Native Poseidon hash failed for t={t} (rc={rc})")
        result = int.from_bytes(bytes(out_buf), "little")
        if not 0 <= result < _P:
            raise PoseidonIntegrityError("Native Poseidon returned out-of-field value")
        return result


_BACKEND_LOCK = threading.RLock()
_CONFIGURED_MODE: PoseidonBackend | None = None
_CONFIGURED_LIB_PATH: str | None = None
_ACTIVE_NATIVE: _NativePoseidonHandle | None = None
_RESOLVED_KEY: tuple[str, str, str] | None = None


def _default_native_lib_path() -> str:
    if sys.platform == "darwin":
        filename = "_poseidon_native.dylib"
    elif sys.platform == "win32":
        filename = "_poseidon_native.dll"
    else:
        filename = "_poseidon_native.so"
    return str(Path(__file__).resolve().with_name(filename))


def _resolve_mode_and_path() -> tuple[str, str]:
    mode = _CONFIGURED_MODE if _CONFIGURED_MODE is not None else os.getenv("CLEARPROOF_POSEIDON_BACKEND", "auto")
    mode = mode.strip().lower()
    if mode not in _VALID_BACKENDS:
        raise PoseidonBackendError(
            f"Invalid CLEARPROOF_POSEIDON_BACKEND={mode!r}; expected one of 'auto', 'native', 'python'"
        )
    lib_path = (
        _CONFIGURED_LIB_PATH
        if _CONFIGURED_LIB_PATH is not None
        else os.getenv("CLEARPROOF_POSEIDON_LIB") or _default_native_lib_path()
    )
    return mode, lib_path


def _load_native_library(lib_path: str) -> _NativePoseidonHandle:
    try:
        lib = ctypes.CDLL(lib_path)
    except OSError as exc:
        raise PoseidonBackendError(f"Unable to load native Poseidon library at {lib_path}: {exc}") from exc
    try:
        return _NativePoseidonHandle(lib, lib_path)
    except AttributeError as exc:
        raise PoseidonBackendError(f"Native Poseidon library at {lib_path} is missing required ABI symbols") from exc


def _resolve_native_handle() -> _NativePoseidonHandle | None:
    global _ACTIVE_NATIVE, _RESOLVED_KEY
    mode, lib_path = _resolve_mode_and_path()
    key = (mode, lib_path, _CONSTANTS_PATH)
    with _BACKEND_LOCK:
        if _RESOLVED_KEY == key:
            return _ACTIVE_NATIVE
        if mode == "python":
            _ACTIVE_NATIVE = None
            _RESOLVED_KEY = key
            return None
        try:
            handle = _load_native_library(lib_path)
        except PoseidonBackendError:
            if mode == "native":
                raise
            logger.debug("Native Poseidon library unavailable at %s; falling back to pure Python", lib_path)
            _ACTIVE_NATIVE = None
            _RESOLVED_KEY = key
            return None
        _ACTIVE_NATIVE = handle
        _RESOLVED_KEY = key
        return handle


def configure_poseidon_backend(backend: PoseidonBackend | None = None, *, lib_path: str | None = None) -> str:
    """Programmatically select the Poseidon backend (``'auto'``, ``'native'``, ``'python'``, or ``None`` for env).

    Returns the resolved active backend name (``'native'`` or ``'python'``).
    Raises ``PoseidonBackendError`` on invalid backend or missing library in ``'native'`` mode,
    and ``PoseidonIntegrityError`` if the native library fails self-test/constant loading.
    """
    global _CONFIGURED_MODE, _CONFIGURED_LIB_PATH, _ACTIVE_NATIVE, _RESOLVED_KEY
    if backend is not None and (not isinstance(backend, str) or backend.strip().lower() not in _VALID_BACKENDS):
        raise PoseidonBackendError(f"Invalid Poseidon backend {backend!r}; expected 'auto', 'native', or 'python'")
    with _BACKEND_LOCK:
        _CONFIGURED_MODE = backend.strip().lower() if backend is not None else None  # type: ignore[assignment]
        _CONFIGURED_LIB_PATH = lib_path
        _ACTIVE_NATIVE = None
        _RESOLVED_KEY = None
        handle = _resolve_native_handle()
    return "native" if handle is not None else "python"


def get_active_poseidon_backend() -> Literal["native", "python"]:
    """Return which Poseidon implementation is currently active (``'native'`` or ``'python'``)."""
    return "native" if _resolve_native_handle() is not None else "python"


def _parse_constants(path: str) -> dict[str, list]:
    with open(path) as f:
        raw = json.load(f)

    def to_int(v: str | int) -> int:
        if isinstance(v, int):
            return v
        return int(v, 16) if v.startswith("0x") else int(v)

    return {
        "C": [[to_int(x) for x in row] for row in raw["C"]],
        "M": [[[to_int(x) for x in row] for row in mat] for mat in raw["M"]],
    }


@lru_cache(maxsize=1)
def _load_constants() -> dict[str, list]:
    """Load and pre-parse the BN254 round constants (cached process-wide)."""
    return _parse_constants(_CONSTANTS_PATH)


@lru_cache(maxsize=1)
def _load_bls12381_constants() -> dict[str, list]:
    """Load and pre-parse the BLS12-381 round constants (cached process-wide)."""
    return _parse_constants(_BLS12_381_CONSTANTS_PATH)


def _pow5(a: int, prime: int) -> int:
    a2 = a * a % prime
    return a2 * a2 % prime * a % prime


def _normalize_inputs(inputs: list[int | str], *, prime: int = _P) -> list[int]:
    if not inputs:
        raise ValueError("Poseidon requires at least 1 input")
    if len(inputs) > len(_N_ROUNDS_P):
        raise ValueError(f"Poseidon supports at most {len(_N_ROUNDS_P)} inputs, got {len(inputs)}")

    def to_field(v: int | str) -> int:
        if isinstance(v, str):
            return (int(v, 16) if v.startswith("0x") else int(v)) % prime
        return int(v) % prime

    return [to_field(v) for v in inputs]


def _poseidon_permutation_fields(field_inputs: list[int], *, prime: int, consts: dict[str, list]) -> int:
    t = len(field_inputs) + 1
    idx = t - 2
    n_rounds_f = _N_ROUNDS_F
    n_rounds_p = _N_ROUNDS_P[idx]
    C = consts["C"][idx]
    M = consts["M"][idx]

    state = [0] + field_inputs

    half_f = n_rounds_f // 2
    for r in range(n_rounds_f + n_rounds_p):
        base = r * t
        state = [(a + C[base + i]) % prime for i, a in enumerate(state)]
        if r < half_f or r >= half_f + n_rounds_p:
            state = [_pow5(a, prime) for a in state]
        else:
            state[0] = _pow5(state[0], prime)
        state = [sum(M[i][j] * state[j] for j in range(t)) % prime for i in range(t)]

    return state[0]


def _poseidon_hash_python_fields(field_inputs: list[int]) -> int:
    return _poseidon_permutation_fields(field_inputs, prime=_P, consts=_load_constants())


def poseidon_hash_python(inputs: list[int | str]) -> int:
    """Compute Poseidon(inputs) strictly using the pure-Python reference implementation."""
    return _poseidon_hash_python_fields(_normalize_inputs(inputs))


def poseidon_hash(inputs: list[int | str]) -> int:
    """
    Compute Poseidon(inputs) over the BN254 scalar field.

    Uses the optional native C accelerator when built and enabled; falls back to
    pure Python only when the native library cannot be loaded in ``auto`` mode.
    Matches circomlib's in-circuit ``Poseidon(len(inputs))`` template (and
    therefore circomlibjs) bit-for-bit.

    Args:
        inputs: 1 to 16 field elements as ints or decimal/hex strings.
            Values are reduced mod the BN254 scalar field order.

    Returns:
        The hash as an integer (state[0] after the permutation).

    Raises:
        ValueError: If inputs are empty or exceed 16 elements.
        PoseidonBackendError: If backend configuration is invalid or ``native``
            mode is selected while the shared library cannot be loaded.
        PoseidonIntegrityError: If the loaded native accelerator returns an
            error, out-of-field value, or fails self-test parity.
    """
    field_inputs = _normalize_inputs(inputs)
    native = _resolve_native_handle()
    if native is not None:
        return native.hash_field_elements(field_inputs)
    return _poseidon_hash_python_fields(field_inputs)


def poseidon_hash_bls12381(inputs: list[int | str]) -> int:
    """
    Compute Poseidon(inputs) over the BLS12-381 scalar field (ADR 0002 task 3).

    Uses curve-correct Grain-LFSR round constants and Cauchy MDS matrices
    generated directly for BLS12-381 r (255 bits) and matches the in-circuit
    ``PoseidonBls(len(inputs))`` template bit-for-bit. Always evaluates in
    pure Python (the native C accelerator is BN254-only).
    """
    field_inputs = _normalize_inputs(inputs, prime=BLS12_381_SCALAR_FIELD)
    return _poseidon_permutation_fields(field_inputs, prime=BLS12_381_SCALAR_FIELD, consts=_load_bls12381_constants())
