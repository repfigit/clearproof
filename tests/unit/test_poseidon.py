# SPDX-License-Identifier: Apache-2.0
"""
Parity and backend tests for Poseidon over the BN254 scalar field.

Covers:
- Hardcoded circomlibjs reference vectors (both pure-Python and native C backends)
- Clean-room constant generator parity and live circomlibjs parity (when Node is present)
- Differential tests (native C vs pure Python) over randomized vectors across all 16 arities
- Boundary BN254 field values (0, 1, p-1, p, p+1, 2p-1, negatives, 256-bit limbs, strings)
- PilotTree and incremental Merkle root parity with native accelerator on vs off
- Backend selection via env/config, load-failure fallback in auto mode, fail-closed
  behavior in native mode, and strict non-fallback (PoseidonIntegrityError) on hash mismatch
- Native build script helpers (scripts/build_native_poseidon.py)
"""

from __future__ import annotations

import ctypes
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import build_native_poseidon as build_script
from src.registry import poseidon as poseidon_module
from src.registry.pilot_tree import PilotTree, zero_root
from src.registry.poseidon import (
    BLS12_381_SCALAR_FIELD,
    BN254_SCALAR_FIELD,
    PoseidonBackendError,
    PoseidonIntegrityError,
    configure_poseidon_backend,
    get_active_poseidon_backend,
    poseidon_hash,
    poseidon_hash_bls12381,
    poseidon_hash_python,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
POSEIDON_SCRIPT = PROJECT_ROOT / "scripts" / "poseidon_hash.js"

# Vectors generated from circomlibjs (poseidon_opt) — do not edit by hand.
# Format: (inputs, expected_output_decimal)
VECTORS: list[tuple[list[int], int]] = [
    (
        [1824594520431655756314206505944531951095131398463257683850144663647063373968],
        17531793832730715075588909366742401781301573028003367552355447868851876210619,
    ),
    (
        [
            15954495723346797708155040157893119970869747214614083462679913151950463946938,
            18983860653883032978028599107465065594857087560896838017056078653818634119630,
        ],
        18971926833837541205317878484336545182402251893385180489922335220846059269835,
    ),
    (
        [
            10912248324753127637078463290580841440536130442217506919694057826247698075863,
            16183215590968758484462576616390573628596896504329330333393857066510874291165,
            6424731962263663284338216923520407066227776192546947621130017002951366184302,
        ],
        3649480351238459189051431477229575281930533472411795536096672673152365846024,
    ),
    (
        [
            13081413455465392244572342473333530436405251966015482383857986170025842136172,
            3102689035640273875588947273399379131239116588543567876133668789744104261721,
            14533599423273338331513258603178475417883917472549531954598567517026694707015,
            6452661720514107276253422314703869864935992227845660567096447206497489093622,
        ],
        13876375525744671113482548886699433543299590267849542148589905704662709516590,
    ),
    # Credential commitment shape: 6 inputs (t=7).
    (
        [11, 22, 33, 44, 55, 66],
        18849161228324411937765677913214915256561993401817509406111680516764733428140,
    ),
    # Sanctions leaf shape: Poseidon(1, address_int) — Tornado Cash 0x8589...A16
    (
        [1, int("8589427373D6D84E98730D7795D8f6f8731FDA16", 16)],
        10122561416306420548199625580112694722673102652569598575967888855013249288081,
    ),
    ([0, 0], 14744269619966411208579211824598458697587494354926760081771325075741142829156),
    # Field reduction: inputs >= p must reduce mod p before hashing.
    (
        [BN254_SCALAR_FIELD - 1, BN254_SCALAR_FIELD + 5],
        14461486180628612516994168498005650177472331051565513618915427233389242898569,
    ),
]


@pytest.fixture(scope="module")
def native_lib_path(tmp_path_factory) -> Path:
    """Compile the optional native C Poseidon library into an isolated temp path."""
    out_dir = tmp_path_factory.mktemp("native-poseidon")
    return build_script.build_native_poseidon(output=out_dir / build_script.default_library_name())


@pytest.fixture(autouse=True)
def _restore_poseidon_backend():
    """Ensure every test leaves the global Poseidon backend selection clean."""
    try:
        yield
    finally:
        configure_poseidon_backend(None, lib_path=None)
        zero_root.cache_clear()


@pytest.mark.parametrize("inputs,expected", VECTORS)
def test_poseidon_matches_circomlibjs_vectors(inputs: list[int], expected: int) -> None:
    assert poseidon_hash(inputs) == expected
    assert poseidon_hash_python(inputs) == expected


def test_poseidon_accepts_strings() -> None:
    """String inputs (decimal or hex) hash identically to int inputs."""
    inputs, expected = VECTORS[1]
    assert poseidon_hash([str(v) for v in inputs]) == expected
    assert poseidon_hash([hex(v) for v in inputs]) == expected


def test_poseidon_rejects_empty_and_oversized() -> None:
    with pytest.raises(ValueError):
        poseidon_hash([])
    with pytest.raises(ValueError):
        poseidon_hash([1] * 17)


def test_poseidon_deterministic_and_field_bound() -> None:
    h1 = poseidon_hash([123, 456])
    h2 = poseidon_hash([123, 456])
    assert h1 == h2
    assert 0 <= h1 < BN254_SCALAR_FIELD


def test_constants_match_cleanroom_generator() -> None:
    """The committed poseidon_constants.json must equal fresh generator output.

    Guards against hand-edits of the constants file and against drift between
    the generator and the shipped parameters.
    """
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "generate_poseidon_constants.py"), "--verify-only"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"constants regeneration mismatch:\n{proc.stdout}\n{proc.stderr}"


@pytest.mark.skipif(
    shutil.which("node") is None or not POSEIDON_SCRIPT.exists(),
    reason="Node.js / poseidon_hash.js not available",
)
def test_live_parity_with_circomlibjs() -> None:
    """Re-verify parity against circomlibjs directly (CI has Node installed)."""
    try:
        proc = subprocess.run(
            ["node", str(POSEIDON_SCRIPT)],
            input=json.dumps(["1", "2", "3"]),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"node execution failed: {exc}")
    if proc.returncode != 0:
        pytest.skip(f"circomlibjs unavailable: {proc.stderr.strip()}")
    assert poseidon_hash([1, 2, 3]) == int(proc.stdout.strip())


def test_numeric_constant_encoding_preserves_reference_vectors(tmp_path, monkeypatch):
    original = json.loads(Path(poseidon_module._CONSTANTS_PATH).read_text())

    def numeric(value):
        if isinstance(value, list):
            return [numeric(item) for item in value]
        return int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)

    converted = {name: numeric(original[name]) for name in ("C", "M")}
    path = tmp_path / "numeric-constants.json"
    path.write_text(json.dumps(converted))
    poseidon_module._load_constants.cache_clear()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(poseidon_module, "_CONSTANTS_PATH", str(path))
            configure_poseidon_backend("python")
            for values, expected in VECTORS:
                assert poseidon_module.poseidon_hash(values) == expected
    finally:
        poseidon_module._load_constants.cache_clear()
    assert poseidon_module.poseidon_hash(VECTORS[0][0]) == VECTORS[0][1]


def test_native_differential_randomized_vectors_all_arities(native_lib_path: Path) -> None:
    """Differential parity: native C vs pure Python across all 16 arities on randomized inputs."""
    assert configure_poseidon_backend("native", lib_path=str(native_lib_path)) == "native"
    assert get_active_poseidon_backend() == "native"

    rng = random.Random(20261125)
    for arity in range(1, 17):
        for _ in range(8):
            vec = [rng.randrange(0, BN254_SCALAR_FIELD) for _ in range(arity)]
            native_out = poseidon_hash(vec)
            python_out = poseidon_hash_python(vec)
            assert native_out == python_out
            assert 0 <= native_out < BN254_SCALAR_FIELD

    # Verify all hardcoded circomlibjs reference vectors with native enabled
    for vec, expected in VECTORS:
        assert poseidon_hash(vec) == expected
        assert poseidon_hash([hex(v) for v in vec]) == expected


def test_native_differential_boundary_field_values(native_lib_path: Path) -> None:
    """Differential parity over BN254 scalar field boundaries, limb edges, and modular reduction."""
    assert configure_poseidon_backend("native", lib_path=str(native_lib_path)) == "native"
    p = BN254_SCALAR_FIELD
    boundary_scalars = [
        0,
        1,
        2,
        2**64 - 1,
        2**64,
        2**128 - 1,
        2**128,
        2**192 - 1,
        2**192,
        2**253,
        p - 2,
        p - 1,
        p,
        p + 1,
        2 * p - 1,
        2 * p,
        2**256 - 1,
        -1,
        -p,
        -(p - 1),
    ]
    for a in boundary_scalars:
        assert poseidon_hash([a]) == poseidon_hash_python([a])
    for i in range(len(boundary_scalars)):
        a = boundary_scalars[i]
        b = boundary_scalars[(i * 7 + 3) % len(boundary_scalars)]
        assert poseidon_hash([a, b]) == poseidon_hash_python([a, b])
        assert poseidon_hash([str(a), hex(b) if b >= 0 else str(b)]) == poseidon_hash_python([a, b])

    # Also test the uncached C entry point directly against pure Python
    lib = ctypes.CDLL(str(native_lib_path))
    consts = poseidon_module._load_constants()
    c_bytes = b"".join(v.to_bytes(32, "little") for v in consts["C"][1])
    m_bytes = b"".join(v.to_bytes(32, "little") for row in consts["M"][1] for v in row)
    in_bytes = (p - 1).to_bytes(32, "little") + (1).to_bytes(32, "little")
    out_buf = (ctypes.c_uint8 * 32)()
    rc = lib.clearproof_poseidon_hash(
        3, poseidon_module._N_ROUNDS_F, poseidon_module._N_ROUNDS_P[1], in_bytes, c_bytes, m_bytes, out_buf
    )
    assert rc == 0
    assert int.from_bytes(bytes(out_buf), "little") == poseidon_hash_python([p - 1, 1])


def test_pilot_tree_roots_and_paths_identical_with_native_on_vs_off(native_lib_path: Path) -> None:
    """Merkle tree roots and membership paths are bit-exact with accelerator on vs off."""
    entries = [(f"{i:064x}", str((i * 997 + 13) % BN254_SCALAR_FIELD)) for i in range(1, 66)]

    configure_poseidon_backend("python")
    zero_root.cache_clear()
    tree_py = PilotTree(entries, depth=32)
    proofs_py = [tree_py.membership(entries[idx][0]) for idx in (0, 15, 31, 32, 64)]

    configure_poseidon_backend("native", lib_path=str(native_lib_path))
    zero_root.cache_clear()
    tree_native = PilotTree(entries, depth=32)
    proofs_native = [tree_native.membership(entries[idx][0]) for idx in (0, 15, 31, 32, 64)]

    assert tree_native.root == tree_py.root
    assert proofs_native == proofs_py


def test_env_and_config_backend_switching_and_load_fallback(
    native_lib_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Swappable via env/config; auto falls back ONLY on load failure; native fails closed."""
    missing = str(tmp_path / "does_not_exist.so")

    # Programmatic python mode
    assert configure_poseidon_backend("python") == "python"
    assert get_active_poseidon_backend() == "python"
    assert poseidon_hash([1, 2]) == poseidon_hash_python([1, 2])

    # Auto mode with missing library falls back silently to python
    assert configure_poseidon_backend("auto", lib_path=missing) == "python"
    assert get_active_poseidon_backend() == "python"
    assert poseidon_hash([1, 2]) == poseidon_hash_python([1, 2])

    # Native mode with missing library fails closed
    with pytest.raises(PoseidonBackendError, match="Unable to load native Poseidon library"):
        configure_poseidon_backend("native", lib_path=missing)

    # Env-driven selection (auto -> native, python -> python, native -> native)
    configure_poseidon_backend(None, lib_path=None)
    monkeypatch.setenv("CLEARPROOF_POSEIDON_LIB", str(native_lib_path))
    monkeypatch.setenv("CLEARPROOF_POSEIDON_BACKEND", "auto")
    assert get_active_poseidon_backend() == "native"
    assert poseidon_hash([42, 99]) == poseidon_hash_python([42, 99])

    monkeypatch.setenv("CLEARPROOF_POSEIDON_BACKEND", "python")
    assert get_active_poseidon_backend() == "python"
    assert poseidon_hash([42, 99]) == poseidon_hash_python([42, 99])

    monkeypatch.setenv("CLEARPROOF_POSEIDON_BACKEND", "native")
    assert get_active_poseidon_backend() == "native"

    # Invalid env backend fails closed
    monkeypatch.setenv("CLEARPROOF_POSEIDON_BACKEND", "bogus")
    with pytest.raises(PoseidonBackendError, match="Invalid CLEARPROOF_POSEIDON_BACKEND"):
        get_active_poseidon_backend()

    # Invalid programmatic backend fails closed
    with pytest.raises(PoseidonBackendError, match="Invalid Poseidon backend"):
        configure_poseidon_backend("invalid")  # type: ignore[arg-type]

    # Platform default filename resolution branches
    for plat, suffix in (("linux", ".so"), ("darwin", ".dylib"), ("win32", ".dll")):
        monkeypatch.setattr(poseidon_module.sys, "platform", plat)
        assert poseidon_module._default_native_lib_path().endswith(f"_poseidon_native{suffix}")


def test_native_failure_modes_never_fallback_on_hash_or_integrity_mismatch(
    native_lib_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ABI mismatch/missing symbols fall back in auto; hash/constant/runtime mismatches ALWAYS raise."""

    def _make_fake_lib(*, abi=1, load_rc=0, hash_rc=0, out_value=None, missing_symbol=False):
        if missing_symbol:
            return SimpleNamespace()

        def abi_fn():
            return abi

        def load_fn(t, rf, rp, c_b, m_b):
            return load_rc

        def hash_fn(t, in_b, out_buf):
            if hash_rc != 0:
                return hash_rc
            val = poseidon_module._SELF_TEST_EXPECTED if out_value is None else out_value
            raw = val.to_bytes(32, "little")
            ctypes.memmove(out_buf, raw, 32)
            return 0

        return SimpleNamespace(
            clearproof_poseidon_abi_version=abi_fn,
            clearproof_poseidon_load_constants=load_fn,
            clearproof_poseidon_hash_cached=hash_fn,
        )

    # 1. Missing symbols -> PoseidonBackendError -> auto falls back, native raises
    monkeypatch.setattr(poseidon_module.ctypes, "CDLL", lambda p: _make_fake_lib(missing_symbol=True))
    assert configure_poseidon_backend("auto", lib_path="/fake/missing-sym.so") == "python"
    with pytest.raises(PoseidonBackendError, match="missing required ABI symbols"):
        configure_poseidon_backend("native", lib_path="/fake/missing-sym.so")

    # 2. ABI mismatch -> PoseidonBackendError -> auto falls back, native raises
    monkeypatch.setattr(poseidon_module.ctypes, "CDLL", lambda p: _make_fake_lib(abi=99))
    assert configure_poseidon_backend("auto", lib_path="/fake/bad-abi.so") == "python"
    with pytest.raises(PoseidonBackendError, match="Unsupported native Poseidon ABI version 99"):
        configure_poseidon_backend("native", lib_path="/fake/bad-abi.so")

    # 3. Constant load failure -> PoseidonIntegrityError EVEN IN AUTO MODE (no silent fallback)
    monkeypatch.setattr(poseidon_module.ctypes, "CDLL", lambda p: _make_fake_lib(load_rc=-6))
    with pytest.raises(PoseidonIntegrityError, match="failed to load constants"):
        configure_poseidon_backend("auto", lib_path="/fake/bad-const.so")

    # 4. Self-test hash mismatch -> PoseidonIntegrityError EVEN IN AUTO MODE (no silent fallback)
    monkeypatch.setattr(poseidon_module.ctypes, "CDLL", lambda p: _make_fake_lib(out_value=12345))
    with pytest.raises(PoseidonIntegrityError, match="self-test hash mismatch"):
        configure_poseidon_backend("auto", lib_path="/fake/bad-hash.so")

    # 5. Runtime native error & out-of-field return value -> PoseidonIntegrityError (never falls back)
    monkeypatch.undo()
    assert configure_poseidon_backend("native", lib_path=str(native_lib_path)) == "native"
    handle = poseidon_module._resolve_native_handle()
    assert handle is not None

    with monkeypatch.context() as patch:
        patch.setattr(handle, "_hash_fn", lambda t, in_b, out_buf: -4)
        with pytest.raises(PoseidonIntegrityError, match="Native Poseidon hash failed"):
            poseidon_hash([1, 2])

    def _emit_out_of_field(t, in_b, out_buf):
        ctypes.memmove(out_buf, BN254_SCALAR_FIELD.to_bytes(32, "little"), 32)
        return 0

    with monkeypatch.context() as patch:
        patch.setattr(handle, "_hash_fn", _emit_out_of_field)
        with pytest.raises(PoseidonIntegrityError, match="out-of-field"):
            poseidon_hash([1, 2])


def test_build_native_poseidon_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """Exercise scripts/build_native_poseidon.py CLI, platform naming, and error paths."""
    out = tmp_path / "custom_poseidon.so"
    rc = build_script.main(["--output", str(out)])
    assert rc == 0 and out.is_file()
    assert "sha256=" in capsys.readouterr().out

    # Default output path & platform naming (restore sys.platform afterward)
    with monkeypatch.context() as patch:
        for plat, expected_name in (
            ("linux", "_poseidon_native.so"),
            ("darwin", "_poseidon_native.dylib"),
            ("win32", "_poseidon_native.dll"),
        ):
            patch.setattr(build_script.sys, "platform", plat)
            assert build_script.default_library_name() == expected_name
            assert build_script.default_output_path().name == expected_name

    # Missing explicit compiler
    with pytest.raises(RuntimeError, match="Requested C compiler not found"):
        build_script.select_compiler("nonexistent-compiler-xyz-12345")

    # Explicit valid compiler resolves
    assert build_script.select_compiler("cc") is not None

    # Auto-selection skips missing CC env var and finds fallback compiler
    with monkeypatch.context() as patch:
        patch.setenv("CC", "nonexistent-compiler-env-xyz")
        assert build_script.select_compiler() is not None

    # No compiler on PATH
    with monkeypatch.context() as patch:
        patch.delenv("CC", raising=False)
        patch.setattr(build_script.shutil, "which", lambda name: None)
        with pytest.raises(RuntimeError, match="No C compiler"):
            build_script.select_compiler()

    # Compiler invocation failure raises RuntimeError
    bad_src = tmp_path / "broken.c"
    bad_src.write_text("this is not valid C syntax ;;;")
    with pytest.raises(RuntimeError, match="Native Poseidon build failed"):
        build_script.build_native_poseidon(source=bad_src, output=tmp_path / "broken.so")

    # Exercise CLI __main__ entry point via subprocess
    cli_out = tmp_path / "cli_poseidon.so"
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "build_native_poseidon.py"), "--output", str(cli_out)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0 and cli_out.is_file() and "sha256=" in proc.stdout


# Known-answer vectors for curve-correct BLS12-381 Poseidon (ADR 0002 task 3),
# verified against compiled Circom PoseidonBls(n) (--prime bls12381).
BLS12_381_VECTORS: list[tuple[list[int], int]] = [
    (
        [0, 0],
        39704413365395714732902920194612999065094381874203236779011164022408220537174,
    ),
    (
        [1, 2],
        18456658763349757341014058622209659766100673761449600566550821987295786346378,
    ),
    (
        [1, 2, 3],
        41091099622722973056082071867846799679887891223501702244297781245659866568853,
    ),
    (
        [204, 11, 22, 33],
        49264448164909394063443318819423742571068542411188447188706153570671675683814,
    ),
    (
        [111, 12345, 67890, 1200, 87600, 1],
        46452670317930163960339998452000309255733502327112562796345186473617373585116,
    ),
    (
        [201, 1, 2, 3, 4, 5, 6, 7, 8],
        12926200779156670433811275351835833735505950207777825141738713560434141610891,
    ),
    (
        [102, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        35094980855324609566572852488257070130035405744181374746571045160406227180351,
    ),
    (
        [BLS12_381_SCALAR_FIELD - 1, BLS12_381_SCALAR_FIELD + 5],
        10294520724728164521974710211175144946335862078518536969276353479490757112503,
    ),
]


@pytest.mark.parametrize("inputs,expected", BLS12_381_VECTORS)
def test_poseidon_bls12381_known_answer_vectors(inputs: list[int], expected: int) -> None:
    digest = poseidon_hash_bls12381(inputs)
    assert digest == expected
    assert 0 <= digest < BLS12_381_SCALAR_FIELD
    # Must differ from BN254 Poseidon (curve-bound round constants).
    assert digest != poseidon_hash(inputs)


def test_poseidon_bls12381_independent_of_native_bn254_backend(native_lib_path: Path) -> None:
    """BLS12-381 hashing stays curve-correct and unaffected when the BN254 native backend is active."""
    assert configure_poseidon_backend("native", lib_path=str(native_lib_path)) == "native"
    for inputs, expected in BLS12_381_VECTORS:
        assert poseidon_hash_bls12381(inputs) == expected


def test_poseidon_bls12381_constants_match_cleanroom_generator() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "generate_poseidon_constants.py"),
            "--curve",
            "bls12-381",
            "--emit-circom",
            "--verify-only",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"BLS12-381 constants mismatch:\n{proc.stdout}\n{proc.stderr}"


@pytest.mark.skipif(
    shutil.which("circom") is None or shutil.which("node") is None,
    reason="Circom and Node.js required for in-circuit BLS12-381 Poseidon parity",
)
@pytest.mark.parametrize(
    "sample",
    [
        [1, 2],
        [204, 11, 22, 33],
        [111, 12345, 67890, 1200, 87600, 1],
        [201, 1, 2, 3, 4, 5, 6, 7, 8],
        [102, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    ],
)
def test_poseidon_bls12381_circom_witness_parity(tmp_path: Path, sample: list[int]) -> None:
    """In-circuit PoseidonBls(n) compiled with --prime bls12381 matches Python bit-for-bit."""
    arity = len(sample)
    expected = poseidon_hash_bls12381(sample)
    probe = tmp_path / f"probe_{arity}.circom"
    probe.write_text(
        f'pragma circom 2.1.6;\ninclude "{PROJECT_ROOT}/circuits/lib/poseidon_bls12381.circom";\n'
        f"template Probe() {{\n"
        f"    signal input inputs[{arity}];\n"
        f"    signal input expected;\n"
        f"    component h = PoseidonBls({arity});\n"
        f"    for (var i = 0; i < {arity}; i++) {{ h.inputs[i] <== inputs[i]; }}\n"
        f"    h.out === expected;\n"
        f"}}\n"
        f"component main {{public [expected]}} = Probe();\n"
    )
    comp = subprocess.run(
        ["circom", str(probe), "--prime", "bls12381", "--wasm", "--r1cs", "-o", str(tmp_path)],
        capture_output=True,
        timeout=120,
    )
    assert comp.returncode == 0, comp.stderr.decode()
    js_dir = tmp_path / f"probe_{arity}_js"
    valid_input = tmp_path / "valid.json"
    valid_input.write_text(json.dumps({"inputs": [str(x) for x in sample], "expected": str(expected)}))
    ok = subprocess.run(
        [
            "node",
            str(js_dir / "generate_witness.js"),
            str(js_dir / f"probe_{arity}.wasm"),
            str(valid_input),
            str(tmp_path / "valid.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )
    assert ok.returncode == 0, ok.stderr.decode()

    wrong_input = tmp_path / "wrong.json"
    wrong_input.write_text(
        json.dumps({"inputs": [str(x) for x in sample], "expected": str((expected + 1) % BLS12_381_SCALAR_FIELD)})
    )
    bad = subprocess.run(
        [
            "node",
            str(js_dir / "generate_witness.js"),
            str(js_dir / f"probe_{arity}.wasm"),
            str(wrong_input),
            str(tmp_path / "wrong.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )
    assert bad.returncode != 0 and b"Assert Failed" in bad.stderr
