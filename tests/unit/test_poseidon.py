"""
Parity tests for the native Python Poseidon implementation.

The hardcoded vectors below were generated with circomlibjs
(``scripts/poseidon_hash.js``) and must match ``src/registry/poseidon.py``
exactly — this is what guarantees Python-computed Merkle roots and credential
commitments remain consistent with the in-circuit Poseidon template.

An optional live-parity test re-checks against circomlibjs when Node.js and
circomlibjs are available; it skips otherwise. A regeneration test verifies
the committed constants file matches the clean-room generator output.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.registry.poseidon import BN254_SCALAR_FIELD, poseidon_hash

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


@pytest.mark.parametrize("inputs,expected", VECTORS)
def test_poseidon_matches_circomlibjs_vectors(inputs: list[int], expected: int) -> None:
    assert poseidon_hash(inputs) == expected


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
