"""Static cross-layer check of the pilot-transfer-v3 public-signal contract.

The circuit, spec, Python prover, tree depths, TypeScript SDK and registry contract must agree on
signal order, tree depths and the indices each layer reads. This test parses source text only; it
never compiles circuits or contracts.
"""

import re
from pathlib import Path

from src.prover.pilot_compliance import PROFILE, PUBLIC_SIGNALS
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, ISSUER_TREE_DEPTH, SANCTIONS_TREE_DEPTH

ROOT = Path(__file__).resolve().parents[2]
CIRCUIT = ROOT / "circuits" / "pilot_compliance.circom"
SPEC = ROOT / "specs" / "pilot-transfer-v3.md"
AUTHORIZATION_TS = ROOT / "packages" / "proof" / "src" / "authorization.ts"
REGISTRY_SOL = ROOT / "packages" / "contracts" / "contracts" / "PilotCurrentRegistry.sol"

EXPECTED_DEPTHS = (ISSUANCE_TREE_DEPTH, ISSUER_TREE_DEPTH, SANCTIONS_TREE_DEPTH)


def _strip_c_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", source)


def _circuit_main() -> tuple[tuple[str, ...], tuple[int, ...]]:
    source = _strip_c_comments(CIRCUIT.read_text())
    match = re.search(
        r"component\s+main\s*\{\s*public\s*\[(?P<signals>[^\]]*)\]\s*\}\s*=\s*PilotCompliance\s*\((?P<args>[^)]*)\)",
        source,
    )
    assert match, "component main {public [...]} = PilotCompliance(...) not found"
    signals = tuple(s.strip() for s in match["signals"].split(",") if s.strip())
    args = tuple(int(a.strip()) for a in match["args"].split(","))
    return signals, args


def _spec_signal_table() -> tuple[str, ...]:
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`?([a-z_]+)`?\s*\|", SPEC.read_text(), flags=re.M)
    assert rows, "public-signal index table not found in spec"
    indices = [int(i) for i, _ in rows]
    assert indices == list(range(len(rows))), f"spec signal indices are not 0..n-1: {indices}"
    return tuple(name for _, name in rows)


def test_profile_name_matches_spec():
    assert PROFILE == "pilot-transfer-v3"
    assert SPEC.read_text().startswith(f"# {PROFILE} ")


def test_circuit_public_signals_match_python():
    signals, _ = _circuit_main()
    assert signals == PUBLIC_SIGNALS
    assert len(signals) == 8


def test_spec_signal_table_matches_python():
    assert _spec_signal_table() == PUBLIC_SIGNALS


def test_circuit_tree_depths_match_registry_constants():
    _, args = _circuit_main()
    assert args == EXPECTED_DEPTHS


def test_spec_names_same_instantiation_and_depths():
    text = SPEC.read_text()
    a, b, c = EXPECTED_DEPTHS
    assert re.search(rf"PilotCompliance\(\s*{a}\s*,\s*{b}\s*,\s*{c}\s*\)", text)
    assert re.search(rf"`issuance-root`\s+{a}\b", text)
    assert re.search(rf"`issuer-root`\s+{b}\b", text)
    assert re.search(rf"`sanctions-root`\s+{c}\b", text)


def _ts_reads_index(source: str, index: int, keywords: tuple[str, ...]) -> bool:
    """True if `signals[<index>]` appears, or a constant assigned <index> (named after a keyword) indexes signals."""
    if re.search(rf"\bsignals\s*\[\s*{index}\s*\]", source):
        return True
    for name, value in re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*\w+)?\s*=\s*(\d+)\b", source):
        if int(value) == index and any(k in name.lower() for k in keywords):
            if re.search(rf"\bsignals\s*\[\s*{re.escape(name)}\s*\]", source):
                return True
    return False


def test_sdk_authorization_reads_nullifier_and_expiry_indices():
    source = _strip_c_comments(AUTHORIZATION_TS.read_text())
    assert PUBLIC_SIGNALS[3] == "authorization_nullifier"
    assert PUBLIC_SIGNALS[5] == "proof_expires_at"
    assert _ts_reads_index(source, 3, ("nullifier",)), "authorization.ts must read the nullifier at index 3"
    assert _ts_reads_index(source, 5, ("expir", "expires")), "authorization.ts must read expiry at index 5"


def test_registry_checks_domain_signals_against_deployment():
    source = _strip_c_comments(REGISTRY_SOL.read_text())
    assert PUBLIC_SIGNALS[6] == "domain_chain_id"
    assert PUBLIC_SIGNALS[7] == "domain_registry"
    assert re.search(r"signals\s*\[\s*6\s*\]\s*!=\s*block\.chainid", source), "registry must bind signal 6 to chainid"
    assert re.search(r"signals\s*\[\s*7\s*\]\s*!=\s*uint160\s*\(\s*address\s*\(\s*this\s*\)\s*\)", source), (
        "registry must bind signal 7 to address(this)"
    )
