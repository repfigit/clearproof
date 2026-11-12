"""Run the Bash lint entry point in an isolated tree with controlled analyzer results."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/circuit_lint.sh"
CIRCUITS = [
    "wallet_ownership_credential",
    "compliance",
    "sanctions_nonmembership",
    "credential_validity",
    "amount_tier",
    "merkle_tree",
    "poseidon_hasher",
    "pilot_compliance",
    "pilot_transfer",
    "pilot_credential",
    "pilot_sanctions",
    "pilot_valuation",
    "pilot_constants",
    "pilot_main",
]
LESS_THAN = "Inputs to `LessThan` need to be constrained to ensure that they are non-negative"
NUM2BITS = "Using `Num2Bits` to convert field elements to bits may lead to aliasing issues."
HINT = "Using the signal assignment operator `<--` does not constrain the assigned signal."
# Reviewed false positives in the current-profile circuits, by file and exact count.
COUNTED = {
    "pilot_compliance": [LESS_THAN],
    "pilot_transfer": [LESS_THAN, LESS_THAN, NUM2BITS],
    "pilot_valuation": [LESS_THAN] * 3 + [HINT] * 7,
}
COUNTED_TOTAL = sum(len(messages) for messages in COUNTED.values())
ALLOWED = [
    "signal `domain_chain_id` is not used by the template",
    "signal `domain_contract_hash` is not used by the template",
    "signal `is_compliant` is not constrained by the template",
    "output signal `valid` defined by the template `SanctionsNonMembership` is not constrained in `ComplianceProof`",
    "signal `valid` is not constrained by the template",
]


@pytest.fixture
def lint_tree(tmp_path):
    root = tmp_path / "project"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(SCRIPT, root / "scripts/circuit_lint.sh")
    commands = tmp_path / "bin"
    commands.mkdir()
    for name in ["dirname", "mktemp", "rm", "grep", "mv", "cat", "basename"]:
        (commands / name).symlink_to(shutil.which(name))
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    env = {**os.environ, "PATH": str(commands), "TMPDIR": str(temporary)}

    def run(output="", code=0, sarif=False, installed=True, counted=COUNTED):
        """Every file prints ``output``; ``counted`` adds per-file warnings (exit 1 for those files)."""
        if installed:
            per_file = {stem: "\n".join(f"warning: {m}" for m in messages) for stem, messages in counted.items()}
            analyzer = commands / "circomspect"
            analyzer.write_text(
                f"#!{sys.executable}\n"
                "import json, pathlib, sys\n"
                "with open('calls.jsonl', 'a') as log: log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "if '--sarif-file' in sys.argv:\n"
                '    pathlib.Path(sys.argv[-1]).write_text(\'{"version":"2.1.0"}\')\n'
                f"extra = {per_file!r}.get(pathlib.Path(sys.argv[1]).stem, '')\n"
                f"print({output!r})\n"
                "print(extra)\n"
                f"sys.exit({code} or (1 if extra else 0))\n"
            )
            analyzer.chmod(0o755)
        result = subprocess.run(
            ["/bin/bash", str(root / "scripts/circuit_lint.sh"), *(["--sarif"] if sarif else [])],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert list(temporary.iterdir()) == [], "lint must remove its temporary files on every exit"
        return result

    return root, run


@pytest.mark.parametrize("sarif", [False, True])
def test_lint_runs_every_circuit_and_emits_requested_reports(lint_tree, sarif):
    root, run = lint_tree
    result = run(sarif=sarif)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"{COUNTED_TOTAL} finding(s), {COUNTED_TOTAL} allowlisted, 0 unexpected" in result.stdout
    calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
    assert [Path(call[0]).stem for call in calls] == CIRCUITS
    assert all(len(call) == (3 if sarif else 1) for call in calls)
    assert sorted(path.stem for path in root.glob("*.sarif")) == (sorted(CIRCUITS) if sarif else [])


def test_lint_accepts_only_documented_findings_even_when_analyzer_returns_one(lint_tree):
    _, run = lint_tree
    result = run("\n".join(f"warning: {message}" for message in ALLOWED), code=1)
    assert result.returncode == 0
    documented = len(ALLOWED) * len(CIRCUITS) + COUNTED_TOTAL
    assert f"{documented} finding(s), {documented} allowlisted, 0 unexpected" in result.stdout


@pytest.mark.parametrize("diagnostic", ["warning: unconstrained secret", "error: cannot parse circuit"])
def test_lint_rejects_unexpected_diagnostics(lint_tree, diagnostic):
    _, run = lint_tree
    result = run(diagnostic, code=1)
    assert result.returncode == 1
    assert f"{len(CIRCUITS)} unexpected" in result.stdout
    assert diagnostic in result.stdout
    assert "Full output:" in result.stdout


@pytest.mark.parametrize("code,output", [(1, ""), (2, ""), (137, "analyzer terminated"), (2, "warning: " + ALLOWED[0])])
def test_lint_fails_closed_when_analyzer_does_not_complete(lint_tree, code, output):
    _, run = lint_tree
    result = run(output, code=code)
    assert result.returncode == 1
    assert f"circomspect exited with status {code}" in result.stdout


def test_lint_reports_missing_analyzer(lint_tree):
    root, run = lint_tree
    result = run(installed=False)
    assert result.returncode == 127
    assert "circomspect not found" in result.stderr
    assert not (root / "calls.jsonl").exists()


def test_current_profile_circuits_are_analyzed():
    """The gate must cover every Circom file of the current profile, including generated ones."""
    root = SCRIPT.parents[1]
    listed = {line.strip() for line in SCRIPT.read_text().splitlines() if line.strip().endswith(".circom")}
    on_disk = {str(path.relative_to(root)) for path in (root / "circuits").rglob("*.circom")}
    assert on_disk <= listed, sorted(on_disk - listed)


@pytest.mark.parametrize(
    "stem,messages,expected,found",
    [
        # A new instance of an already reviewed warning type is not covered by the allowlist.
        ("pilot_valuation", [LESS_THAN] * 4 + [HINT] * 7, 3, 4),
        # A reviewed finding that disappears means the allowlist is stale.
        ("pilot_transfer", [LESS_THAN, NUM2BITS], 2, 1),
        ("pilot_compliance", [], 1, 0),
    ],
)
def test_counted_allowlist_requires_the_exact_reviewed_count(lint_tree, stem, messages, expected, found):
    _, run = lint_tree
    result = run(counted={**COUNTED, stem: messages})
    assert result.returncode == 1
    assert f"circuits/{stem}.circom: allowlist expects {expected} finding(s)" in result.stdout
    assert f"found {found}" in result.stdout


def test_counted_findings_are_not_allowed_in_other_files(lint_tree):
    """The reviewed warning types stay unexpected anywhere they were not reviewed."""
    _, run = lint_tree
    result = run(counted={**COUNTED, "compliance": [LESS_THAN], "pilot_sanctions": [HINT]})
    assert result.returncode == 1
    assert "2 unexpected" in result.stdout
    assert LESS_THAN in result.stdout and HINT in result.stdout
