"""Execute build-shell control flow with synthetic artifacts and no ceremony/network."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = [
    "artifacts/compliance.r1cs", "artifacts/compliance.sym", "artifacts/compliance_js/compliance.wasm",
    "artifacts/compliance_final.zkey", "artifacts/verification_key.json",
    "packages/contracts/contracts/Groth16Verifier.sol",
]
PIN = "e970efa7774da80101e0ac336d083ef3339855c98112539338d706b2b89ac694"
TOOL = r'''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open('commands.jsonl', 'a') as log: log.write(json.dumps([name, *args]) + '\n')
stage = ' '.join([name, *args[:3]])
if stage == os.environ.get('FAIL_STAGE'): sys.exit(23)
def write(path):
    if path == os.environ.get('SKIP_ARTIFACT'): return
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('SYNTHETIC TEST ARTIFACT\n')
if name == 'circom':
    if args == ['--version']: print('circom compiler 2.2.2')
    else:
        for path in ['artifacts/compliance.r1cs', 'artifacts/compliance.sym',
                     'artifacts/compliance_js/compliance.wasm']:
            write(path)
elif name == 'npx':
    if args == ['snarkjs', '--help']:
        if not os.environ.get('NO_SNARKJS'): print('snarkjs@0.7.5')
        sys.exit(99)
    action = tuple(args[1:3])
    if action == ('powersoftau', 'new'): write(args[5])
    elif action == ('powersoftau', 'contribute'): write(args[4])
    elif action == ('powersoftau', 'prepare'): write(args[5])
    elif action == ('groth16', 'setup'): write(args[5])
    elif action == ('zkey', 'contribute'): write(args[4])
    elif action == ('zkey', 'export'): write(args[5])
    elif action != ('r1cs', 'info'): raise AssertionError(args)
elif name == 'node':
    assert args[0] == 'scripts/generate_verifier.mjs'
    write(args[-1])
elif name == 'curl':
    write(args[-1])
    sys.exit(int(os.environ.get('CURL_EXIT', '0')))
elif name == 'sha256sum':
    print(os.environ['TEST_DIGEST'] + '  ' + args[0])
elif name == 'stat':
    mode = os.environ.get('STAT_MODE', 'gnu')
    if mode == 'missing' or (mode == 'bsd' and args[0] == '-c%s'): sys.exit(1)
    print(pathlib.Path(args[1]).stat().st_size)
else: raise AssertionError(name)
'''


@pytest.fixture
def build_tree(tmp_path):
    root = tmp_path / "project"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/compile_circuits.sh", root / "scripts/compile_circuits.sh")
    commands = tmp_path / "bin"
    commands.mkdir()
    for name in ["mkdir", "rm", "head", "awk", "xxd", "mv", "mktemp"]:
        (commands / name).symlink_to(shutil.which(name))
    for name in ["circom", "npx", "node", "curl", "sha256sum", "stat"]:
        executable = commands / name
        executable.write_text(f"#!{sys.executable}\n" + TOOL)
        executable.chmod(0o755)
    env = {**os.environ, "PATH": str(commands), "TEST_DIGEST": PIN, "CLEARPROOF_DEV_ENTROPY": "synthetic"}
    for name in ["CLEARPROOF_GENERATE_PTAU", "FAIL_STAGE", "SKIP_ARTIFACT", "CURL_EXIT", "NO_SNARKJS", "STAT_MODE"]:
        env.pop(name, None)

    def run():
        result = subprocess.run(
            ["/bin/bash", "scripts/compile_circuits.sh"], cwd=root, env=env,
            capture_output=True, text=True, timeout=30,
        )
        assert not list((root / "artifacts").glob("*.download.*")), "temporary downloads must be cleaned"
        return result

    return root, commands, env, run


def calls(root):
    return [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]


@pytest.mark.parametrize("mode", ["download", "existing", "local"])
def test_build_shell_completes_each_phase_one_path_with_synthetic_outputs(build_tree, mode):
    root, _, env, run = build_tree
    if mode == "existing":
        (root / "artifacts").mkdir()
        (root / "artifacts/pot18_final.ptau").write_text("synthetic cached phase one")
    elif mode == "local":
        env["CLEARPROOF_GENERATE_PTAU"] = "1"
    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "=== Build Complete ===" in result.stdout
    assert all((root / path).is_file() for path in ARTIFACTS)
    assert not list((root / "artifacts").glob('*_000[01].*'))
    recorded = calls(root)
    assert any(call[:4] == ["npx", "snarkjs", "groth16", "setup"] for call in recorded)
    assert any(call[:2] == ["node", "scripts/generate_verifier.mjs"] for call in recorded)
    assert not any("solidityverifier" in call for call in recorded)
    assert any(call[0] == "curl" for call in recorded) == (mode == "download")
    assert any(call[:3] == ["npx", "snarkjs", "powersoftau"] for call in recorded) == (mode == "local")


@pytest.mark.parametrize("name", ["circom", "npx"])
def test_build_shell_rejects_missing_prerequisites_before_creating_artifacts(build_tree, name):
    root, commands, _, run = build_tree
    (commands / name).unlink()
    result = run()
    assert result.returncode == 1
    assert f"{name} not found" in result.stdout
    assert not (root / "artifacts").exists()


def test_build_shell_rejects_unavailable_snarkjs_despite_npx_present(build_tree):
    root, _, env, run = build_tree
    env["NO_SNARKJS"] = "1"
    result = run()
    assert result.returncode == 1
    assert "snarkjs not found" in result.stdout
    assert not (root / "artifacts").exists()


def test_build_shell_rejects_and_removes_a_download_with_wrong_checksum(build_tree):
    root, _, env, run = build_tree
    env["TEST_DIGEST"] = "0" * 64
    result = run()
    assert result.returncode == 1
    assert "ptau SHA256 mismatch" in result.stdout
    assert not (root / "artifacts/pot18_final.ptau").exists()
    assert not any(call[:2] == ["circom", "circuits/compliance.circom"] for call in calls(root))


def test_failed_download_cannot_be_reused_as_existing_phase_one(build_tree):
    root, _, env, run = build_tree
    env["CURL_EXIT"] = "28"
    result = run()
    assert result.returncode != 0
    assert not (root / "artifacts/pot18_final.ptau").exists()
    env.pop("CURL_EXIT")
    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Downloading audited Hermez" in result.stdout
    assert sum(call[0] == "curl" for call in calls(root)) == 2


@pytest.mark.parametrize("path", ARTIFACTS)
def test_build_shell_reports_missing_outputs(build_tree, path):
    _, _, env, run = build_tree
    env["SKIP_ARTIFACT"] = path
    result = run()
    assert result.returncode == 1
    assert "=== Build Complete ===" not in result.stdout
    if path.endswith(".wasm"):
        assert "WASM file not generated" in result.stdout
    else:
        assert f"[MISSING] {path}" in result.stdout


@pytest.mark.parametrize("mode", ["bsd", "missing"])
def test_build_shell_artifact_size_reporting_has_portable_fallbacks(build_tree, mode):
    _, _, env, run = build_tree
    env["STAT_MODE"] = mode
    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "(? bytes)" in result.stdout if mode == "missing" else "(? bytes)" not in result.stdout


@pytest.mark.parametrize("stage", [
    "npx snarkjs powersoftau new", "npx snarkjs powersoftau contribute", "npx snarkjs powersoftau prepare",
    "circom circuits/compliance.circom --r1cs --wasm", "npx snarkjs r1cs info",
    "npx snarkjs groth16 setup", "npx snarkjs zkey contribute", "npx snarkjs zkey export",
    "node scripts/generate_verifier.mjs artifacts/verification_key.json "
    "packages/contracts/contracts/Groth16Verifier.sol",
])
def test_build_shell_stops_at_failed_tool_stage(build_tree, stage):
    root, _, env, run = build_tree
    env["CLEARPROOF_GENERATE_PTAU"] = "1"
    env["FAIL_STAGE"] = stage
    result = run()
    assert result.returncode == 23, result.stdout + result.stderr
    assert "=== Build Complete ===" not in result.stdout
    assert " ".join(calls(root)[-1][:4]) == stage


def test_build_shell_generates_development_entropy_when_not_supplied(build_tree):
    root, _, env, run = build_tree
    env.pop("CLEARPROOF_DEV_ENTROPY")
    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    contribution = next(call for call in calls(root) if call[:4] == ["npx", "snarkjs", "zkey", "contribute"])
    entropy = next(arg.removeprefix("-e=") for arg in contribution if arg.startswith("-e="))
    assert len(bytes.fromhex(entropy)) == 32
