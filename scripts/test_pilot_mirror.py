#!/usr/bin/env python3
"""Run the durable pilot suite with a fresh, owned local EVM and existing development artifacts."""

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_doctor(directory: Path) -> None:
    """Synthetic fixture pin only; this check never approves development keys."""
    pin = (directory / "development-manifest-pin.txt").read_text().strip()
    command = [
        "node",
        str(ROOT / "packages/cli/dist/index.js"),
        "doctor",
        "--python",
        sys.executable,
        "--artifacts",
        str(directory),
        "--trusted-manifest-digest",
        pin,
    ]
    for mode, expected in (("development", 0), ("production", 1)):
        result = subprocess.run([*command, "--mode", mode], cwd=ROOT, capture_output=True, text=True, timeout=125)
        if result.returncode != expected or result.stderr:
            raise RuntimeError("Built artifact doctor failed its local acceptance check")
        report = json.loads(result.stdout)
        if report.get("production_eligible") is not False:
            raise RuntimeError("Artifact doctor misreported production assurance")
        if mode == "development" and not (
            report.get("status") == "development_unapproved"
            and report.get("manifest_digest") == pin
            and report.get("current_profile_supported") is True
            and report.get("policy_schema_supported") is True
        ):
            raise RuntimeError("Artifact doctor did not establish the current development profile")
        if mode == "production" and report.get("reason") != "development_artifacts_forbidden":
            raise RuntimeError("Artifact doctor did not reject unapproved production use")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path, help="Inspected unapproved pilot artifact directory")
    parser.add_argument("--output", type=Path, help="New private directory for synthetic reports and encrypted export")
    args = parser.parse_args()
    if not os.environ.get("DATABASE_URL"):
        parser.error("DATABASE_URL must identify the test PostgreSQL database")
    directory = args.artifacts.resolve(strict=True)
    for name in ("verification-key.json", "development-manifest-pin.txt"):
        if not (directory / name).is_file():
            parser.error("The complete development artifact bundle is required")
    check_doctor(directory)
    output = None
    if args.output is not None:
        output = args.output.absolute()
        output.mkdir(mode=0o700, exist_ok=False)
        (output / "reports").mkdir(mode=0o700)
        (output / "private").mkdir(mode=0o700)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "CLEARPROOF_PILOT_TEST_ARTIFACTS": str(directory),
        "CLEARPROOF_MIRROR_TEST_RPC": url,
        "CLEARPROOF_POLICY_CLI_TEST": "1",
    }
    # Ignore inherited capture destinations; outputs require this command's explicit flag.
    env.pop("CLEARPROOF_PILOT_RUN_OUTPUT", None)
    if output is not None:
        env["CLEARPROOF_PILOT_RUN_OUTPUT"] = str(output)
    # Hardhat logs contain its public development account keys; keep them private and ephemeral.
    with tempfile.TemporaryFile() as log:
        node = subprocess.Popen(
            [
                "npm",
                "exec",
                "--offline",
                "--workspace=@clearproof/contracts",
                "--",
                "hardhat",
                "node",
                "--hostname",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        tests = None
        try:
            deadline = time.monotonic() + 30
            while True:
                if node.poll() is not None:
                    raise RuntimeError("Owned local EVM exited before readiness")
                try:
                    request = urllib.request.Request(
                        url,
                        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(request, timeout=1) as response:
                        if json.load(response).get("result") != "0x7a69":
                            raise RuntimeError("Local EVM has an unexpected chain ID")
                    break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Owned local EVM did not become ready") from None
                    time.sleep(0.1)
            print(
                "Running real PostgreSQL authorization and receipt mirroring on an isolated development EVM", flush=True
            )
            tests = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "tests/integration/test_proof_storage.py",
                    "tests/integration/test_pilot_storage.py",
                    "tests/integration/test_publication_journal.py",
                    "-q",
                    "--tb=short",
                ],
                cwd=ROOT,
                env=env,
                start_new_session=True,
            )
            code = tests.wait(timeout=420)
            if code == 0 and output is not None:
                finish_outputs(output, directory)
            return code
        finally:
            for process in (tests, node):
                if process is None:
                    continue
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


def finish_outputs(output, artifacts):
    expected = {
        "policy-comparison.json",
        "history.encrypted.json",
        "reviewer-trust.json",
        "history-report.json",
        "history-clock.json",
        "observation-cohort.json",
        "observations.json",
        "investigation.json",
        "counterparty-scenarios.json",
    }
    if {p.name for p in (output / "reports").iterdir()} != expected:
        raise RuntimeError("Pilot gate passed but required retained outputs are missing or unexpected")
    if not (output / "private/reviewer-key.json").is_file():
        raise RuntimeError("Synthetic offline reviewer key was not retained")
    inventory = []
    for name in sorted(expected):
        raw = (output / "reports" / name).read_bytes()
        json.loads(raw)
        inventory.append({"path": "reports/" + name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    manifest = dict(
        schema_version="clearproof-local-pilot-run-v1",
        outcome="acceptance-tests-passed",
        assurance="development-unapproved",
        source_authenticity="local-simulators-and-synthetic-fixtures",
        scope="local-acceptance-suite",
        clean_environment="not-established",
        artifact_manifest_pin=(artifacts / "development-manifest-pin.txt").read_text().strip(),
        reports=inventory,
        private_material="private/reviewer-key.json; never publish this directory",
    )
    fd = os.open(output / "run.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(manifest, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print("Retained synthetic reports and encrypted export; private reviewer key is separate", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
