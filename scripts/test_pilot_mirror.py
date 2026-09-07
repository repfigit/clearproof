#!/usr/bin/env python3
"""Run the durable pilot suite with a fresh, owned local EVM and existing development artifacts."""

import argparse
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path, help="Inspected unapproved pilot artifact directory")
    args = parser.parse_args()
    if not os.environ.get("DATABASE_URL"):
        parser.error("DATABASE_URL must identify the test PostgreSQL database")
    directory = args.artifacts.resolve(strict=True)
    for name in ("verification-key.json", "development-manifest-pin.txt"):
        if not (directory / name).is_file():
            parser.error("The complete development artifact bundle is required")
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
                [sys.executable, "-m", "pytest", "tests/integration/test_pilot_storage.py", "-q", "--tb=short"],
                cwd=ROOT,
                env=env,
                start_new_session=True,
            )
            return tests.wait(timeout=420)
        finally:
            for process in (tests, node):
                if process is None:
                    continue
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
