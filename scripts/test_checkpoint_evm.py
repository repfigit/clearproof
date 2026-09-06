"""Run checkpoint integration on an owned, ephemeral loopback Hardhat node."""

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "packages/contracts"


def main() -> int:
    # npm may hoist Hardhat to the repo root. Resolve from the workspace using
    # Node's package lookup instead of assuming a node_modules directory layout.
    cli = subprocess.run(
        ["node", "-p", "require.resolve('hardhat/internal/cli/cli.js')"],
        cwd=CONTRACTS,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["node", cli, "compile"], cwd=CONTRACTS, check=True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    node = subprocess.Popen(
        ["node", cli, "node", "--hostname", "127.0.0.1", "--port", str(port)],
        cwd=CONTRACTS,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if node.poll() is not None:
                raise RuntimeError("Owned Hardhat node exited during startup")
            request = urllib.request.Request(
                url,
                data=b'{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}',
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=1) as response:
                    assert json.load(response)["result"] == "0x7a69"
                break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Owned Hardhat node did not become ready")
        env = {**os.environ, "CHECKPOINT_TEST_RPC": url}
        return subprocess.run(
            [sys.executable, "-m", "pytest", "tests/integration/test_pilot_checkpoint.py", "-q"], cwd=ROOT, env=env
        ).returncode
    finally:
        if node.poll() is None:
            os.killpg(node.pid, signal.SIGTERM)
            try:
                node.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(node.pid, signal.SIGKILL)
                node.wait()


if __name__ == "__main__":
    raise SystemExit(main())
