"""Exercise installed Python module entrypoints in owned child processes."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "module,options",
    [
        ("src.prover.history_cli", ["--bundle", "--trust", "--runtime"]),
        ("src.protocol.bridges.pilot_bilateral_cli", ["--trust", "--request"]),
    ],
)
def test_module_help_and_required_arguments(module, options):
    help_result = subprocess.run([sys.executable, "-m", module, "--help"], capture_output=True, timeout=15)
    assert help_result.returncode == 0
    assert b"usage:" in help_result.stdout
    assert all(option.encode() in help_result.stdout for option in options)
    invalid = subprocess.run([sys.executable, "-m", module], input=b"", capture_output=True, timeout=15)
    assert invalid.returncode == 2
    assert b"required" in invalid.stderr
