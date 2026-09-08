"""Importing CLI configuration must not run its command or consume secrets."""

import importlib
import subprocess
import sys
from pathlib import Path


def test_bilateral_cli_import_has_no_command_side_effects():
    module = "src.protocol.bridges.pilot_bilateral_cli"
    result = subprocess.run(
        [sys.executable, "-c", (
            "import importlib, io, sys; "
            "source = io.TextIOWrapper(io.BytesIO(b'synthetic-secret')); sys.stdin = source; "
            f"importlib.import_module({module!r}); "
            "assert source.tell() == 0"
        )],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
        check=True,
        timeout=30,
    )
    assert result.stdout == ""
    assert result.stderr == ""
    assert callable(importlib.import_module(module).main)
