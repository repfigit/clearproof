"""Exercise the development runner's real subprocess lifecycle."""

import os
import runpy
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

run = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/test_development_circuits.py"))["run"]


def test_runner_success_and_nonzero_exit(capsys):
    run(sys.executable, "-c", "pass", timeout=5)
    assert "Development step elapsed:" in capsys.readouterr().out
    with pytest.raises(subprocess.CalledProcessError) as exc:
        run(sys.executable, "-c", "raise SystemExit(7)", timeout=5)
    assert exc.value.returncode == 7


def test_timeout_terminates_owned_child_group(tmp_path):
    pid_file = tmp_path / "child.pid"
    program = (
        "import subprocess,sys,time; "
        "from pathlib import Path; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run(sys.executable, "-c", program, pid_file, timeout=1)
        pid = int(pid_file.read_text())
        # An orphan may briefly remain a zombie until the host's init reaps it.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{pid}/stat")
            try:
                state = stat.read_text().split()[2]
            except (FileNotFoundError, ProcessLookupError):
                # The host may reap the process between lookup and read.
                break
            if state == "Z":
                break
            time.sleep(0.02)
        else:
            pytest.fail("Timed-out worker remained running")
    finally:
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
