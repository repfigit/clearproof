"""The operational key generator emits keys that work with actual HPKE envelopes."""

import base64
import hashlib
import runpy
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.sar.hpke_envelope import open_envelope, seal_envelope

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/hpke_keygen.py"


def check_key_output(output):
    # Keep ephemeral generated private material inside the test process.
    lines = output.splitlines()
    assert len(lines) == 4
    assert lines[0].startswith("# HPKE v2 keypair (X25519)")
    settings = dict(line.split("=", 1) for line in lines[1:3])
    assert set(settings) == {"VASP_HPKE_PRIVATE_KEY", "VASP_HPKE_PUBLIC_KEY"}
    private = base64.b64decode(settings["VASP_HPKE_PRIVATE_KEY"], altchars=b"-_", validate=True)
    public = base64.b64decode(settings["VASP_HPKE_PUBLIC_KEY"], altchars=b"-_", validate=True)
    assert len(private) == len(public) == 32
    derived = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert derived == public
    fingerprint = base64.urlsafe_b64encode(hashlib.sha256(public).digest()[:16]).decode("ascii")
    assert lines[3] == f"# key id (kid fingerprint): {fingerprint}"
    envelope = seal_envelope(b"synthetic operational key test", public, "synthetic-keygen-envelope")
    assert open_envelope(envelope, private) == b"synthetic operational key test"
    return public


def test_import_is_silent_and_main_generates_distinct_usable_keys(capsys):
    module = runpy.run_path(str(SCRIPT))
    assert capsys.readouterr().out == ""
    module["main"]()
    first = check_key_output(capsys.readouterr().out)
    module["main"]()
    second = check_key_output(capsys.readouterr().out)
    assert first != second


def test_script_entry_point_generates_usable_keys(capsys):
    runpy.run_path(str(SCRIPT), run_name="__main__")
    output = capsys.readouterr()
    assert output.err == ""
    check_key_output(output.out)


def test_actual_cli_works_outside_repository_without_writing_files(tmp_path):
    external = tmp_path / "external-working-directory"
    external.mkdir()
    process = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=external, capture_output=True, text=True, timeout=15
    )
    assert process.returncode == 0
    assert process.stderr == ""
    check_key_output(process.stdout)
    assert list(external.iterdir()) == []
