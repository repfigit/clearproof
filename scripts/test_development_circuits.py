#!/usr/bin/env python3
"""Compile and prove both profiles with isolated, unapproved development keys.

No generated source, key or artifact is written into the tracked checkout.
A local contribution is a reproducibility tool, not a production ceremony.
"""

import argparse
import hashlib
import json
import os
import runpy
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(*args, cwd=ROOT, env=None, timeout=1800):
    # Arguments are development artifact paths/options, never customer inputs.
    print("Development step:", " ".join(str(arg) for arg in args), flush=True)
    started = time.monotonic()
    process = subprocess.Popen([str(arg) for arg in args], cwd=cwd, env=env, start_new_session=True)
    try:
        code = process.wait(timeout=timeout)
        if code:
            raise subprocess.CalledProcessError(code, process.args)
    finally:
        # Kill the owned group on timeout/interruption, including worker children.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        print(f"Development step elapsed: {time.monotonic() - started:.1f}s", flush=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory for unapproved development artifacts")
    parser.add_argument(
        "--prepared-ptau", type=Path, help="Explicit local development input; never production approval"
    )
    args = parser.parse_args()
    output = args.output.resolve()
    # Refuse reuse or overwrite, including existing symlinks.
    output.mkdir(parents=True, exist_ok=False)
    node = shutil.which("node")
    circom = shutil.which("circom")
    if not node or not circom:
        raise SystemExit("Node and Circom must be installed")
    cli = ROOT / "node_modules/snarkjs/build/cli.cjs"
    if not cli.is_file():
        raise SystemExit("Install the repository dependencies before running")
    (output / "DEVELOPMENT-ONLY.txt").write_text(
        "UNAPPROVED development keys. No audit or production ceremony.\n"
        "Synthetic policy-schema marker is unbound, not an approved policy.\n"
    )
    ptau = output / "UNAPPROVED-final.ptau"
    if args.prepared_ptau:
        shutil.copyfile(args.prepared_ptau, ptau)
    else:
        initial = output / "UNAPPROVED-initial.ptau"
        contributed = output / "UNAPPROVED-contributed.ptau"
        run(node, cli, "powersoftau", "new", "bn128", "16", initial)
        run(
            node,
            cli,
            "powersoftau",
            "contribute",
            initial,
            contributed,
            "--name=Clearproof CI development only",
            "-e=unapproved-ci-development-not-a-production-ceremony",
        )
        run(node, cli, "powersoftau", "prepare", "phase2", contributed, ptau, "-v", timeout=5400)
        initial.unlink()
        contributed.unlink()
    (output / "ptau-sha256.txt").write_text(digest(ptau) + "\n")

    for name, source in (("legacy", "compliance"), ("pilot", "pilot_compliance")):
        target = output / name
        target.mkdir()
        run(circom, ROOT / f"circuits/{source}.circom", "--r1cs", "--wasm", "--sym", "-o", target)
        run(node, cli, "groth16", "setup", target / f"{source}.r1cs", ptau, target / "initial.zkey")
        key = target / ("compliance_final.zkey" if name == "legacy" else "UNAPPROVED-development.zkey")
        run(
            node,
            cli,
            "zkey",
            "contribute",
            target / "initial.zkey",
            key,
            "--name=Clearproof CI phase two development only",
            "-e=unapproved-ci-phase-two-development",
        )
        (target / "initial.zkey").unlink()
        vkey = target / ("verification_key.json" if name == "legacy" else "verification-key.json")
        run(node, cli, "zkey", "export", "verificationkey", key, vkey)
        run(node, ROOT / "scripts/generate_verifier.mjs", vkey, target / "Groth16Verifier.sol")

    # Preserve the existing legacy CLI smoke check using fresh, matching files.
    for workspace in ("content", "proof", "cli"):
        directory = ROOT / f"packages/{workspace}"
        compiler = subprocess.check_output(
            [node, "-e", "process.stdout.write(require.resolve('typescript/bin/tsc'))"],
            cwd=directory,
            text=True,
            timeout=30,
        )
        run(node, compiler, cwd=directory)
    run(node, ROOT / "packages/cli/dist/index.js", "demo", "--artifacts", output / "legacy")

    # Reproduce the composed profile from synthetic fixtures, without private data.
    from src.prover.pilot_artifacts import PilotArtifactManifest, inspect_artifacts
    from src.prover.pilot_compliance import PUBLIC_SIGNALS

    pilot = output / "pilot"
    fixture = runpy.run_path(str(ROOT / "tests/unit/test_pilot_compliance.py"))
    witness = fixture["witness"].__wrapped__()
    (pilot / "synthetic.json").write_text(json.dumps(witness))
    (pilot / "expected-public.json").write_text(json.dumps([witness[name] for name in PUBLIC_SIGNALS]))
    run(
        node,
        pilot / "pilot_compliance_js/generate_witness.js",
        pilot / "pilot_compliance_js/pilot_compliance.wasm",
        pilot / "synthetic.json",
        pilot / "synthetic.wtns",
    )
    run(
        node,
        cli,
        "groth16",
        "prove",
        pilot / "UNAPPROVED-development.zkey",
        pilot / "synthetic.wtns",
        pilot / "proof.json",
        pilot / "public.json",
    )
    shutil.copyfile(pilot / "pilot_compliance_js/pilot_compliance.wasm", pilot / "pilot_compliance.wasm")
    # This digest identifies a source inventory; it is not a reproducible-build attestation.
    sources = {
        str(p.relative_to(ROOT)): digest(p)
        for folder in (ROOT / "circuits", ROOT / "node_modules/circomlib/circuits")
        for p in sorted(folder.rglob("*.circom"))
    }
    source_bytes = json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
    (output / "source-inventory.json").write_bytes(source_bytes)
    value = {
        "policy_schema_digest": "0" * 64,
        "source_bundle_digest": hashlib.sha256(source_bytes).hexdigest(),
        "compiler_sha256": digest(Path(circom)),
        "public_signals": list(PUBLIC_SIGNALS),
    }
    for role, filename in (
        ("wasm", "pilot_compliance.wasm"),
        ("r1cs", "pilot_compliance.r1cs"),
        ("proving_key", "UNAPPROVED-development.zkey"),
        ("verification_key", "verification-key.json"),
    ):
        path = pilot / filename
        value[role] = {"filename": filename, "sha256": digest(path), "size": path.stat().st_size}
    raw = json.dumps(value).encode()
    manifest = PilotArtifactManifest.model_validate_json(raw)
    (pilot / "manifest.json").write_bytes(raw)
    (pilot / "development-manifest-pin.txt").write_text(manifest.digest)
    inspect_artifacts(pilot, trusted_digest=manifest.digest)
    run(
        sys.executable,
        "-m",
        "pytest",
        "tests/integration/test_pilot_pairing.py",
        "-q",
        env={**os.environ, "CLEARPROOF_PILOT_TEST_ARTIFACTS": str(pilot)},
    )
    print("Development round trips passed; artifacts remain unapproved:", output, flush=True)


if __name__ == "__main__":
    main()
