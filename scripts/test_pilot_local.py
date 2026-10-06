#!/usr/bin/env python3
"""Run synthetic pilot acceptance with an owned PostgreSQL cluster and local EVM."""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Direct script invocation must resolve this checkout, including the scripts namespace.
sys.path.insert(0, str(ROOT))


def check_prerequisites(artifacts: Path) -> None:
    """Read-only preflight before allocating either owned service or output."""
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required")
    for module in ("pytest", "pytest_asyncio", "psycopg", "cryptography", "web3"):
        if importlib.util.find_spec(module) is None:
            raise RuntimeError("Install the locked Python development dependencies")
    if not (ROOT / "packages/cli/dist/index.js").is_file():
        raise RuntimeError("Build the CLI and its dependencies before local acceptance")
    result = subprocess.run(
        [
            "node",
            "-e",
            "const [major, minor] = process.versions.node.split('.').map(Number);"
            "if (major < 22 || (major === 22 && minor < 12)) process.exit(1);"
            "require.resolve('hardhat', {paths: ['./packages/contracts']});",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=10,
    )
    if result.returncode:
        raise RuntimeError("Node 22.12+ and the locked Hardhat installation are required")
    from scripts.test_pilot_mirror import check_doctor

    check_doctor(artifacts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path, help="Inspected unapproved pilot artifacts")
    parser.add_argument("output", type=Path, help="New private run directory")
    parser.add_argument("--postgres-bin", required=True, type=Path, help="PostgreSQL 18 bin directory")
    parser.add_argument(
        "--preflight", action="store_true", help="Check setup without starting services or creating output"
    )
    args = parser.parse_args()
    binaries = {name: args.postgres_bin.resolve() / name for name in ("initdb", "pg_ctl", "createdb")}
    if any(not p.is_file() or not os.access(p, os.X_OK) for p in binaries.values()):
        parser.error("PostgreSQL initdb, pg_ctl and createdb executables are required")
    artifacts = args.artifacts.resolve(strict=True)
    version = subprocess.check_output([str(binaries["initdb"]), "--version"], text=True, timeout=10)
    if not version.startswith("initdb (PostgreSQL) 18."):
        parser.error("This local acceptance setup requires PostgreSQL 18")
    output = args.output.absolute()
    if output.exists():
        raise FileExistsError("Choose a new private run directory; existing output is never reused")
    check_prerequisites(artifacts)
    if args.preflight:
        print(
            json.dumps(
                {
                    "schema_version": "clearproof-local-preflight-v1",
                    "scope": "local-synthetic-acceptance-setup",
                    "status": "development_unapproved",
                    "checks": ["python_dependencies", "node_hardhat", "built_cli", "postgres_18", "artifact_doctor"],
                    "services_started": False,
                    "authorization_consumed": False,
                    "production_eligible": False,
                },
                sort_keys=True,
            )
        )
        return 0
    output.mkdir(mode=0o700, exist_ok=False)
    data = output / "postgres"
    # The temporary socket directory is private and kept short independently of the output path.
    with tempfile.TemporaryDirectory(prefix="cp-pg-") as socket_dir:
        if len(os.fsencode(socket_dir)) > 80:
            raise ValueError("Select a shorter TMPDIR for the private PostgreSQL socket")
        with (output / "postgres-setup.log").open("x") as log:

            def run(command):
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)

            run(
                [
                    str(binaries["initdb"]),
                    "-D",
                    str(data),
                    "--auth-local=trust",
                    "--auth-host=reject",
                    "--no-locale",
                    "--encoding=UTF8",
                ]
            )
            try:
                # pg_ctl parses -o using a shell; quote the generated path even though no customer data is used.
                import shlex

                run(
                    [
                        str(binaries["pg_ctl"]),
                        "-D",
                        str(data),
                        "-l",
                        str(output / "postgres.log"),
                        "-o",
                        f"-F -k {shlex.quote(socket_dir)} -h '' -p 5432",
                        "-w",
                        "start",
                    ]
                )
                run([str(binaries["createdb"]), "-h", socket_dir, "-p", "5432", "clearproof_test"])
                from psycopg.conninfo import make_conninfo

                env = {
                    **os.environ,
                    "DATABASE_URL": make_conninfo(host=socket_dir, port=5432, dbname="clearproof_test"),
                }
                # The child owns its EVM and enforces its own acceptance-test timeout and cleanup.
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/test_pilot_mirror.py"),
                        str(artifacts),
                        "--output",
                        str(output / "pilot"),
                    ],
                    cwd=ROOT,
                    env=env,
                )
                return result.returncode
            finally:
                stopped = subprocess.run(
                    [str(binaries["pg_ctl"]), "-D", str(data), "-m", "immediate", "-w", "stop"],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                )
                if stopped.returncode and (data / "postmaster.pid").exists():
                    raise RuntimeError("Owned PostgreSQL cluster did not stop; inspect the private setup log")
    # Data remains private for diagnosis; never publish the complete output directory.


if __name__ == "__main__":
    raise SystemExit(main())
