"""Reproduce the dated synthetic prove-only comparison; requires Linux tools."""

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
from pathlib import Path

from src.prover.pilot_artifacts import inspect_artifacts

parser = argparse.ArgumentParser(description="Synthetic current-profile native prove-only benchmark")
parser.add_argument("--artifacts", type=Path, required=True)
parser.add_argument("--native", type=Path, required=True)
parser.add_argument("--native-sha256", required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--samples", type=int, choices=range(1, 21), default=5)
parser.add_argument("--cores", type=int, choices=range(1, 5), default=4)
args = parser.parse_args()
ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = args.artifacts.resolve()
OUT = args.output.resolve()
NATIVE = args.native.resolve()
KEY = ARTIFACTS / "UNAPPROVED-development.zkey"
WITNESS = ARTIFACTS / "synthetic.wtns"
EXPECTED = json.loads((ARTIFACTS / "expected-public.json").read_text())
CLI = ROOT / "node_modules/snarkjs/build/cli.cjs"
if len(EXPECTED) != 8:
    raise RuntimeError("An explicit current eight-signal synthetic bundle is required")
if (
    not re.fullmatch(r"[0-9a-f]{64}", args.native_sha256)
    or hashlib.sha256(NATIVE.read_bytes()).hexdigest() != args.native_sha256
):
    raise RuntimeError("Native binary does not match the operator-provided pin")
artifacts = inspect_artifacts(
    ARTIFACTS, trusted_digest=(ARTIFACTS / "development-manifest-pin.txt").read_text().strip()
)
if artifacts.manifest.proof_profile != "pilot-transfer-v3" or artifacts.manifest.proving_key.filename != KEY.name:
    raise RuntimeError("Use the isolated unapproved current-profile synthetic bundle")
OUT.mkdir(parents=True, exist_ok=False)
info = subprocess.check_output(
    ["node", str(CLI), "r1cs", "info", str(ARTIFACTS / artifacts.manifest.r1cs.filename)], text=True, timeout=30
)
constraints = int(re.search(r"# of Constraints:\s*(\d+)", info).group(1))

allowed = os.sched_getaffinity(0)
cores = set()
cpus = []
for line in subprocess.check_output(["lscpu", "--parse=CPU,CORE,SOCKET"], text=True).splitlines():
    if line.startswith("#"):
        continue
    cpu, core, socket = map(int, line.split(","))
    if cpu in allowed and (socket, core) not in cores:
        cores.add((socket, core))
        cpus.append(cpu)
    if len(cpus) == args.cores:
        break
if len(cpus) != args.cores:
    raise RuntimeError("The requested distinct physical cores are unavailable")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(proof, public, log_path):
    if json.loads(public.read_text()) != EXPECTED:
        raise RuntimeError("Public signals differ from the current statement")
    with log_path.open("wb") as log:
        subprocess.run(
            ["node", str(CLI), "groth16", "verify", str(ARTIFACTS / "verification-key.json"), str(public), str(proof)],
            cwd=ROOT,
            check=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    if "OK!" not in log_path.read_text():
        raise RuntimeError("Independent verifier did not accept the proof")


records = []
for backend, threads in [("snarkjs-cli-default", None), ("rapidsnark-omp1", 1), ("rapidsnark-omp4", 4)]:
    for sample in range(args.samples + 1):
        stem = OUT / f"{backend}-{sample}"
        proof, public = Path(str(stem) + "-proof.json"), Path(str(stem) + "-public.json")
        env = os.environ.copy()
        if threads is None:
            cmd = ["node", str(CLI), "groth16", "prove", str(KEY), str(WITNESS), str(proof), str(public)]
        else:
            env.update(OMP_NUM_THREADS=str(threads), OMP_THREAD_LIMIT=str(threads), OMP_DYNAMIC="FALSE")
            cmd = [str(NATIVE), str(KEY), str(WITNESS), str(proof), str(public)]
        metrics = Path(str(stem) + "-time.txt")
        with Path(str(stem) + "-run.log").open("wb") as log:
            subprocess.run(
                [
                    "/usr/bin/time",
                    "-f",
                    "%e %U %S %M",
                    "-o",
                    str(metrics),
                    "taskset",
                    "-c",
                    ",".join(map(str, cpus)),
                    *cmd,
                ],
                env=env,
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=120,
            )
        verify(proof, public, Path(str(stem) + "-verification.log"))
        wall, user, system, rss = map(float, metrics.read_text().strip().split())
        record = dict(
            backend=backend,
            warmup=sample == 0,
            wall_seconds=wall,
            user_seconds=user,
            system_seconds=system,
            max_rss_kib=int(rss),
        )
        records.append(record)
        (OUT / "samples.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)

report = dict(
    scope=(
        "Prove only: process start, key/witness reads, proof/public writes included; "
        "witness generation and independent pairing excluded"
    ),
    assurance=(
        "Unapproved development artifacts and wholly synthetic input; no production SLA or audited backend assurance"
    ),
    cpu_affinity=cpus,
    physical_cores=len(cpus),
    logical_cpus_reported=os.cpu_count(),
    node_version=subprocess.check_output(["node", "--version"], text=True).strip(),
    platform=platform.platform(),
    upstream_commit="81eddf1a536d26497b237c0b8a04fe90baf7e439",
    native_binary_sha256=sha(NATIVE),
    proving_key_sha256=sha(KEY),
    witness_sha256=sha(WITNESS),
    r1cs_sha256=sha(ARTIFACTS / "pilot_compliance.r1cs"),
    constraints=constraints,
    parallelism_notes=[
        "CPU affinity bounds capacity; OpenMP settings do not bound upstream std::thread pools.",
        "snarkjs uses os.cpus().length workers (maximum 64); native pools use hardware_concurrency.",
    ],
    snarkjs_version=json.loads((ROOT / "node_modules/snarkjs/package.json").read_text())["version"],
    samples=records,
    summaries={},
)
for backend in {record["backend"] for record in records}:
    measured = [r for r in records if r["backend"] == backend and not r["warmup"]]
    report["summaries"][backend] = dict(
        count=len(measured),
        median_wall_seconds=statistics.median(r["wall_seconds"] for r in measured),
        min_wall_seconds=min(r["wall_seconds"] for r in measured),
        max_wall_seconds=max(r["wall_seconds"] for r in measured),
        median_max_rss_kib=statistics.median(r["max_rss_kib"] for r in measured),
        max_rss_kib=max(r["max_rss_kib"] for r in measured),
    )
for backend in report["summaries"]:
    public = OUT / f"{backend}-{args.samples}-public.json"
    proof = OUT / f"{backend}-{args.samples}-proof.json"
    changed = json.loads(public.read_text())
    changed[0] = str(int(changed[0]) + 1)
    altered = OUT / f"{backend}-tampered-public.json"
    altered.write_text(json.dumps(changed))
    rejection = subprocess.run(
        ["node", str(CLI), "groth16", "verify", str(ARTIFACTS / "verification-key.json"), str(altered), str(proof)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if rejection.returncode == 0 or "Invalid proof" not in rejection.stdout + rejection.stderr:
        raise RuntimeError("Independent tampered-statement rejection failed")
report["acceptance"] = {
    "all_proofs_independently_verified": True,
    "all_public_vectors_match_expected_eight_signals": True,
    "tampered_public_signal_rejected_for_each_backend": True,
}
(OUT / "report.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report["summaries"], indent=2), flush=True)
