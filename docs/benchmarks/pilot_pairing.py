# SPDX-License-Identifier: Apache-2.0
"""Measure the current synthetic pairing path; no network or customer records."""

import argparse
import asyncio
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from src.prover.pilot_artifacts import inspect_artifacts
from src.prover.pilot_verifier import PAIRING_PROCESS_LIMIT, PilotPairingVerifier, public_signals

ROOT = Path(__file__).resolve().parents[2]


async def measure(verifier, proof, signals, concurrency):
    owned = []
    peaks = {"aggregate": 0, "individual": 0}
    original = asyncio.create_subprocess_exec

    async def spawn(*args, **kwargs):
        proc = await original(*args, **kwargs)
        owned.append(proc)
        return proc

    async def sample():
        while True:
            rss = []
            for proc in owned:
                if proc.returncode is not None:
                    continue
                try:
                    for line in Path(f"/proc/{proc.pid}/status").read_text().splitlines():
                        if line.startswith("VmRSS:"):
                            rss.append(int(line.split()[1]))
                            break
                except FileNotFoundError:
                    pass
            peaks["aggregate"] = max(peaks["aggregate"], sum(rss))
            peaks["individual"] = max(peaks["individual"], max(rss, default=0))
            await asyncio.sleep(0.01)

    async def inspect():
        started = time.perf_counter()
        result = await verifier.inspect(proof, signals, expected_signals=signals)
        if not result.cryptographic_valid:
            raise RuntimeError("Synthetic proof failed independent pairing")
        return time.perf_counter() - started

    # Instrument only this standalone benchmark process, never a serving API.
    asyncio.create_subprocess_exec = spawn
    monitor = asyncio.create_task(sample())
    started = time.perf_counter()
    try:
        durations = await asyncio.gather(*(inspect() for _ in range(concurrency)))
        elapsed = time.perf_counter() - started
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        asyncio.create_subprocess_exec = original
    if len(owned) != concurrency or any(proc.returncode is None for proc in owned):
        raise RuntimeError("Unexpected runtime count or unfinished child")
    return dict(
        concurrent_processes=concurrency,
        elapsed_seconds=elapsed,
        request_seconds=durations,
        requests_per_second=concurrency / elapsed,
        sampled_aggregate_peak_rss_kib=peaks["aggregate"],
        sampled_individual_peak_rss_kib=peaks["individual"],
        proofs_accepted=concurrency,
    )


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, choices=range(1, 11), default=5)
    parser.add_argument("--cores", type=int, choices=range(1, 5), default=4)
    args = parser.parse_args()
    if platform.system() != "Linux" or args.output.exists():
        raise RuntimeError("Requires Linux and a new output file")
    allowed = os.sched_getaffinity(0)
    physical, cpus = set(), []
    for line in subprocess.check_output(["lscpu", "--parse=CPU,CORE,SOCKET"], text=True, timeout=10).splitlines():
        if line.startswith("#"):
            continue
        cpu, core, socket = map(int, line.split(","))
        if cpu in allowed and (socket, core) not in physical:
            physical.add((socket, core))
            cpus.append(cpu)
        if len(cpus) == args.cores:
            break
    if len(cpus) != args.cores:
        raise RuntimeError("Requested distinct physical cores are unavailable")
    os.sched_setaffinity(0, cpus)
    artifacts = inspect_artifacts(
        args.artifacts, trusted_digest=(args.artifacts / "development-manifest-pin.txt").read_text().strip()
    )
    if (
        artifacts.manifest.proof_profile != "pilot-transfer-v3"
        or artifacts.manifest.assurance != "development-unapproved"
    ):
        raise RuntimeError("Requires an isolated unapproved current-profile development bundle")
    proof = (args.artifacts / "proof.json").read_bytes()
    signals = public_signals(json.loads((args.artifacts / "expected-public.json").read_text()))
    verifier = PilotPairingVerifier.load(
        artifacts,
        bundle_path=ROOT / "node_modules/snarkjs/build/snarkjs.min.js",
        bundle_sha256=args.bundle_sha256,
        node=Path(shutil.which("node")),
    )
    records = []
    for concurrency in (1, PAIRING_PROCESS_LIMIT):
        await measure(verifier, proof, signals, concurrency)  # One excluded warmup per mode.
        for index in range(args.samples):
            records.append({"sample": index + 1, **await measure(verifier, proof, signals, concurrency)})
    summary = []
    for concurrency in (1, PAIRING_PROCESS_LIMIT):
        selected = [r for r in records if r["concurrent_processes"] == concurrency]
        summary.append(
            dict(
                concurrent_processes=concurrency,
                median_request_seconds=statistics.median(t for r in selected for t in r["request_seconds"]),
                median_requests_per_second=statistics.median(r["requests_per_second"] for r in selected),
                max_sampled_aggregate_rss_kib=max(r["sampled_aggregate_peak_rss_kib"] for r in selected),
                max_sampled_individual_rss_kib=max(r["sampled_individual_peak_rss_kib"] for r in selected),
            )
        )
    report = dict(
        schema_version="clearproof-pairing-benchmark-v1",
        measured_at=datetime.now(timezone.utc).isoformat(),
        scope="synthetic-current-profile-pairing-only",
        production_eligible=False,
        authorization_consumed=False,
        artifact_manifest_digest=artifacts.manifest.digest,
        proof_sha256=hashlib.sha256(proof).hexdigest(),
        runtime_bundle_sha256=args.bundle_sha256,
        verification_key_sha256=artifacts.manifest.verification_key.sha256,
        node_version=subprocess.check_output([str(verifier.node), "--version"], text=True, timeout=10).strip(),
        host=platform.platform(),
        cpu_affinity=cpus,
        process_limit=PAIRING_PROCESS_LIMIT,
        samples_per_mode=args.samples,
        warmup_batches_per_mode=1,
        rss_sample_interval_seconds=0.01,
        rss_scope="Node child processes including threads; excludes Python, database and containers",
        summary=summary,
        samples=records,
    )
    with args.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    asyncio.run(main())
