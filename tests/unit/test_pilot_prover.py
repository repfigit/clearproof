"""Private proving transport and process ownership; stub runtimes are not real proofs."""

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.prover import pilot_prover as module
from src.prover.pilot_prover import PilotProver, PilotProvingError, bounded_output
from tests.unit.test_pilot_artifacts import bundle as bundle
from tests.unit.test_pilot_artifacts import publish
from tests.unit.test_pilot_verifier import synthetic_proof

SIGNALS = ["1"] * 8
PRIVATE = {"holder_secret": "SYNTHETIC_PRIVATE_INPUT_987654321"}


def prover(bundle, source):
    root, _, digest = bundle
    node = shutil.which("node")
    if not node:
        pytest.skip("requires Node")
    runtime = root / "runtime.js"
    runtime.write_bytes(source)
    return PilotProver.load(
        root,
        trusted_digest=digest,
        bundle_path=runtime,
        bundle_sha256=hashlib.sha256(source).hexdigest(),
        node=Path(node),
    )


def good_runtime():
    # Returns encoding-valid synthetic values and a stubbed pairing result only.
    return (
        "const snarkjs={groth16:{fullProve:async()=>({proof:"
        + json.dumps(synthetic_proof())
        + ",publicSignals:"
        + json.dumps(SIGNALS)
        + "}),verify:async()=>true}};"
    ).encode()


async def test_private_inputs_never_enter_environment_arguments_or_runtime_files(bundle, monkeypatch):
    target = prover(bundle, good_runtime())
    monkeypatch.setenv("PRIVATE_ENVIRONMENT_TEST", PRIVATE["holder_secret"])
    original = asyncio.create_subprocess_exec
    observed = []

    async def inspect_spawn(*args, **kwargs):
        assert PRIVATE["holder_secret"] not in repr(args) + repr(kwargs)
        assert "PRIVATE_ENVIRONMENT_TEST" not in kwargs["env"]
        script = Path(args[-2])
        assert PRIVATE["holder_secret"].encode() not in script.read_bytes()
        observed.append(script.parent)
        return await original(*args, **kwargs)

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", inspect_spawn)
    result = await target.prove(PRIVATE, expected_signals=SIGNALS)
    assert result.public_signals == tuple(SIGNALS)
    assert "pi_a" in json.loads(result.proof)
    assert "pi_a" not in repr(result) and PRIVATE["holder_secret"] not in repr(target)
    assert observed and all(not directory.exists() for directory in observed)
    assert sorted(p.name for p in target.root.iterdir()) == [
        "manifest.json",
        "proving_key.bin",
        "r1cs.bin",
        "runtime.js",
        "verification_key.bin",
        "wasm.bin",
    ]


@pytest.mark.parametrize("timeout", [True, 0, 121, 1.5])
async def test_invalid_timeouts_reject_before_spawn(bundle, timeout):
    with pytest.raises(PilotProvingError, match="invalid_proving_timeout"):
        await prover(bundle, good_runtime()).prove(PRIVATE, expected_signals=SIGNALS, timeout=timeout)


@pytest.mark.parametrize("value", [None, [], {"nan": float("nan")}, {"object": object()}])
async def test_invalid_private_inputs_reject_without_echoing(bundle, value):
    with pytest.raises(PilotProvingError, match="invalid_proving_input"):
        await prover(bundle, good_runtime()).prove(value, expected_signals=SIGNALS)


async def test_input_size_bound(bundle):
    with pytest.raises(PilotProvingError, match="proving_input_limit"):
        await prover(bundle, good_runtime()).prove({"secret": "x" * 65536}, expected_signals=SIGNALS)


@pytest.mark.parametrize("attack", ["size", "hash", "symlink", "fifo", "root-symlink", "missing"])
async def test_artifact_replacement_rejects(bundle, attack):
    target = prover(bundle, good_runtime())
    wasm = target.root / "wasm.bin"
    if attack == "size":
        wasm.write_bytes(b"changed-size")
    elif attack == "hash":
        wasm.write_bytes(b"x" * wasm.stat().st_size)
    elif attack in ("symlink", "fifo", "missing"):
        wasm.unlink()
        if attack == "symlink":
            wasm.symlink_to(target.root / "r1cs.bin")
        elif attack == "fifo":
            os.mkfifo(wasm)
    else:
        from dataclasses import replace

        alias = target.root.parent / "alias"
        alias.symlink_to(target.root, target_is_directory=True)
        target = replace(target, root=alias)
    with pytest.raises(PilotProvingError, match="proving_artifact_|proving_runtime_failed"):
        await target.prove(PRIVATE, expected_signals=SIGNALS)


@pytest.mark.parametrize("attack", ["signal", "pairing", "exception"])
async def test_bad_backend_results_reject_without_subprocess_detail(bundle, attack):
    source = good_runtime()
    if attack == "signal":
        source = source.replace(json.dumps(SIGNALS).encode(), json.dumps(["2"] * 8).encode())
    elif attack == "pairing":
        source = source.replace(b"verify:async()=>true", b"verify:async()=>false")
    else:
        source = b"const snarkjs={groth16:{fullProve:async()=>{throw new Error('PRIVATE-DETAIL')}}};"
    with pytest.raises(PilotProvingError, match="^proving_runtime_failed$"):
        await prover(bundle, source).prove(PRIVATE, expected_signals=SIGNALS)


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        "[]",
        '{"other":1}',
        json.dumps({"proof": {}, "public_signals": SIGNALS}),
        json.dumps({"proof": synthetic_proof(), "public_signals": ["2"] * 8}),
    ],
)
async def test_defensive_result_parsing(bundle, output):
    source = (
        "process.stdin.on('end',()=>{process.stdout.write("
        + json.dumps(output)
        + ");process.exit(0)});process.stdin.resume();"
    ).encode()
    with pytest.raises(PilotProvingError, match="invalid_proving_result|proving_signal_mismatch"):
        await prover(bundle, source).prove(PRIVATE, expected_signals=SIGNALS)


async def test_output_limit_kills_runtime(bundle):
    source = b"process.stdout.write('x'.repeat(1000000));setInterval(()=>{},1000);"
    with pytest.raises(PilotProvingError, match="proving_output_limit"):
        await prover(bundle, source).prove(PRIVATE, expected_signals=SIGNALS)


def running(pid):
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        return "State:\tZ" not in status
    except FileNotFoundError:
        return False


async def wait_pid(path):
    async with asyncio.timeout(5):
        while not path.exists():
            await asyncio.sleep(0.01)
    return int(path.read_text())


@pytest.mark.parametrize("cancel", [False, True])
async def test_timeout_and_cancellation_reap_owned_process(bundle, cancel):
    pidfile = bundle[0] / "owned-pid"
    source = (
        "require('node:fs').writeFileSync("
        + json.dumps(str(pidfile))
        + ",String(process.pid));"
        + "const snarkjs={groth16:{fullProve:async()=>new Promise(()=>setInterval(()=>{},1000))}};"
    ).encode()
    target = prover(bundle, source)
    task = asyncio.create_task(target.prove(PRIVATE, expected_signals=SIGNALS, timeout=1 if not cancel else 120))
    pid = await wait_pid(pidfile)
    assert re.search(r"Max core file size\s+0\s+0\s+bytes", Path(f"/proc/{pid}/limits").read_text())
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(PilotProvingError, match="proving_timeout"):
            await task
    assert not running(pid)


async def test_cancellation_during_creation_still_reaps_spawned_process(bundle, monkeypatch):
    target = prover(bundle, good_runtime())
    original = asyncio.create_subprocess_exec
    started, processes = asyncio.Event(), []

    async def delayed(*args, **kwargs):
        started.set()
        await asyncio.sleep(0.05)
        proc = await original(*args, **kwargs)
        processes.append(proc)
        return proc

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", delayed)
    task = asyncio.create_task(target.prove(PRIVATE, expected_signals=SIGNALS))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert processes and processes[0].returncode is not None


async def test_runtime_spawn_failure_is_sanitized(bundle, monkeypatch):
    target = prover(bundle, good_runtime())

    async def unavailable(*args, **kwargs):
        raise OSError("PRIVATE-ERROR")

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", unavailable)
    with pytest.raises(PilotProvingError, match="^proving_runtime_unavailable$"):
        await target.prove(PRIVATE, expected_signals=SIGNALS)


@pytest.mark.parametrize("heap", [True, 255, 4097])
def test_heap_limit_rejects(bundle, heap):
    root, _, digest = bundle
    with pytest.raises(PilotProvingError, match="invalid_proving_heap_limit"):
        PilotProver.load(
            root,
            trusted_digest=digest,
            bundle_path=root / "missing",
            bundle_sha256="0" * 64,
            node=Path("/missing"),
            heap_mb=heap,
        )


def test_unsupported_worker_platform_rejects(bundle, monkeypatch):
    target = prover(bundle, good_runtime())
    monkeypatch.setattr(module.sys, "platform", "win32")
    with pytest.raises(PilotProvingError, match="linux_proving_worker_required"):
        PilotProver.load(
            target.root,
            trusted_digest=bundle[2],
            bundle_path=target.root / "runtime.js",
            bundle_sha256="0" * 64,
            node=target.verifier.node,
        )


@pytest.mark.parametrize("profile,policy", [("pilot-transfer-v2", None), ("pilot-transfer-v3", "00" * 32)])
def test_historical_profiles_and_unrecognized_policy_schemas_reject(bundle, profile, policy):
    root, value, _ = bundle
    value["proof_profile"] = profile
    if policy is not None:
        value["policy_schema_digest"] = policy
    bundle = (root, value, publish(root, value))
    with pytest.raises(PilotProvingError, match="unsupported_proving_profile"):
        prover(bundle, good_runtime())


async def test_reader_accepts_exact_output_bound():
    stream = asyncio.StreamReader()
    stream.feed_data(b"x" * module.MAX_OUTPUT)
    stream.feed_eof()
    assert len(await bounded_output(stream)) == module.MAX_OUTPUT


async def test_process_exit_race_during_cleanup_still_reaps(bundle, monkeypatch):
    source = b"const snarkjs={groth16:{fullProve:async()=>new Promise(()=>setInterval(()=>{},1000))}};"
    target = prover(bundle, source)
    original = os.killpg

    def process_finished(pid, sig):
        original(pid, sig)
        raise ProcessLookupError

    monkeypatch.setattr(module.os, "killpg", process_finished)
    with pytest.raises(PilotProvingError, match="proving_timeout"):
        await target.prove(PRIVATE, expected_signals=SIGNALS, timeout=1)


async def test_worker_sigkill_terminates_prover_without_finally_cleanup(bundle):
    pidfile = bundle[0] / "crash-owned-pid"
    source = (
        "require('node:fs').writeFileSync(" + json.dumps(str(pidfile)) + ",String(process.pid));"
        "const snarkjs={groth16:{fullProve:async()=>new Promise(()=>setInterval(()=>{},1000))}};"
    ).encode()
    target = prover(bundle, source)
    # The outer worker receives its private input through a pipe too.
    worker = r"""
import asyncio, hashlib, json, sys
from pathlib import Path
from src.prover.pilot_prover import PilotProver
root, pin, runtime, node = sys.argv[1:]
runtime = Path(runtime)
p = PilotProver.load(Path(root), trusted_digest=pin, bundle_path=runtime,
    bundle_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(), node=Path(node))
asyncio.run(p.prove(json.load(sys.stdin), expected_signals=['1']*8))
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            worker,
            str(target.root),
            bundle[2],
            str(target.root / "runtime.js"),
            str(target.verifier.node),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=Path(__file__).resolve().parents[2],
    )
    try:
        process.stdin.write(json.dumps(PRIVATE).encode())
        process.stdin.close()
        pid = await wait_pid(pidfile)
        process.kill()
        await asyncio.to_thread(process.wait, timeout=5)
        async with asyncio.timeout(5):
            while running(pid):
                await asyncio.sleep(0.01)
    finally:
        if process.poll() is None:
            process.kill()
        await asyncio.to_thread(process.wait, timeout=5)
