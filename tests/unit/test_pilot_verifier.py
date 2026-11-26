"""Canonical proof parsing and actual owned-runtime lifecycle checks."""

import asyncio
import gc
import hashlib
import json
import os
import shutil
import signal
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import src.prover.pilot_verifier as pv
from src.prover.pilot_artifacts import InspectedArtifacts, PilotArtifactManifest
from src.prover.pilot_compliance import PUBLIC_SIGNALS
from src.prover.pilot_verifier import (
    BASE_FIELD,
    DEFAULT_PAIRING_PROCESS_LIMIT,
    MAX_PAIRING_PAYLOAD,
    MAX_PAIRING_PROCESS_LIMIT,
    PAIRING_PROCESS_LIMIT,
    PairingCapacityExceeded,
    PairingConfigurationError,
    PilotPairingVerifier,
    PilotProof,
    ProofInspectionError,
    pairing_process_limit,
    pinned_bundle,
    public_signals,
)
from src.registry.poseidon import BN254_SCALAR_FIELD


def synthetic_proof():
    return {
        "protocol": "groth16",
        "curve": "bn128",
        "pi_a": ["1", "2", "1"],
        "pi_b": [["1", "2"], ["3", "4"], ["1", "0"]],
        "pi_c": ["1", "2", "1"],
    }


@pytest.mark.parametrize("value", [str(BASE_FIELD), "01", "-1", "1.0", "0x1", True, 1, "1" * 10000])
def test_noncanonical_curve_coordinates_rejected(value):
    proof = synthetic_proof()
    proof["pi_a"][0] = value
    with pytest.raises(ProofInspectionError, match="invalid_proof_encoding"):
        PilotProof.parse(json.dumps(proof).encode())


@pytest.mark.parametrize("attack", ["duplicate", "extra", "infinity", "projective", "wrong-curve", "legacy"])
def test_proof_shape_rejections(attack):
    proof = synthetic_proof()
    if attack == "duplicate":
        raw = b'{"curve":"bn254",' + json.dumps(proof).encode()[1:]
    else:
        if attack == "extra":
            proof["secret"] = "do-not-log"
        elif attack == "infinity":
            proof["pi_a"] = ["0", "1", "0"]
        elif attack == "projective":
            proof["pi_b"][2] = ["2", "0"]
        elif attack == "wrong-curve":
            proof["curve"] = "bls12381"
        else:
            proof["pi_c"].append("1")
        raw = json.dumps(proof).encode()
    with pytest.raises(ProofInspectionError, match="^invalid_proof_encoding$"):
        PilotProof.parse(raw)


@pytest.mark.parametrize("value", [["0"] * 16, ["0"] * 7, ["01"] * 8, [str(BN254_SCALAR_FIELD)] * 8, [True] * 8])
def test_signal_aliases_and_legacy_layout_rejected(value):
    with pytest.raises(ProofInspectionError, match="invalid_public_signals"):
        public_signals(value)


def test_base_and_scalar_fields_are_distinct():
    proof = synthetic_proof()
    proof["pi_a"][0] = str(BN254_SCALAR_FIELD)
    # Encoding-valid coordinate, not a claim that this is a point on the curve.
    PilotProof.parse(json.dumps(proof).encode())
    assert public_signals([str(BN254_SCALAR_FIELD - 1)] * 8)


@pytest.fixture
def artifacts():
    value = {
        "public_signals": list(PUBLIC_SIGNALS),
        "policy_schema_digest": "00" * 32,
        "source_bundle_digest": "00" * 32,
        "compiler_sha256": "00" * 32,
    }
    for role in ("wasm", "r1cs", "proving_key", "verification_key"):
        value[role] = {"filename": role, "sha256": "00" * 32, "size": 1}
    return InspectedArtifacts(PilotArtifactManifest.model_validate_json(json.dumps(value)), b"{}")


def runtime(tmp_path, artifacts, source):
    node = shutil.which("node")
    if not node:
        pytest.skip("requires Node")
    path = tmp_path / "bundle.js"
    path.write_bytes(source)
    return PilotPairingVerifier.load(
        artifacts, bundle_path=path, bundle_sha256=hashlib.sha256(source).hexdigest(), node=Path(node)
    )


async def test_context_mismatch_precedes_runtime(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"throw new Error('should not execute')")
    with pytest.raises(ProofInspectionError, match="public_signal_context_mismatch"):
        await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["1"] * 8)


async def test_pinned_snapshot_and_environment_isolation(tmp_path, artifacts, monkeypatch):
    # Stub tests transport only; actual Groth16 is covered by the integration test.
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    (tmp_path / "bundle.js").write_bytes(b"throw new Error('replacement')")
    monkeypatch.setenv("NODE_OPTIONS", "--nonexistent-option-that-would-fail")
    result = await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    assert result.cryptographic_valid is True
    assert not hasattr(result, "authorized") and not hasattr(result, "valid")


@pytest.mark.parametrize("cancel", [False, True])
async def test_timeout_and_cancellation_reap_owned_process(tmp_path, artifacts, cancel):
    pid_file = tmp_path / "owned.pid"
    source = (
        "const fs=require('node:fs');"
        f"fs.writeFileSync({json.dumps(str(pid_file) + '.tmp')},String(process.pid));"
        f"fs.renameSync({json.dumps(str(pid_file) + '.tmp')},{json.dumps(str(pid_file))});\n"
        "const snarkjs={groth16:{verify:async()=>new Promise(()=>{setInterval(()=>{},1000)})}};"
    ).encode()
    verifier = runtime(tmp_path, artifacts, source)
    task = asyncio.create_task(
        verifier.inspect(
            json.dumps(synthetic_proof()).encode(),
            ["0"] * 8,
            expected_signals=["0"] * 8,
            timeout=1,
        )
    )
    async with asyncio.timeout(5):
        while not pid_file.exists():
            await asyncio.sleep(0.01)
    pid = int(pid_file.read_text())
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(ProofInspectionError, match="pairing_timeout"):
            await task
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_bundle_mismatch_and_symlink_rejected(tmp_path):
    source = tmp_path / "source.js"
    source.write_bytes(b"stub")
    with pytest.raises(ProofInspectionError, match="runtime_bundle_mismatch"):
        pinned_bundle(source, "00" * 32)
    link = tmp_path / "link.js"
    link.symlink_to(source)
    with pytest.raises(ProofInspectionError, match="runtime_bundle_unavailable"):
        pinned_bundle(link, hashlib.sha256(b"stub").hexdigest())


@pytest.mark.parametrize("raw", [None, "{}", bytearray(b"{}")])
def test_proof_requires_bytes(raw):
    with pytest.raises(ProofInspectionError, match="^invalid_proof_encoding$"):
        PilotProof.parse(raw)


@pytest.mark.parametrize("pin", [None, "", "AB" * 32, "00" * 31, "00" * 33])
def test_runtime_pin_requires_exact_lowercase_sha256(tmp_path, pin):
    with pytest.raises(ProofInspectionError, match="^invalid_runtime_pin$"):
        pinned_bundle(tmp_path / "missing", pin)


@pytest.mark.parametrize("kind", ["empty", "oversized", "fifo"])
def test_runtime_bundle_must_be_bounded_regular_file(tmp_path, kind):
    path = tmp_path / "bundle"
    if kind == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes(b"" if kind == "empty" else b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ProofInspectionError, match="^invalid_runtime_bundle$"):
        pinned_bundle(path, "00" * 32)


@pytest.mark.parametrize("kind", ["relative", "missing", "directory", "not-executable"])
def test_node_runtime_requires_absolute_executable_file(tmp_path, artifacts, kind):
    node = tmp_path / "node"
    if kind == "relative":
        node = Path("node")
    elif kind == "directory":
        node.mkdir()
    elif kind == "not-executable":
        node.write_text("synthetic")
        node.chmod(0o600)
    with pytest.raises(ProofInspectionError, match="^invalid_node_runtime$"):
        PilotPairingVerifier.load(artifacts, bundle_path=tmp_path / "missing", bundle_sha256="00" * 32, node=node)


@pytest.mark.parametrize("timeout", [0, 61, True, 1.0, "10"])
async def test_invalid_timeout_rejects_before_parsing(tmp_path, artifacts, timeout):
    verifier = runtime(tmp_path, artifacts, b"throw new Error('must not execute')")
    with pytest.raises(ProofInspectionError, match="^invalid_verification_timeout$"):
        await verifier.inspect(b"invalid", [], expected_signals=[], timeout=timeout)


@pytest.mark.parametrize(
    "source",
    [
        b"process.exit(2)",
        b"process.stdout.write('unexpected');process.exit(0)",
        b"const snarkjs={groth16:{verify:async()=>{throw new Error('synthetic-private-detail')}}};",
    ],
)
async def test_runtime_failure_is_bounded_and_private(tmp_path, artifacts, source, caplog):
    verifier = runtime(tmp_path, artifacts, source)
    with pytest.raises(ProofInspectionError, match="^pairing_runtime_failed$"):
        await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    assert "synthetic-private-detail" not in caplog.text


async def test_negative_pairing_result_preserves_profile(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>false}};")
    result = await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    assert result.cryptographic_valid is False
    assert result.manifest_digest == artifacts.manifest.digest
    assert result.proof_profile == artifacts.manifest.proof_profile


async def test_removed_node_runtime_fails_closed(tmp_path, artifacts):
    node = tmp_path / "node"
    node.write_text("#!/bin/sh\nexit 0\n")
    node.chmod(0o700)
    source = tmp_path / "bundle"
    source.write_bytes(b"synthetic")
    verifier = PilotPairingVerifier.load(
        artifacts,
        bundle_path=source,
        bundle_sha256=hashlib.sha256(b"synthetic").hexdigest(),
        node=node,
    )
    node.unlink()
    with pytest.raises(ProofInspectionError, match="^pairing_runtime_unavailable$"):
        await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)


async def test_cancellation_during_spawn_retains_process_ownership(tmp_path, artifacts, monkeypatch):
    verifier = runtime(
        tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>new Promise(()=>{setInterval(()=>{},1000)})}};"
    )
    original_spawn = asyncio.create_subprocess_exec
    spawned = asyncio.Event()
    release = asyncio.Event()
    owned = {}

    async def delayed_spawn(*args, **kwargs):
        process = await original_spawn(*args, **kwargs)
        owned.update(process=process, script=Path(args[2]))
        spawned.set()
        await release.wait()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
    task = asyncio.create_task(
        verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    )
    try:
        async with asyncio.timeout(5):
            await spawned.wait()
            task.cancel()
            # Deliver cancellation while the shielded spawn still owns the child.
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert owned["process"].returncode is not None
        assert owned["script"].exists()
        with pytest.raises(ProcessLookupError):
            os.kill(owned["process"].pid, 0)
    finally:
        release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_process_exit_race_during_cleanup_is_reaped(tmp_path, artifacts, monkeypatch):
    verifier = runtime(
        tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>new Promise(()=>{setInterval(()=>{},1000)})}};"
    )
    original_spawn = asyncio.create_subprocess_exec
    original_killpg = os.killpg
    owned = {}

    async def track_spawn(*args, **kwargs):
        process = await original_spawn(*args, **kwargs)
        owned.update(process=process, script=Path(args[2]))
        return process

    def disappearing_group(pid, sig):
        # Deliver the real signal, then model a group disappearing before killpg.
        original_killpg(pid, sig)
        raise ProcessLookupError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", track_spawn)
    monkeypatch.setattr(os, "killpg", disappearing_group)
    with pytest.raises(ProofInspectionError, match="^pairing_timeout$"):
        await verifier.inspect(
            json.dumps(synthetic_proof()).encode(),
            ["0"] * 8,
            expected_signals=["0"] * 8,
            timeout=1,
        )
    assert owned["process"].returncode is not None
    assert owned["script"].exists()
    with pytest.raises(ProcessLookupError):
        os.kill(owned["process"].pid, 0)


async def test_shared_pairing_limit_rejects_without_spawn_and_holds_slots_through_cleanup(
    tmp_path, artifacts, monkeypatch
):
    assert PAIRING_PROCESS_LIMIT == 2
    original_spawn = asyncio.create_subprocess_exec
    spawned = []
    cleaning = asyncio.Event()
    release_cleanup = asyncio.Event()

    async def track_spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        spawned.append(proc)
        if len(spawned) == 1:
            original_wait = proc.wait

            async def delayed_wait():
                result = await original_wait()
                cleaning.set()
                await release_cleanup.wait()
                return result

            proc.wait = delayed_wait
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", track_spawn)
    tasks = []
    verifiers = []
    proof = json.dumps(synthetic_proof()).encode()
    signals = ["0"] * 8
    for index in range(PAIRING_PROCESS_LIMIT):
        folder = tmp_path / str(index)
        folder.mkdir()
        verifier = runtime(
            folder, artifacts, b"const snarkjs={groth16:{verify:async()=>new Promise(()=>{setInterval(()=>{},1000)})}};"
        )
        verifiers.append(verifier)
        tasks.append(asyncio.create_task(verifier.inspect(proof, signals, expected_signals=signals, timeout=60)))
    extra_folder = tmp_path / "extra"
    extra_folder.mkdir()
    extra = runtime(extra_folder, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    try:
        async with asyncio.timeout(5):
            while len(spawned) < PAIRING_PROCESS_LIMIT:
                await asyncio.sleep(0.01)
            with pytest.raises(PairingCapacityExceeded, match="^pairing_capacity_exceeded$"):
                await extra.inspect(proof, signals, expected_signals=signals)
            assert len(spawned) == PAIRING_PROCESS_LIMIT
            tasks[0].cancel()
            await cleaning.wait()
            tasks[0].cancel()
            await asyncio.sleep(0)
            tasks[0].cancel()
            await asyncio.sleep(0)
            assert not tasks[0].done()
            with pytest.raises(PairingCapacityExceeded):
                await extra.inspect(proof, signals, expected_signals=signals)
            assert len(spawned) == PAIRING_PROCESS_LIMIT
            release_cleanup.set()
            with pytest.raises(asyncio.CancelledError):
                await tasks[0]
            assert (await extra.inspect(proof, signals, expected_signals=signals)).cryptographic_valid
            tasks[1].cancel()
            with pytest.raises(asyncio.CancelledError):
                await tasks[1]
    finally:
        release_cleanup.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    # Both slots are reusable after failures/cancellation, across verifier objects.
    results = await asyncio.gather(*(extra.inspect(proof, signals, expected_signals=signals) for _ in range(2)))
    assert all(result.cryptographic_valid for result in results)
    for verifier in (*verifiers, extra):
        await verifier.aclose()
    for proc in spawned:
        assert proc.returncode is not None
        with pytest.raises(ProcessLookupError):
            os.kill(proc.pid, 0)


# --- pool configuration, single bundle snapshot and worker reuse -----------------


@pytest.mark.parametrize("raw", [None, "", "  "])
def test_pairing_limit_defaults(raw):
    environ = {} if raw is None else {"PAIRING_PROCESS_LIMIT": raw}
    assert pairing_process_limit(environ) == DEFAULT_PAIRING_PROCESS_LIMIT == 2


@pytest.mark.parametrize(
    "raw,expected", [("1", 1), (" 4 ", 4), (str(MAX_PAIRING_PROCESS_LIMIT), MAX_PAIRING_PROCESS_LIMIT)]
)
def test_pairing_limit_accepts_bounded_decimal(raw, expected):
    assert pairing_process_limit({"PAIRING_PROCESS_LIMIT": raw}) == expected


@pytest.mark.parametrize("raw", ["0", "01", "1.0", "-1", "+2", "abc", "2 2", str(MAX_PAIRING_PROCESS_LIMIT + 1)])
def test_pairing_limit_rejects_invalid_values(raw):
    with pytest.raises(PairingConfigurationError, match="between 1 and 32"):
        pairing_process_limit({"PAIRING_PROCESS_LIMIT": raw})


@pytest.mark.parametrize("stage", ["directory", "write"])
def test_runtime_directory_failure_is_bounded(tmp_path, artifacts, monkeypatch, stage):
    source = tmp_path / "bundle"
    source.write_bytes(b"synthetic")
    if stage == "directory":
        monkeypatch.setattr(pv.tempfile, "mkdtemp", Mock(side_effect=OSError))
    else:
        # The pin read uses the first os.open; the runtime write must fail.
        original_open = os.open
        calls = []

        def failing_open(*args, **kwargs):
            calls.append(1)
            if len(calls) > 1:
                raise OSError
            return original_open(*args, **kwargs)

        monkeypatch.setattr(pv.os, "open", failing_open)
        monkeypatch.setattr(pv, "shutil", SimpleNamespace(rmtree=Mock()))
    with pytest.raises(ProofInspectionError, match="^pairing_runtime_unavailable$"):
        PilotPairingVerifier.load(
            artifacts,
            bundle_path=source,
            bundle_sha256=hashlib.sha256(b"synthetic").hexdigest(),
            node=Path(shutil.which("node")),
        )


async def test_bundle_is_written_once_and_workers_are_reused(tmp_path, artifacts, monkeypatch):
    original_spawn = asyncio.create_subprocess_exec
    spawned = []

    async def track_spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        spawned.append(proc)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", track_spawn)
    source = b'const snarkjs={groth16:{verify:async(k,s)=>s[0]==="0"}};'
    verifier = runtime(tmp_path, artifacts, source)
    script = verifier._script
    assert list(verifier._directory.iterdir()) == [script]
    script_bytes = script.read_bytes()
    assert script_bytes.startswith(source) and b"readline.createInterface" in script_bytes
    stage = (script.stat().st_ino, script.stat().st_size, hashlib.sha256(script_bytes).hexdigest())

    first = await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    second = await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["1"] * 8, expected_signals=["1"] * 8)
    assert (first.cryptographic_valid, second.cryptographic_valid) == (True, False)
    assert len(spawned) == 1
    assert (script.stat().st_ino, script.stat().st_size, hashlib.sha256(script.read_bytes()).hexdigest()) == stage
    assert list(verifier._directory.iterdir()) == [script]
    await verifier.aclose()
    assert not verifier._directory.exists()


async def test_pooled_results_match_fresh_verifier(tmp_path, artifacts):
    source = b'const snarkjs={groth16:{verify:async(k,s)=>s[3]==="7"}};'
    pool = runtime(tmp_path, artifacts, source)
    fresh = runtime(tmp_path, artifacts, source)
    proof = json.dumps(synthetic_proof()).encode()
    for signals, expected in ((["7"] * 8, True), (["8"] * 8, False)):
        pooled = await pool.inspect(proof, signals, expected_signals=signals)
        standalone = await fresh.inspect(proof, signals, expected_signals=signals)
        assert pooled.cryptographic_valid is expected
        assert (pooled.cryptographic_valid, pooled.manifest_digest, pooled.proof_profile) == (
            standalone.cryptographic_valid,
            standalone.manifest_digest,
            standalone.proof_profile,
        )
    await pool.aclose()
    await fresh.aclose()


async def test_dead_idle_worker_is_replaced(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    proof = json.dumps(synthetic_proof()).encode()
    signals = ["0"] * 8
    await verifier.inspect(proof, signals, expected_signals=signals)
    (dead,) = verifier.runtime_processes()
    os.killpg(dead.pid, signal.SIGKILL)
    async with asyncio.timeout(5):
        while dead.returncode is None:
            await asyncio.sleep(0.01)
    assert (await verifier.inspect(proof, signals, expected_signals=signals)).cryptographic_valid
    (replacement,) = verifier.runtime_processes()
    assert replacement is not dead
    await verifier.aclose()


async def test_garbage_collected_verifier_reaps_workers_and_directory(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    (proc,) = verifier.runtime_processes()
    directory = verifier._directory
    del verifier
    gc.collect()
    assert not directory.exists()
    async with asyncio.timeout(5):
        while proc.returncode is None:
            await asyncio.sleep(0.01)
    pv._kill_group(proc)  # Already-reaped group is tolerated.


async def test_park_drops_a_worker_that_exited_while_idle(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    dead = pv._Worker(SimpleNamespace(returncode=0))
    verifier._workers.append(dead)
    verifier._park(dead)
    assert dead not in verifier._idle and dead not in verifier._workers
    live = verifier.runtime_processes()
    await verifier.aclose()
    assert live and verifier.runtime_processes() == ()


async def test_exchange_treats_stream_limit_and_eof_as_runtime_failure(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")

    class Stream:
        def __init__(self, outcome):
            self.outcome = outcome

        def write(self, _data):
            pass

        async def drain(self):
            pass

        async def readline(self):
            if isinstance(self.outcome, Exception):
                raise self.outcome
            return self.outcome

    for outcome, returncode, expected in (
        (ValueError("limit"), None, b""),
        (b"", None, b""),
        (b"1\n", 0, b""),
        (b"1\n", None, b"1\n"),
    ):
        worker = SimpleNamespace(proc=SimpleNamespace(stdin=Stream(b""), stdout=Stream(outcome), returncode=returncode))
        assert await verifier._exchange(worker, b"request", 1) == expected


async def test_oversized_payload_fails_before_spawn(tmp_path, artifacts, monkeypatch):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    # strict_json caps the raw key at 64 KiB; widen only this projection to cross the line limit.
    monkeypatch.setattr(pv, "strict_json", lambda _raw, **_kw: {"padding": "x" * MAX_PAIRING_PAYLOAD})
    with pytest.raises(ProofInspectionError, match="^pairing_runtime_failed$"):
        await verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    assert verifier.runtime_processes() == ()


async def test_configured_limit_rebuilds_the_shared_pool(tmp_path, artifacts, monkeypatch):
    monkeypatch.setattr(pv, "PAIRING_PROCESS_LIMIT", 1)
    original_spawn = asyncio.create_subprocess_exec
    spawned = []

    async def track_spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        spawned.append(proc)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", track_spawn)
    verifier = runtime(
        tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>new Promise(()=>{setInterval(()=>{},1000)})}};"
    )
    proof = json.dumps(synthetic_proof()).encode()
    signals = ["0"] * 8
    task = asyncio.create_task(verifier.inspect(proof, signals, expected_signals=signals, timeout=60))
    try:
        async with asyncio.timeout(5):
            while len(spawned) < 1:
                await asyncio.sleep(0.01)
            with pytest.raises(PairingCapacityExceeded):
                await verifier.inspect(proof, signals, expected_signals=signals)
            assert len(spawned) == 1
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    # The single slot stays reusable after each retired worker.
    for _ in range(2):
        with pytest.raises(ProofInspectionError, match="^pairing_timeout$"):
            await verifier.inspect(proof, signals, expected_signals=signals, timeout=1)
    # Two concurrent calls cannot both pass a single configured slot.
    results = await asyncio.gather(
        *(verifier.inspect(proof, signals, expected_signals=signals, timeout=1) for _ in range(2)),
        return_exceptions=True,
    )
    assert sum(isinstance(item, PairingCapacityExceeded) for item in results) == 1
    # Restoring the process limit rebuilds the bound without a restart.
    monkeypatch.setattr(pv, "PAIRING_PROCESS_LIMIT", PAIRING_PROCESS_LIMIT)
    results = await asyncio.gather(
        *(verifier.inspect(proof, signals, expected_signals=signals, timeout=1) for _ in range(2)),
        return_exceptions=True,
    )
    assert all(
        isinstance(item, ProofInspectionError) and not isinstance(item, PairingCapacityExceeded) for item in results
    )
    await verifier.aclose()


async def test_retire_park_and_borrow_tolerate_untracked_workers(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    dead = pv._Worker(SimpleNamespace(returncode=0, pid=1))
    # Retiring a worker already dropped from the tracked set is a no-op removal.
    await verifier._retire({"worker": dead})
    assert dead not in verifier._workers
    # Parking a dead, untracked worker does not raise.
    verifier._park(dead)
    assert verifier._idle == deque()
    # A dead idle worker that is no longer tracked is skipped before spawning.
    verifier._idle.append(dead)
    worker = await verifier._borrow({"worker": None})
    assert worker is not dead and dead not in verifier._idle
    await verifier.aclose()


def test_kill_group_tolerates_an_already_vanished_group(monkeypatch):
    monkeypatch.setattr(pv.os, "killpg", Mock(side_effect=ProcessLookupError))
    pv._kill_group(SimpleNamespace(returncode=None, pid=1))


async def test_aclose_waits_for_an_in_flight_spawn(tmp_path, artifacts):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    directory = verifier._directory
    task = asyncio.create_task(
        verifier.inspect(json.dumps(synthetic_proof()).encode(), ["0"] * 8, expected_signals=["0"] * 8)
    )
    await asyncio.sleep(0)  # Let the spawn register while the directory still exists.
    await verifier.aclose()
    assert not directory.exists()
    assert (await task).cryptographic_valid


async def test_worker_readiness_is_bounded_and_fail_closed(tmp_path, artifacts, monkeypatch):
    verifier = runtime(tmp_path, artifacts, b"const snarkjs={groth16:{verify:async()=>true}};")
    stage = {"line": b"R\n"}

    class Stream:
        async def readline(self):
            if isinstance(stage["line"], Exception):
                raise stage["line"]
            return stage["line"]

    worker = SimpleNamespace(proc=SimpleNamespace(stdout=Stream()))
    await verifier._await_ready(worker)
    stage["line"] = b"X\n"
    with pytest.raises(ProofInspectionError, match="^pairing_runtime_failed$"):
        await verifier._await_ready(worker)
    stage["line"] = OSError()
    with pytest.raises(ProofInspectionError, match="^pairing_runtime_unavailable$"):
        await verifier._await_ready(worker)
    monkeypatch.setattr(pv, "STARTUP_TIMEOUT", 0.01)
    stage["line"] = b""
    worker.proc.stdout = SimpleNamespace(readline=AsyncMock(side_effect=asyncio.TimeoutError))
    with pytest.raises(ProofInspectionError, match="^pairing_timeout$"):
        await verifier._await_ready(worker)
