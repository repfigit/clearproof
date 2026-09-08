"""Canonical proof parsing and actual owned-runtime lifecycle checks."""

import asyncio
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from src.prover.pilot_artifacts import InspectedArtifacts, PilotArtifactManifest
from src.prover.pilot_compliance import PUBLIC_SIGNALS
from src.prover.pilot_verifier import (
    BASE_FIELD,
    PilotPairingVerifier,
    PilotProof,
    ProofInspectionError,
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
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert owned["process"].returncode is not None
        assert not owned["script"].parent.exists()
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
    assert not owned["script"].parent.exists()
    with pytest.raises(ProcessLookupError):
        os.kill(owned["process"].pid, 0)
