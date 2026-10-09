"""Native transport/process invariants; synthetic stubs do not establish pairing."""

import asyncio
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from src.prover import pilot_native_prover as module
from src.prover.pilot_native_prover import PilotNativeProver, select_pilot_backend
from src.prover.pilot_prover import PilotProvingError
from tests.unit.test_pilot_artifacts import bundle as bundle
from tests.unit.test_pilot_prover import PRIVATE, SIGNALS, prover, running, wait_pid
from tests.unit.test_pilot_verifier import synthetic_proof

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="requires Linux memory files and parent-death protection"
)


def runtime(pairing=True):
    return (
        "const snarkjs={wtns:{calculate:async(witness,wasm,output)=>{"
        "output.data=Buffer.from(JSON.stringify(witness));}},"
        f"groth16:{{verify:async()=>{str(pairing).lower()}}}}};"
    ).encode()


def executable(root, *, proof=None, signals=SIGNALS, source=None):
    path = root / "synthetic-native"
    if source is None:
        proof = synthetic_proof() if proof is None else proof
        if type(proof) is dict:
            proof = {key: value for key, value in proof.items() if key != "curve"}
        source = (
            "import json,sys\n"
            "from pathlib import Path\n"
            "assert json.loads(Path(sys.argv[2]).read_text())\n"
            f"Path(sys.argv[3]).write_text({json.dumps(json.dumps(proof))})\n"
            f"Path(sys.argv[4]).write_text({json.dumps(json.dumps(signals))})\n"
        )
    path.write_text(f"#!{sys.executable}\n" + source)
    path.chmod(0o700)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def native(bundle, *, source=None, binary_source=None, **kwargs):
    javascript = prover(bundle, runtime() if source is None else source)
    binary, pin = executable(bundle[0], source=binary_source, **kwargs)
    return PilotNativeProver.load(javascript, binary=binary, binary_sha256=pin)


async def test_anonymous_transport_is_sealed_private_and_leaves_no_plaintext_files(bundle, monkeypatch):
    target = native(bundle)
    monkeypatch.setenv("PRIVATE_TEST_ENVIRONMENT", PRIVATE["holder_secret"])
    spawn = asyncio.create_subprocess_exec
    observed = []
    inherited = []

    async def inspect_spawn(*args, **kwargs):
        import fcntl

        assert PRIVATE["holder_secret"] not in repr(args) + repr(kwargs)
        assert "PRIVATE_TEST_ENVIRONMENT" not in kwargs["env"]
        directory = Path(kwargs["cwd"])
        assert sorted(p.name for p in directory.iterdir()) == ["runtime.cjs"]
        assert PRIVATE["holder_secret"].encode() not in (directory / "runtime.cjs").read_bytes()
        assert 1 <= len(json.loads(args[5])) <= 4
        for fd in kwargs["pass_fds"]:
            assert os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:clearproof-")
        if args[6].startswith("/proc/self/fd/"):
            # Executable, key and witness are immutable before native proving.
            for fd in kwargs["pass_fds"][:3]:
                assert fcntl.fcntl(fd, 1034) & 15 == 15
            assert stat.S_IMODE(os.fstat(kwargs["pass_fds"][0]).st_mode) == 0o700
            for fd in kwargs["pass_fds"][1:]:
                assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        inherited.extend(kwargs["pass_fds"])
        observed.append(directory)
        return await spawn(*args, **kwargs)

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", inspect_spawn)
    before = {p.name: p.read_bytes() for p in bundle[0].iterdir()}
    result = await target.prove(PRIVATE, expected_signals=SIGNALS)
    assert result.public_signals == tuple(SIGNALS)
    assert json.loads(result.proof)["curve"] == "bn128"
    assert PRIVATE["holder_secret"] not in repr(result) + repr(target)
    assert len(observed) == 3 and all(not path.exists() for path in observed)
    assert {p.name: p.read_bytes() for p in bundle[0].iterdir()} == before
    for fd in set(inherited):
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("timeout", [True, 0, 121, 1.5])
async def test_invalid_timeouts_fail_before_spawn(bundle, timeout):
    with pytest.raises(PilotProvingError, match="invalid_proving_timeout"):
        await native(bundle).prove(PRIVATE, expected_signals=SIGNALS, timeout=timeout)


@pytest.mark.parametrize("value", [None, [], {"nan": float("nan")}, {"object": object()}])
async def test_invalid_inputs_are_sanitized(bundle, value):
    with pytest.raises(PilotProvingError, match="invalid_proving_input"):
        await native(bundle).prove(value, expected_signals=SIGNALS)


async def test_private_input_size_is_bounded(bundle):
    with pytest.raises(PilotProvingError, match="proving_input_limit"):
        await native(bundle).prove({"secret": "x" * 65536}, expected_signals=SIGNALS)


@pytest.mark.parametrize("attack", ["binary-hash", "binary-size", "binary-symlink", "wasm", "key", "missing"])
async def test_runtime_and_artifacts_are_rechecked_before_each_job(bundle, attack):
    target = native(bundle)
    path = (
        target.binary
        if attack.startswith("binary") or attack == "missing"
        else bundle[0] / ("wasm.bin" if attack == "wasm" else "proving_key.bin")
    )
    if attack in ("binary-symlink", "missing"):
        path.unlink()
        if attack == "binary-symlink":
            path.symlink_to(bundle[0] / "r1cs.bin")
    else:
        path.write_bytes(b"x" * (path.stat().st_size if attack != "binary-size" else 0))
    with pytest.raises(PilotProvingError, match="native_pin_mismatch|native_file_rejected|native_runtime_unavailable"):
        await target.prove(PRIVATE, expected_signals=SIGNALS)


@pytest.mark.parametrize("proof", [[], {}, {**synthetic_proof(), "pi_a": [str(2**256), "2", "1"]}])
async def test_invalid_native_proof_shape_is_rejected(bundle, proof):
    with pytest.raises(PilotProvingError, match="invalid_proving_result"):
        await native(bundle, proof=proof).prove(PRIVATE, expected_signals=SIGNALS)


async def test_native_signal_mismatch_is_rejected_before_pairing(bundle):
    with pytest.raises(PilotProvingError, match="proving_signal_mismatch"):
        await native(bundle, signals=["2"] * 8).prove(PRIVATE, expected_signals=SIGNALS)


async def test_independent_pairing_failure_cannot_fall_back_or_return_a_proof(bundle):
    with pytest.raises(PilotProvingError, match="^native_runtime_failed$"):
        await native(bundle, source=runtime(pairing=False)).prove(PRIVATE, expected_signals=SIGNALS)


@pytest.mark.parametrize("size", [0, 9000])
async def test_native_output_is_size_bounded(bundle, size):
    source = f"import sys\nfrom pathlib import Path\nPath(sys.argv[3]).write_bytes(b'x'*{size})\n"
    with pytest.raises(PilotProvingError, match="native_output_limit"):
        await native(bundle, binary_source=source).prove(PRIVATE, expected_signals=SIGNALS)


@pytest.mark.parametrize("cancel", [False, True])
async def test_owned_native_process_is_reaped_before_timeout_or_cancellation_returns(bundle, cancel):
    pidfile = bundle[0] / "owned-native-pid"
    source = (
        "import os,time\nfrom pathlib import Path\n"
        f"p=Path({str(pidfile)!r})\nt=p.with_suffix('.tmp')\n"
        "t.write_text(str(os.getpid()))\nt.replace(p)\n"
        "time.sleep(60)\n"
    )
    javascript = prover(bundle, runtime())
    binary, pin = executable(bundle[0], source=source)
    target = PilotNativeProver.load(javascript, binary=binary, binary_sha256=pin)
    task = asyncio.create_task(target.prove(PRIVATE, expected_signals=SIGNALS, timeout=5 if cancel else 1))
    pid = await wait_pid(pidfile)
    assert running(pid)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(PilotProvingError, match="proving_timeout"):
            await task
    assert not running(pid)


@pytest.mark.parametrize("cpus", [[], (), (True,), (-1,), (999999,), (0, 0), (0, 1, 2, 3, 4)])
def test_invalid_cpu_configuration_is_rejected(bundle, cpus):
    javascript = prover(bundle, runtime())
    binary, pin = executable(bundle[0])
    with pytest.raises(PilotProvingError, match="invalid_native_cpu_affinity"):
        PilotNativeProver.load(javascript, binary=binary, binary_sha256=pin, cpus=cpus)


@pytest.mark.parametrize("pin", [None, "", "a" * 63, "X" * 64, "0" * 64])
def test_binary_pin_is_required_and_verified(bundle, pin):
    javascript = prover(bundle, runtime())
    binary, _ = executable(bundle[0])
    with pytest.raises(PilotProvingError, match="invalid_native_pin|native_pin_mismatch"):
        PilotNativeProver.load(javascript, binary=binary, binary_sha256=pin)


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_discovery_preserves_javascript_outside_linux(bundle, monkeypatch, platform):
    javascript = prover(bundle, runtime())
    monkeypatch.setattr(module.sys, "platform", platform)
    assert select_pilot_backend(javascript, binary="absent") is javascript
    with pytest.raises(PilotProvingError, match="linux_native_prover_required"):
        PilotNativeProver.load(javascript, binary="absent", binary_sha256="0" * 64)


def test_absent_or_unpinned_automatic_discovery_preserves_javascript(bundle, monkeypatch):
    javascript = prover(bundle, runtime())
    monkeypatch.delenv("CLEARPROOF_RAPIDSNARK_BIN", raising=False)
    monkeypatch.delenv("CLEARPROOF_RAPIDSNARK_SHA256", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    assert select_pilot_backend(javascript) is javascript
    monkeypatch.setattr(module.shutil, "which", lambda name: "/public-unpinned-prover")
    assert select_pilot_backend(javascript) is javascript
    with pytest.raises(PilotProvingError, match="native_binary_pin_required"):
        select_pilot_backend(javascript, binary="/public-unpinned-prover")


def test_operator_environment_and_pinned_path_discovery_select_native(bundle, monkeypatch):
    javascript = prover(bundle, runtime())
    binary, pin = executable(bundle[0])
    monkeypatch.setenv("CLEARPROOF_RAPIDSNARK_BIN", str(binary))
    monkeypatch.setenv("CLEARPROOF_RAPIDSNARK_SHA256", pin)
    selected = select_pilot_backend(javascript)
    assert isinstance(selected, PilotNativeProver) and selected.binary == binary
    monkeypatch.delenv("CLEARPROOF_RAPIDSNARK_BIN")
    monkeypatch.setattr(module.shutil, "which", lambda name: str(binary) if name == "prover" else None)
    assert isinstance(select_pilot_backend(javascript), PilotNativeProver)


def test_native_fingerprint_binds_binary_and_js_bytes_and_allows_replica_resource_placement(bundle):
    target = native(bundle)
    assert replace(target, binary_sha256="0" * 64).runtime_digest != target.runtime_digest
    assert replace(target, cpus=(target.cpus[0],)).runtime_digest == target.runtime_digest
    assert replace(target, javascript=replace(target.javascript, heap_mb=256)).runtime_digest == target.runtime_digest
    changed_js = replace(target.javascript, verifier=replace(target.verifier, bundle=b"changed-public-runtime"))
    assert replace(target, javascript=changed_js).runtime_digest != target.runtime_digest


def test_javascript_backend_type_and_missing_binary_are_rejected(bundle):
    with pytest.raises(PilotProvingError, match="invalid_native_javascript_backend"):
        PilotNativeProver.load(object(), binary="absent", binary_sha256="0" * 64)
    with pytest.raises(PilotProvingError, match="native_binary_unavailable"):
        PilotNativeProver.load(prover(bundle, runtime()), binary="absent", binary_sha256="0" * 64)


@pytest.mark.parametrize("case", ["missing", "failed"])
def test_unavailable_kernel_memory_api_is_reported_without_inputs(monkeypatch, case):
    from types import SimpleNamespace

    library = SimpleNamespace()
    if case == "failed":
        library.memfd_create = lambda *args: -1
    monkeypatch.setattr(module.ctypes, "CDLL", lambda *args, **kwargs: library)
    with pytest.raises(OSError, match="Anonymous Linux memory"):
        module._memfd("public-test-name")


@pytest.mark.parametrize("failure", ["truncated", "zero-write", "growing", "fifo", "size-limit", "expected-size"])
def test_snapshot_io_failures_close_owned_descriptors(bundle, monkeypatch, failure):
    path = bundle[0] / "wasm.bin"
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    maximum, size = 1000, None
    if failure == "truncated":
        monkeypatch.setattr(module.os, "read", lambda *args: b"")
    elif failure == "zero-write":
        monkeypatch.setattr(module.os, "write", lambda *args: 0)
    elif failure == "growing":
        read = os.read

        def growing(fd, count):
            return b"extra" if count == 1 else read(fd, count)

        monkeypatch.setattr(module.os, "read", growing)
    elif failure == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif failure == "size-limit":
        maximum = 1
    else:
        size = 1
    descriptors = []
    with pytest.raises(PilotProvingError, match="native_file_rejected|native_pin_mismatch"):
        with module._memory_files() as descriptors:
            module._snapshot(path, pin, maximum, descriptors, size=size)
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_snapshot_handles_short_writes_and_seals_the_snapshot(bundle, monkeypatch):
    path = bundle[0] / "wasm.bin"
    original = os.write
    monkeypatch.setattr(module.os, "write", lambda fd, block: original(fd, block[:3]))
    with module._memory_files() as descriptors:
        fd = module._snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest(), 1000, descriptors)
        assert module._read(fd, 1000) == path.read_bytes()
        with pytest.raises(OSError):
            os.write(fd, b"replacement")


def test_native_binary_must_have_executable_permissions(bundle):
    javascript = prover(bundle, runtime())
    binary, pin = executable(bundle[0])
    binary.chmod(0o600)
    with pytest.raises(PilotProvingError, match="native_file_rejected"):
        PilotNativeProver.load(javascript, binary=binary, binary_sha256=pin)


def test_memory_file_permission_failure_closes_the_new_descriptor(monkeypatch):
    created = []

    def failed(fd, mode):
        created.append(fd)
        raise OSError("synthetic-permission-error")

    monkeypatch.setattr(module.os, "fchmod", failed)
    with pytest.raises(OSError, match="synthetic-permission-error"):
        module._memfd("public-test-name")
    for fd in created:
        with pytest.raises(OSError):
            os.fstat(fd)


async def test_repeated_cancellation_waits_for_owned_operation_to_settle():
    completion = asyncio.Event()

    async def owned():
        await completion.wait()
        return "done"

    task = asyncio.create_task(owned())
    settling = asyncio.create_task(module._settled(task))
    await asyncio.sleep(0)
    settling.cancel()
    await asyncio.sleep(0)
    settling.cancel()
    await asyncio.sleep(0)
    assert not task.cancelled() and not settling.done()
    completion.set()
    assert await settling == ("done", True)


async def test_cancel_race_with_completed_owned_operation_is_reconciled(monkeypatch):
    task = asyncio.create_task(asyncio.sleep(0, result="created"))
    await task

    async def cancelled(task):
        raise asyncio.CancelledError

    monkeypatch.setattr(module.asyncio, "shield", cancelled)
    assert await module._settled(task) == ("created", True)


async def test_cancellation_during_delayed_spawn_reaps_created_child(bundle, monkeypatch):
    javascript = prover(bundle, runtime())
    binary, pin = executable(bundle[0])
    target = PilotNativeProver.load(javascript, binary=binary, binary_sha256=pin)
    created = asyncio.Event()
    release = asyncio.Event()
    original = asyncio.create_subprocess_exec
    processes = []

    async def delayed(*args, **kwargs):
        proc = await original(*args, **kwargs)
        processes.append(proc)
        created.set()
        await release.wait()
        return proc

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", delayed)
    task = asyncio.create_task(target.prove(PRIVATE, expected_signals=SIGNALS))
    await created.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert processes[0].returncode is not None and not running(processes[0].pid)


@pytest.mark.parametrize("phase", ["witness-result", "witness-empty", "pairing-result", "bad-json"])
async def test_defensive_phase_results_are_rejected(bundle, monkeypatch, phase):
    target = native(bundle)
    original = module._run

    async def altered(*args, **kwargs):
        command = args[0]
        pins = json.loads(command[-1]) if command[0] == str(target.verifier.node) else None
        if pins and pins["mode"] == "witness":
            if phase == "witness-result":
                return b"unexpected"
            if phase == "witness-empty":
                return b"1"
        if pins and pins["mode"] == "verify" and phase == "pairing-result":
            return b"unexpected"
        result = await original(*args, **kwargs)
        if pins is None and phase == "bad-json":
            proof = kwargs["descriptors"][-2]
            os.ftruncate(proof, 0)
            os.lseek(proof, 0, os.SEEK_SET)
            os.write(proof, b"not-json")
        return result

    monkeypatch.setattr(module, "_run", altered)
    with pytest.raises(
        PilotProvingError,
        match="native_witness_failed|native_witness_limit|native_pairing_failed|invalid_proving_result",
    ):
        await target.prove(PRIVATE, expected_signals=SIGNALS)


@pytest.mark.parametrize("race", ["already-gone", "cancel-during-reap"])
async def test_cleanup_races_cannot_leave_an_owned_native_process_running(bundle, monkeypatch, race):
    pidfile = bundle[0] / "native-cleanup-pid"
    source = (
        "import os,time\nfrom pathlib import Path\n"
        f"p=Path({str(pidfile)!r})\nt=p.with_suffix('.tmp')\n"
        "t.write_text(str(os.getpid()))\nt.replace(p)\ntime.sleep(60)\n"
    )
    target = native(bundle, binary_source=source)
    reaping, release = asyncio.Event(), asyncio.Event()
    original_spawn = asyncio.create_subprocess_exec
    original_kill = os.killpg

    async def spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        if args[6].startswith("/proc/self/fd/") and race == "cancel-during-reap":
            wait = proc.wait

            async def delayed_wait():
                reaping.set()
                await release.wait()
                return await wait()

            proc.wait = delayed_wait
        return proc

    def disappeared(pid, signal):
        original_kill(pid, signal)
        raise ProcessLookupError

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    if race == "already-gone":
        monkeypatch.setattr(module.os, "killpg", disappeared)
    task = asyncio.create_task(target.prove(PRIVATE, expected_signals=SIGNALS))
    pid = await wait_pid(pidfile)
    task.cancel()
    if race == "cancel-during-reap":
        await reaping.wait()
        task.cancel()
        await asyncio.sleep(0)
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not running(pid)


@pytest.mark.parametrize("case", ["pid-one", "orphan-before", "orphan-after", "guard-failed"])
def test_native_launcher_checks_parent_and_sets_cpu_dump_and_file_bounds(monkeypatch, case):
    import ctypes
    import resource
    from types import SimpleNamespace
    from unittest.mock import Mock

    parents = iter([2 if case == "orphan-before" else 1, 2 if case == "orphan-after" else 1])
    execute, limits, affinity = Mock(), Mock(), Mock()
    monkeypatch.setattr(os, "getppid", lambda: next(parents))
    monkeypatch.setattr(os, "execv", execute)
    monkeypatch.setattr(os, "sched_setaffinity", affinity)
    monkeypatch.setattr(resource, "setrlimit", limits)
    monkeypatch.setattr(
        ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(prctl=lambda *args: 1 if case == "guard-failed" else 0)
    )
    monkeypatch.setattr(sys, "argv", ["launcher", "1", "[2,4]", "/public-executable", "public-argument"])
    if case == "pid-one":
        exec(module._GUARD)
        execute.assert_called_once_with("/public-executable", ["/public-executable", "public-argument"])
        affinity.assert_called_once_with(0, [2, 4])
        limits.assert_any_call(resource.RLIMIT_CORE, (0, 0))
        limits.assert_any_call(resource.RLIMIT_FSIZE, (module.MAX_WITNESS, module.MAX_WITNESS))
    else:
        with pytest.raises(SystemExit) as error:
            exec(module._GUARD)
        assert error.value.code == 2
        execute.assert_not_called()


async def test_native_child_dies_when_its_worker_is_sigkilled(bundle):
    import signal

    pidfile = bundle[0] / "native-crash-pid"
    source = (
        "import os,time\nfrom pathlib import Path\n"
        f"p=Path({str(pidfile)!r})\nt=p.with_suffix('.tmp')\n"
        "t.write_text(str(os.getpid()))\nt.replace(p)\ntime.sleep(60)\n"
    )
    target = native(bundle, binary_source=source)
    root, _, pin = bundle
    script = root / "public-worker.py"
    script.write_text(
        "import asyncio,json,sys\nfrom pathlib import Path\n"
        f"sys.path.insert(0,{str(Path(__file__).resolve().parents[2])!r})\n"
        "from src.prover.pilot_prover import PilotProver\n"
        "from src.prover.pilot_native_prover import PilotNativeProver\n"
        f"js=PilotProver.load(Path({str(root)!r}),trusted_digest={pin!r},"
        f"bundle_path=Path({str(root / 'runtime.js')!r}),"
        f"bundle_sha256={hashlib.sha256(target.verifier.bundle).hexdigest()!r},"
        f"node=Path({shutil.which('node')!r}))\n"
        f"native=PilotNativeProver.load(js,binary=Path({str(target.binary)!r}),"
        f"binary_sha256={target.binary_sha256!r})\n"
        f"asyncio.run(native.prove(json.loads(sys.stdin.read()),expected_signals={SIGNALS!r}))\n"
    )
    worker = subprocess.Popen(
        [sys.executable, str(script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        env={name: value for name, value in os.environ.items() if name != "PYTHONPATH"},
    )
    try:
        worker.stdin.write(json.dumps(PRIVATE).encode())
        worker.stdin.close()
        pid = await wait_pid(pidfile)
        assert running(pid)
        # The worker may exit between checks on loaded CI runners; sending a
        # signal or waiting on an already-reaped PID raises ProcessLookupError,
        # which is the test's desired end state (the child is already dead).
        try:
            worker.send_signal(signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            worker.wait(timeout=5)
        except ProcessLookupError:
            pass
        async with asyncio.timeout(5):
            while running(pid):
                await asyncio.sleep(0.01)
    finally:
        if worker.poll() is None:
            try:
                worker.kill()
            except ProcessLookupError:
                pass
            try:
                worker.wait(timeout=5)
            except ProcessLookupError:
                pass
