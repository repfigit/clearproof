"""Audit mirror persistence and failure paths with synthetic event metadata."""

import json
from unittest.mock import patch

import pytest

from src.chain.audit_mirror import AuditMirror


def test_default_environment_empty_file_and_blank_lines(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AUDIT_MIRROR_PATH", raising=False)
    assert AuditMirror().verify_integrity()
    path = tmp_path / "configured.jsonl"
    monkeypatch.setenv("AUDIT_MIRROR_PATH", str(path))
    path.touch()
    assert AuditMirror().verify_integrity()
    path.write_text("\n\n")
    mirror = AuditMirror()
    mirror.record("synthetic", {})
    assert mirror.verify_integrity()


def test_reopen_and_large_records_preserve_the_exact_tail_hash(tmp_path):
    path = tmp_path / "mirror.jsonl"
    mirror = AuditMirror(str(path))
    mirror.record("proof_recorded", {"synthetic_padding": "x" * 10000}, block_number=123, tx_hash="0xabc")
    AuditMirror(str(path)).record("credential_revoked", {"commitment": "123"})
    assert AuditMirror(str(path)).verify_integrity()
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[0]["block_number"] == 123
    assert records[0]["tx_hash"] == "0xabc"
    assert records[1]["data"] == {"commitment": "123"}


def test_failed_write_does_not_advance_in_memory_chain(tmp_path):
    mirror = AuditMirror(str(tmp_path / "mirror.jsonl"))
    mirror.record("first", {})
    with patch("builtins.open", side_effect=PermissionError("synthetic write failure")):
        with pytest.raises(PermissionError):
            mirror.record("not-written", {})
    mirror.record("second", {})
    assert mirror.verify_integrity()


def test_unreadable_tail_cannot_silently_restart_a_chain(tmp_path):
    path = tmp_path / "mirror.jsonl"
    AuditMirror(str(path)).record("first", {})
    with patch("builtins.open", side_effect=PermissionError("synthetic read failure")):
        with pytest.raises(PermissionError):
            AuditMirror(str(path))


@pytest.mark.parametrize("contents", ['not-json\n', '[]\n', '{"prev_hash":"SYNTHETIC-PRIVATE-MARKER"}\n'])
def test_corruption_rejected_without_logging_untrusted_values(tmp_path, contents, caplog):
    path = tmp_path / "mirror.jsonl"
    mirror = AuditMirror(str(path))
    path.write_text(contents)
    assert mirror.verify_integrity() is False
    assert "SYNTHETIC-PR" not in caplog.text


def test_read_failure_returns_false(tmp_path):
    path = tmp_path / "mirror.jsonl"
    mirror = AuditMirror(str(path))
    mirror.record("first", {})
    with patch("builtins.open", side_effect=PermissionError("synthetic read failure")):
        assert mirror.verify_integrity() is False


def test_mutating_an_earlier_record_breaks_the_link(tmp_path):
    path = tmp_path / "mirror.jsonl"
    mirror = AuditMirror(str(path))
    mirror.record("first", {})
    mirror.record("second", {})
    contents = path.read_text().replace('"first"', '"changed"')
    path.write_text(contents)
    assert mirror.verify_integrity() is False


def test_interleaved_instances_extend_one_chain(tmp_path):
    path = tmp_path / "mirror.jsonl"
    first = AuditMirror(str(path))
    second = AuditMirror(str(path))
    first.record("first", {})
    second.record("second", {})
    first.record("third", {})
    assert first.verify_integrity()


def _append_worker(path, worker, barrier):
    mirror = AuditMirror(path)
    barrier.wait(timeout=20)
    for sequence in range(12):
        mirror.record("synthetic", {"worker": worker, "sequence": sequence})


def test_independent_processes_append_without_forks_or_lost_records(tmp_path):
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    path = tmp_path / "mirror.jsonl"
    context = multiprocessing.get_context("spawn")
    with context.Manager() as manager, ProcessPoolExecutor(max_workers=4, mp_context=context) as executor:
        barrier = manager.Barrier(4)
        results = [executor.submit(_append_worker, str(path), worker, barrier) for worker in range(4)]
        for result in results:
            result.result(timeout=30)
    assert AuditMirror(str(path)).verify_integrity()
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 48
    assert {(record["data"]["worker"], record["data"]["sequence"]) for record in records} == {
        (worker, sequence) for worker in range(4) for sequence in range(12)
    }


def test_incomplete_trailing_record_is_not_extended(tmp_path):
    path = tmp_path / "mirror.jsonl"
    mirror = AuditMirror(str(path))
    path.write_bytes(b'{"interrupted":')
    with pytest.raises(ValueError, match="incomplete trailing record"):
        mirror.record("next", {})
    assert path.read_bytes() == b'{"interrupted":'


def test_lock_timeout_never_appends_without_ownership(tmp_path):
    import portalocker

    path = tmp_path / "mirror.jsonl"
    mirror = AuditMirror(str(path), lock_timeout=0)
    mirror.record("first", {})
    original = path.read_bytes()
    with portalocker.Lock(path, "a+b", timeout=0):
        with pytest.raises(portalocker.exceptions.AlreadyLocked):
            mirror.record("contender", {})
        assert mirror.verify_integrity() is False
    assert path.read_bytes() == original
    mirror.record("after-release", {})
    assert mirror.verify_integrity()
