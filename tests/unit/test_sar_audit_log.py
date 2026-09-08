"""Hash-chain continuity and isolation of the in-memory examination API."""

import hashlib

import pytest

from src.sar.audit_log import AuditEntry, AuditLog


@pytest.fixture
def log():
    return AuditLog()


def test_append_hashes_payload_and_preserves_explicit_epoch(log, monkeypatch):
    monkeypatch.setattr("src.sar.audit_log.time.time", lambda: 1000)
    first = log.append("proof_generated", "synthetic", "a", b"synthetic-private-input", timestamp=0)
    second = log.append("review", "synthetic", "b", b"other")
    assert first.timestamp == 0
    assert second.timestamp == 1000
    assert first.sequence_number == 0
    assert second.sequence_number == 1
    assert second.prev_entry_hash == first.entry_hash
    assert first.data_hash == hashlib.sha256(b"synthetic-private-input").hexdigest()
    assert "synthetic-private-input" not in first.model_dump_json()
    assert len(log) == 2
    assert log.verify_chain()


@pytest.mark.parametrize("accessor", ["append", "entries", "transaction"])
def test_returned_records_cannot_mutate_retained_entries(log, accessor):
    appended = log.append("proof_generated", "synthetic", "a", b"payload")
    entry = (
        appended
        if accessor == "append"
        else log.entries[0]
        if accessor == "entries"
        else log.get_entries_for_transaction("a")[0]
    )
    entry.data_hash = "0" * 64
    entry.actor = "changed"
    assert log.entries[0].actor == "synthetic"
    assert log.verify_chain()


@pytest.mark.parametrize("corruption", ["predecessor", "hash", "sequence"])
def test_integrity_rejects_corrupted_internal_records(log, corruption):
    log.append("proof_generated", "synthetic", "a", b"payload")
    entry = log._entries[0]
    if corruption == "predecessor":
        entry.prev_entry_hash = "1" * 64
    elif corruption == "hash":
        entry.entry_hash = "1" * 64
    else:
        entry.sequence_number = 5
        entry.entry_hash = AuditEntry.compute_hash(entry.data_hash, entry.prev_entry_hash, entry.sequence_number)
    assert not log.verify_chain()


def test_examination_filtering_empty_chain_and_detached_exports(log):
    assert log.verify_chain()
    assert log.export_examination_bundle()["entries"] == []
    log.append("proof_generated", "synthetic", "", b"first")
    log.append("review", "synthetic", "a", b"second")
    complete = log.export_examination_bundle()
    assert complete["total_entries"] == complete["exported_entries"] == 2
    assert complete["chain_valid"] is True
    for reference in ("", "a"):
        filtered = log.export_examination_bundle(reference)
        assert filtered["exported_entries"] == 1
        assert filtered["entries"][0]["transaction_ref"] == reference
        filtered["entries"][0]["actor"] = "changed"
    assert all(entry.actor == "synthetic" for entry in log.entries)
    snapshot = log.entries
    snapshot.clear()
    assert len(log) == 2
    assert log.get_entries_for_transaction("absent") == []
