"""Deterministic independent-state replay with explicit unresolved evidence."""

import itertools

import pytest

from src.reconciliation.events import TransferEvent, TransferScope, reconcile


@pytest.fixture
def scope():
    return TransferScope(
        tenant_id="tenant-a", transfer_id="transfer-a", chain_id="1", registry_address="0x" + "12" * 20
    )


def event(scope, dimension, state, sequence=1, source="source-a", **updates):
    value = dict(
        scope=scope,
        source_id=source,
        source_event_id=f"{dimension}-{sequence}",
        source_sequence=sequence,
        dimension=dimension,
        state=state,
        occurred_at=100 + sequence,
        ingested_at=110 + sequence,
        evidence_digest="ab" * 32,
    )
    if dimension == "chain" and state != "pending":
        value.update(block_number=42, block_hash="cd" * 32)
    return TransferEvent(**{**value, **updates})


def test_reordered_deliveries_and_retries_converge(scope):
    events = (
        event(scope, "custody", "created"),
        event(scope, "custody", "submitted", 2),
        event(scope, "custody", "failed", 3),
        event(scope, "compliance", "approved"),
    )
    original = tuple(e.model_dump_json() for e in events)
    expected = reconcile(scope, events, now=200).model_dump_json()
    for order in itertools.permutations(events):
        assert reconcile(scope, order, now=200).model_dump_json() == expected
    retry = TransferEvent.model_validate({**events[0].model_dump(), "ingested_at": 190})
    assert reconcile(scope, events + (retry,), now=200).model_dump_json() == expected
    assert tuple(e.model_dump_json() for e in events) == original
    report = reconcile(scope, events, now=200)
    assert report.states["custody"] == "failed" and report.states["compliance"] == "approved"
    assert report.findings[0].reason == "settlement-failed"


def test_approval_timeout_and_missing_evidence_are_separate(scope):
    events = (
        event(scope, "compliance", "approved"),
        event(scope, "counterparty", "timeout"),
        event(scope, "chain", "finalized"),
    )
    report = reconcile(scope, events, now=200)
    assert {f.reason for f in report.findings} == {
        "approval-without-submission",
        "counterparty-timeout",
        "settled-with-unresolved-evidence",
    }
    assert all(f.since == 101 and f.age_seconds == 99 for f in report.findings)
    assert report.states["proof"] == report.states["evidence"] == "unknown"
    assert report.source_authenticity == "caller-required"


def test_reorganization_and_changed_canonical_block_supersede_finality(scope):
    finalized = event(scope, "chain", "finalized")
    reorged = event(scope, "chain", "reorged", 2, block_hash="ef" * 32)
    report = reconcile(scope, (reorged, finalized), now=200)
    assert report.states["chain"] == "reorged"
    assert [f.reason for f in report.findings] == ["chain-reorganization"]
    other = event(scope, "chain", "finalized", source="source-b", block_hash="99" * 32)
    conflict = reconcile(scope, (finalized, other), now=200)
    assert conflict.states["chain"] == "conflict"
    assert conflict.findings[0].reason == "source-conflict-chain"


def test_complete_report_does_not_infer_authorization(scope):
    events = tuple(
        event(scope, dim, state)
        for dim, state in {
            "compliance": "approved",
            "proof": "valid",
            "counterparty": "accepted",
            "custody": "submitted",
            "chain": "finalized",
            "evidence": "complete",
        }.items()
    )
    report = reconcile(scope, events, now=200)
    assert report.findings == ()
    assert "authorized" not in report.model_dump() and "consume" not in report.model_dump()
    assert report.scope_digest != TransferScope.model_validate({**scope.model_dump(), "tenant_id": "tenant-b"}).digest


@pytest.mark.parametrize(
    "change",
    [
        {"state": "failed"},
        {"evidence_digest": "ff" * 32},
        {"source_event_id": "different-id"},
    ],
)
def test_conflicting_identities_or_sequences_reject(scope, change):
    original = event(scope, "custody", "submitted")
    altered = TransferEvent.model_validate({**original.model_dump(), **change})
    with pytest.raises(ValueError, match="Conflicting"):
        reconcile(scope, (original, altered), now=200)


def test_unknown_states_future_observations_and_scope_substitution_reject(scope):
    with pytest.raises(ValueError):
        event(scope, "proof", "approved")
    with pytest.raises(ValueError):
        event(scope, "proof", "valid", occurred_at=300)
    with pytest.raises(ValueError):
        event(scope, "chain", "finalized", block_hash=None)
    foreign = TransferScope.model_validate({**scope.model_dump(), "tenant_id": "tenant-b"})
    with pytest.raises(ValueError, match="scope"):
        reconcile(scope, (event(foreign, "proof", "valid"),), now=200)
    with pytest.raises(ValueError, match="clock"):
        reconcile(scope, (event(scope, "proof", "valid"),), now=100)
    with pytest.raises(ValueError, match="256"):
        reconcile(scope, (event(scope, "proof", "valid"),) * 257, now=200)
    assert all(state == "unknown" for state in reconcile(scope, (), now=200).states.values())


@pytest.mark.parametrize(
    "dimension,state,reason",
    [
        ("compliance", "denied", "compliance-denied"),
        ("compliance", "review", "compliance-review-required"),
        ("proof", "invalid", "proof-invalid"),
        ("counterparty", "rejected", "counterparty-rejected"),
        ("counterparty", "information-requested", "counterparty-information-requested"),
        ("custody", "cancelled", "custody-cancelled"),
        ("evidence", "incomplete", "evidence-incomplete"),
    ],
)
def test_adverse_observations_stay_in_queue(scope, dimension, state, reason):
    report = reconcile(scope, (event(scope, dimension, state),), now=200)
    assert [finding.reason for finding in report.findings] == [reason]
    assert report.findings[0].age_seconds == 99
    assert report.findings[0].owner and report.findings[0].next_action


def test_custody_completion_requires_separate_finality_observation(scope):
    completed = event(scope, "custody", "completed")
    report = reconcile(scope, (completed,), now=200)
    assert report.states["chain"] == "unknown"
    assert [f.reason for f in report.findings] == ["custody-completed-without-finality"]
    report = reconcile(scope, (completed, event(scope, "chain", "finalized")), now=200)
    assert "custody-completed-without-finality" not in {f.reason for f in report.findings}
    assert "settled-with-unresolved-evidence" in {f.reason for f in report.findings}


def test_same_source_block_replacement_cannot_silently_keep_finality(scope):
    original = event(scope, "chain", "finalized")
    replaced = event(scope, "chain", "finalized", 2, block_hash="ef" * 32, block_number=43)
    forward = reconcile(scope, (original, replaced), now=200)
    backward = reconcile(scope, (replaced, original), now=200)
    assert forward == backward
    assert "canonical-block-observation-changed" in {f.reason for f in forward.findings}
    changed = next(f for f in forward.findings if f.reason == "canonical-block-observation-changed")
    assert changed.since == 102 and changed.age_seconds == 98
    unchanged = event(scope, "chain", "finalized", 2)
    assert "canonical-block-observation-changed" not in {
        f.reason for f in reconcile(scope, (original, unchanged), now=200).findings
    }


def test_repeated_observation_does_not_reset_block_change_age(scope):
    original = event(scope, "chain", "finalized")
    replaced = event(scope, "chain", "confirmed", 2, block_hash="ef" * 32)
    repeated = event(scope, "chain", "finalized", 3, block_hash="ef" * 32)
    report = reconcile(scope, (repeated, original, replaced), now=200)
    changed = next(f for f in report.findings if f.reason == "canonical-block-observation-changed")
    assert changed.since == 102
