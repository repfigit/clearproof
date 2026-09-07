"""Real OpenSSL timestamp responses, verified offline with independently pinned trust."""

import json
import time
from pathlib import Path

import pytest

from src.protocol.decision_attestation import DecisionAttestation, SignedDecision
from src.prover.history_timing import TimestampTrust, timestamp_request
from tests.timestamp_fixture import timestamp_authority


@pytest.fixture
def case(tmp_path):
    root, leaf, issue = timestamp_authority(tmp_path)
    now = int(time.time())
    fixture = json.loads((Path(__file__).parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    context = fixture["records"][1]["value"]
    signed = SignedDecision(
        statement=DecisionAttestation(
            tenant_id=context["tenant_id"],
            chain_id=int(context["deployment_chain_id"]),
            registry_address=context["deployment_address"],
            receipt_digest="ab" * 32,
            evidence_digest="cd" * 32,
            context_digest="ef" * 32,
            decision_at=now - 2,
            key_id="aa" * 32,
        ),
        signature="bb" * 64,
    )
    config = dict(
        certificate=leaf, roots=(root,), policy_oid="1.2.3.4", not_before=now - 100, not_after=now + 86400 * 30
    )
    raw = issue(timestamp_request(signed))
    return signed, raw, now, config


def test_real_timestamp_offline_and_after_certificate_expiry(case, monkeypatch):
    signed, raw, now, config = case
    import socket

    def no_network(*args, **kwargs):
        raise AssertionError("Offline timestamp review attempted network access")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    trust = TimestampTrust(**config)
    observation = trust.verify_decision_window(raw, signed, expires_at=now + 300, verified_at=now + 86400 * 10)
    assert observation.accuracy_us == 1000000
    assert (now - 1) * 1000000 <= observation.generated_at_us <= (now + 10) * 1000000
    assert observation.policy_oid == "1.2.3.4"


def test_timestamp_cannot_be_rebound_or_tampered(case):
    signed, raw, now, config = case
    trust = TimestampTrust(**config)
    changed = SignedDecision(statement=signed.statement, signature="cc" * 64)
    for body, decision in ((raw, changed), (raw[:-1] + bytes([raw[-1] ^ 1]), signed), (raw + b"junk", signed)):
        with pytest.raises(ValueError):
            trust.verify(body, decision, verified_at=now + 20)


@pytest.mark.parametrize(
    "changes",
    [
        {"policy_oid": "1.2.3.5"},
        {"max_accuracy_us": 999999},
        {"compromised_at": 1},
        {"not_after": 2, "not_before": 1},
    ],
)
def test_independent_authority_constraints(case, changes):
    signed, raw, now, config = case
    with pytest.raises(ValueError):
        TimestampTrust(**{**config, **changes}).verify(raw, signed, verified_at=now + 20)


def test_wrong_pinned_certificate(case, tmp_path):
    signed, raw, now, config = case
    other_root, other, _ = timestamp_authority(tmp_path / "other")
    with pytest.raises(ValueError):
        TimestampTrust(**{**config, "certificate": other}).verify(raw, signed, verified_at=now + 20)
    with pytest.raises(ValueError):
        TimestampTrust(**{**config, "roots": (other_root,)}).verify(raw, signed, verified_at=now + 20)


def test_insufficient_time_window_and_future_review(case):
    signed, raw, now, config = case
    trust = TimestampTrust(**config)
    with pytest.raises(ValueError):
        trust.verify(raw, signed, verified_at=now - 10)
    with pytest.raises(ValueError):
        trust.verify_decision_window(raw, signed, expires_at=now - 1, verified_at=now + 20)
    with pytest.raises(ValueError):
        TimestampTrust(**{**config, "max_delay_seconds": 1}).verify_decision_window(
            raw,
            signed,
            expires_at=now + 300,
            verified_at=now + 20,
        )
