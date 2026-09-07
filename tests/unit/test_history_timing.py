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


@pytest.mark.parametrize(
    "changes",
    [
        {"not_before": True},
        {"not_after": "100"},
        {"not_before": -1},
        {"not_before": 100, "not_after": 100},
        {"not_after": 2**53},
        {"max_accuracy_us": True},
        {"max_accuracy_us": -1},
        {"max_accuracy_us": 60000001},
        {"max_delay_seconds": True},
        {"max_delay_seconds": 0},
        {"max_delay_seconds": 3601},
        {"compromised_at": True},
        {"compromised_at": -1},
        {"compromised_at": 2**53},
        {"roots": ()},
    ],
)
def test_timestamp_authority_configuration_bounds(case, changes):
    _, _, _, config = case
    with pytest.raises(ValueError, match="Invalid timestamp authority configuration"):
        TimestampTrust(**{**config, **changes})


def test_timestamp_authority_root_inventory_is_bounded(case):
    _, _, _, config = case
    with pytest.raises(ValueError, match="Invalid timestamp authority configuration"):
        TimestampTrust(**{**config, "roots": config["roots"] * 17})


@pytest.mark.parametrize("raw", [None, "not-bytes", b"", b"x" * 32769])
def test_timestamp_response_size_rejected_before_decoding(case, raw):
    signed, _, now, config = case
    with pytest.raises(ValueError, match="Invalid timestamp response size"):
        TimestampTrust(**config).verify(raw, signed, verified_at=now + 20)


@pytest.mark.parametrize("clock", [True, "100", -1, 2**53])
def test_timestamp_review_time_requires_safe_integer(case, clock):
    signed, raw, _, config = case
    with pytest.raises(ValueError, match="Invalid timestamp review time"):
        TimestampTrust(**config).verify(raw, signed, verified_at=clock)


@pytest.mark.parametrize("critical,extra_usage", [(False, False), (True, True)])
def test_timestamp_certificate_usage_must_be_exclusive_and_critical(case, critical, extra_usage):
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _, _, _, config = case
    key = Ed25519PrivateKey.generate()
    usages = [x509.ExtendedKeyUsageOID.TIME_STAMPING]
    if extra_usage:
        usages.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Synthetic invalid TSA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.ExtendedKeyUsage(usages), critical=critical)
        .sign(key, None)
    )
    with pytest.raises(ValueError, match="exclusive critical timestamping usage"):
        TimestampTrust(**{**config, "certificate": certificate})


def test_timestamp_microseconds_requires_offset_and_preserves_precision():
    from datetime import UTC, datetime, timedelta, timezone

    from src.prover.history_timing import _microseconds

    with pytest.raises(ValueError, match="UTC offset"):
        _microseconds(datetime(2026, 1, 1))
    assert _microseconds(datetime(1970, 1, 1, 0, 0, 0, 123456, tzinfo=UTC)) == 123456
    assert _microseconds(datetime(1970, 1, 1, 1, tzinfo=timezone(timedelta(hours=1)))) == 0
    assert _microseconds(datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)) == -1


@pytest.mark.parametrize("mutation", ["encoding", "version", "imprint", "no-digests", "weak-digest"])
def test_decoded_timestamp_profile_rejected_before_signature_verification(case, monkeypatch, mutation):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from cryptography import x509

    from src.prover import history_timing

    signed, raw, now, config = case
    decoded = history_timing.decode_timestamp_response(raw)
    info = SimpleNamespace(version=decoded.tst_info.version, message_imprint=decoded.tst_info.message_imprint)
    response = SimpleNamespace(
        as_bytes=lambda: raw,
        tst_info=info,
        signed_data=SimpleNamespace(digest_algorithms=decoded.signed_data.digest_algorithms),
    )
    if mutation == "encoding":
        response.as_bytes = lambda: raw + b"trailing"
    elif mutation == "version":
        info.version = 2
    elif mutation == "imprint":
        info.message_imprint = SimpleNamespace(hash_algorithm=x509.ObjectIdentifier("1.3.14.3.2.26"))
    elif mutation == "no-digests":
        response.signed_data.digest_algorithms = set()
    else:
        response.signed_data.digest_algorithms = {x509.ObjectIdentifier("1.3.14.3.2.26")}
    # Isolate the application's decoded-profile checks. Existing tests perform
    # real DER parsing and signature verification; this response is not signed.
    monkeypatch.setattr(history_timing, "decode_timestamp_response", lambda _: response)
    trust = TimestampTrust(**config)
    verifier = Mock(spec=trust._verifier)
    monkeypatch.setattr(trust, "_verifier", verifier)
    with pytest.raises(ValueError, match="could not be authenticated") as error:
        trust.verify(raw, signed, verified_at=now + 20)
    assert str(error.value.__cause__) == "Unsupported timestamp response profile"
    verifier.verify_message.assert_not_called()


@pytest.mark.parametrize("accuracy", [(-1, 0, 0), (0, -1, 0), (0, 1000, 0), (0, 0, -1), (0, 0, 1000)])
def test_decoded_timestamp_accuracy_guards(case, monkeypatch, accuracy):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from src.prover import history_timing

    signed, raw, now, config = case
    decoded = history_timing.decode_timestamp_response(raw)
    info = SimpleNamespace(
        version=decoded.tst_info.version,
        message_imprint=decoded.tst_info.message_imprint,
        accuracy=SimpleNamespace(**dict(zip(("seconds", "millis", "micros"), accuracy))),
    )
    response = SimpleNamespace(as_bytes=lambda: raw, tst_info=info, signed_data=decoded.signed_data)
    # Exercise post-verification validation independently of the DER library's
    # own constraints. These altered decoder objects are not cryptographic proof.
    monkeypatch.setattr(history_timing, "decode_timestamp_response", lambda _: response)
    trust = TimestampTrust(**config)
    verifier = Mock(spec=trust._verifier)
    monkeypatch.setattr(trust, "_verifier", verifier)
    with pytest.raises(ValueError, match="could not be authenticated") as error:
        trust.verify(raw, signed, verified_at=now + 20)
    assert str(error.value.__cause__) == "Invalid timestamp accuracy"
    verifier.verify_message.assert_called_once_with(response, history_timing.timestamp_message(signed))


def test_real_signed_timestamp_without_accuracy_is_rejected(case, tmp_path):
    from src.prover.history_timing import decode_timestamp_response, timestamp_message

    signed, _, now, config = case
    root, leaf, issue = timestamp_authority(tmp_path / "no-accuracy", accuracy=None)
    raw = issue(timestamp_request(signed))
    decoded = decode_timestamp_response(raw)
    assert decoded.tst_info.accuracy is None
    trust = TimestampTrust(**{**config, "certificate": leaf, "roots": (root,)})
    # Establish that the response is correctly signed, then check the additional
    # application requirement for a bounded observation interval.
    trust._verifier.verify_message(decoded, timestamp_message(signed))
    with pytest.raises(ValueError, match="could not be authenticated") as error:
        trust.verify(raw, signed, verified_at=now + 20)
    assert str(error.value.__cause__) == "Timestamp accuracy is unspecified"
