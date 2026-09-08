"""Bounded independent reviewer configuration and secret-safe command failures."""

import base64
import io
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from src.prover.history_cli import HistoryReviewerConfiguration, load_reviewer_configuration, main, read_bounded
from src.prover.history_timing import TimestampTrust
from tests.timestamp_fixture import timestamp_authority


def configuration():
    return {
        "schema_version": "clearproof-history-reviewer-v1",
        "binding": {
            "tenant_id": "tenant-a",
            "receipt_id": "aa" * 32,
            "reviewer_id": "reviewer-a",
            "key_id": "bb" * 32,
            "exported_at": 100,
        },
        "artifact_manifest_digest": "cc" * 32,
        "runtime_sha256": "dd" * 32,
    }


def test_minimal_trust_does_not_infer_authorities():
    config = load_reviewer_configuration(json.dumps(configuration()).encode())
    assert config.trust() == {}


@pytest.mark.parametrize("raw", [b'{"schema_version":1,"schema_version":2}', b"{}", b"{}" * (128 * 1024 + 1)])
def test_invalid_or_oversized_config_rejects(raw):
    with pytest.raises(ValueError):
        load_reviewer_configuration(raw)


def test_unknown_fields_and_incomplete_statement_reject():
    for changes in ({"arbitrary_trust": True}, {"statement": {"policies": []}}):
        with pytest.raises(ValueError):
            load_reviewer_configuration(json.dumps({**configuration(), **changes}).encode())


def test_bounded_input_rejects_symlink_directory_and_size(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"123")
    link = tmp_path / "link"
    link.symlink_to(source)
    for path, limit in ((source, 2), (link, 10), (tmp_path, 10)):
        with pytest.raises((ValueError, OSError)):
            read_bounded(path, limit)
    assert read_bounded(source, 3) == b"123"


@pytest.mark.parametrize("secret", [b"ee" * 32, b"ee" * 32 + b"\n", b"ee" * 32 + b"\n\n", b"SECRET-NOT-A-KEY"])
def test_cli_failure_does_not_echo_secret_or_contents(tmp_path, monkeypatch, capsys, secret):
    source = tmp_path / "trust.json"
    source.write_bytes(b"SENSITIVE-CONFIGURATION")
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(secret)))
    code = main(
        [
            "--trust",
            str(source),
            "--bundle",
            str(source),
            "--artifacts",
            str(tmp_path),
            "--runtime",
            str(source),
            "--node",
            str(source),
        ]
    )
    output = capsys.readouterr()
    assert code == 2 and not output.err
    assert json.loads(output.out)["reasons"] == ["history_input_unavailable"]
    assert secret.decode() not in output.out and "SENSITIVE-CONFIGURATION" not in output.out


def test_published_reviewer_schema_matches_runtime():
    path = Path(__file__).parents[2] / "specs/history-reviewer-v1.schema.json"
    assert json.loads(path.read_text()) == HistoryReviewerConfiguration.model_json_schema()


@pytest.mark.parametrize("invalid_root", ["", "A" * 21849], ids=["empty", "oversized"])
def test_timing_root_size_rejects_and_cli_reports_minimized_failure(tmp_path, monkeypatch, capsys, invalid_root):
    root, leaf, _ = timestamp_authority(tmp_path)
    now = int(time.time())
    timing = {
        "certificate_der_base64": base64.b64encode(leaf.public_bytes(Encoding.DER)).decode(),
        "roots_der_base64": [base64.b64encode(root.public_bytes(Encoding.DER)).decode()],
        "policy_oid": "1.2.3.4",
        "not_before": now - 100,
        "not_after": now + 86400,
    }
    valid = {**configuration(), "timing": timing}
    trusted = load_reviewer_configuration(json.dumps(valid).encode()).trust()["timing_trust"]
    assert isinstance(trusted, TimestampTrust)
    invalid = {**valid, "timing": {**timing, "roots_der_base64": [invalid_root]}}
    config = load_reviewer_configuration(json.dumps(invalid).encode())
    with pytest.raises(ValueError, match="^Certificate size limit$"):
        config.trust()
    source = tmp_path / "invalid-root-trust.json"
    source.write_text(json.dumps(invalid))
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"ee" * 32)))
    assert main([
        "--trust", str(source), "--bundle", str(tmp_path / "absent-bundle"),
        "--artifacts", str(tmp_path / "absent-artifacts"), "--runtime", str(tmp_path / "absent-runtime"),
        "--node", str(tmp_path / "absent-node"),
    ]) == 2
    output = capsys.readouterr()
    assert not output.err
    assert json.loads(output.out) == {
        "schema_version": "clearproof-history-report-v1",
        "scope": "recorded-local-policy-decision",
        "outcome": "indeterminate",
        "reasons": ["history_input_unavailable"],
    }
    assert isinstance(load_reviewer_configuration(json.dumps(valid).encode()).trust()["timing_trust"], TimestampTrust)
