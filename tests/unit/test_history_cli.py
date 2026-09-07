"""Bounded independent reviewer configuration and secret-safe command failures."""

import io
import json
from pathlib import Path

import pytest

from src.prover.history_cli import HistoryReviewerConfiguration, load_reviewer_configuration, main, read_bounded


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
