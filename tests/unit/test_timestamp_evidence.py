"""Retained timestamp framing rejects malformed or oversized evidence."""

import base64
import binascii

import pytest

from src.prover.history_timing import MAX_TIMESTAMP_BYTES
from src.services.timestamp_evidence import timestamp_record_bytes


def retained(raw):
    encoded = base64.b64encode(raw).decode("ascii")
    return {
        "schema_version": "clearproof-retained-timestamp-v1",
        "tenant_id": "synthetic-tenant",
        "receipt_id": "a" * 64,
        "response": [encoded[index : index + 2048] for index in range(0, len(encoded), 2048)],
    }


def decode(record):
    return timestamp_record_bytes(record, tenant_id="synthetic-tenant", receipt_id="a" * 64)


@pytest.mark.parametrize("size", [1, 1536, 1537, MAX_TIMESTAMP_BYTES])
def test_retained_timestamp_round_trips_chunk_boundaries(size):
    raw = bytes(index % 256 for index in range(size))
    assert decode(retained(raw)) == raw


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "unsupported"),
        ("tenant_id", "another-tenant"),
        ("receipt_id", "b" * 64),
        ("response", None),
        ("response", ("YQ==",)),
        ("response", []),
        ("response", ["YQ=="] * 23),
        ("response", [False]),
        ("response", [""]),
        ("response", ["A" * 2049]),
    ],
)
def test_retained_timestamp_rejects_invalid_framing(field, value):
    record = retained(b"synthetic timestamp")
    record[field] = value
    with pytest.raises(ValueError, match="Invalid retained timestamp record"):
        decode(record)


@pytest.mark.parametrize("record", [None, [], "synthetic"])
def test_retained_timestamp_requires_object(record):
    with pytest.raises(ValueError, match="Invalid retained timestamp record"):
        decode(record)


@pytest.mark.parametrize("encoded", ["!!!", "YQ", "YQ==\n"])
def test_retained_timestamp_rejects_invalid_base64(encoded):
    record = retained(b"a")
    record["response"] = [encoded]
    with pytest.raises(binascii.Error):
        decode(record)


def test_retained_timestamp_rejects_decoded_payload_over_limit():
    # This still fits the 22 permitted encoded chunks; enforce the decoded bound.
    record = retained(b"x" * (MAX_TIMESTAMP_BYTES + 1))
    assert len(record["response"]) == 22
    with pytest.raises(ValueError, match="Invalid retained timestamp size"):
        decode(record)
