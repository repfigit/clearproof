"""Reject executable, ambiguous and unbounded representations before persistence."""

import json

import pytest
from pydantic import ValidationError

from src.storage.models import StoredProof
from src.storage.signals import MAX_SIGNALS, SCALAR_FIELD, decode_legacy_signals, validate_public_signals


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {},
        ("1",),
        '["1"]',
        [1],
        [True],
        [None],
        [["1"]],
        [""],
        ["01"],
        ["+1"],
        ["-1"],
        ["1.0"],
        ["1e2"],
        ["0x1"],
        [" 1"],
        ["1\n"],
        ["١"],
        [str(SCALAR_FIELD)],
        ["9" * 10000],
        ["1"] * (MAX_SIGNALS + 1),
    ],
)
def test_model_rejects_invalid_signals(sample_compliance_proof, bad):
    data = sample_compliance_proof.model_dump()
    data["public_signals"] = bad
    with pytest.raises(ValidationError, match="public_signals"):
        StoredProof.model_validate(data)


def test_field_boundaries_and_defensive_copy():
    values = ["0", str(SCALAR_FIELD - 1)] * (MAX_SIGNALS // 2)
    validated = validate_public_signals(values)
    assert validated == values
    values[0] = "mutated"
    assert validated[0] == "0"


@pytest.mark.parametrize("encoded", ["['0', '123']", '["0", "123"]', ["0", "123"]])
def test_bounded_legacy_decoding(encoded):
    assert decode_legacy_signals(encoded) == ["0", "123"]


@pytest.mark.parametrize(
    "encoded",
    [
        "[str(1)]",
        "['1' + '2']",
        "['1' '2']",
        r"['\x31']",
        "['1' * 1000000]",
        "['1'] * 1000000",
        "[x for x in []]",
        "('1',)",
        "[b'1']",
        "[1]",
        "[True]",
        "{0: '1'}",
        "['1', ['2']]",
        "['01']",
        json.dumps("['1']"),
        "[" * 8000 + "]" * 8000,
        " " * 17000,
    ],
)
def test_legacy_decoder_accepts_no_expressions_or_nested_encodings(encoded):
    with pytest.raises(ValueError, match="public_signals"):
        decode_legacy_signals(encoded)
