"""Synthetic information validation before recipient encryption."""

import copy
import json
from pathlib import Path

import pytest

from src.protocol.transfer import Transfer, VerificationContext
from src.protocol.transfer_information import TransferInformation, validate_transfer_information


def synthetic_information(transfer, context):
    return {
        "schema_version": "clearproof-transfer-information-v1",
        "transfer_digest": transfer.digest,
        "context_digest": context.digest,
        "asset_id": transfer.asset_id,
        "amount_base_units": transfer.amount_base_units,
        "originator": {
            "participant": transfer.originator.model_dump(mode="json"),
            "person": {
                "kind": "natural_person",
                "name": "Synthetic José Originator",
                "address": {"lines": ["Synthetic address only"], "country": "US"},
            },
        },
        "beneficiary": {
            "participant": transfer.beneficiary.model_dump(mode="json"),
            "person": {
                "kind": "legal_person",
                "legal_name": "Synthetic Recipient Ltd",
                "address": {"lines": ["Synthetic recipient address only"], "country": "GB"},
                "country_of_registration": "GB",
            },
        },
    }


@pytest.fixture
def case():
    fixture = json.loads((Path(__file__).parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    transfer = Transfer.model_validate(fixture["records"][0]["value"])
    context = VerificationContext.model_validate(fixture["records"][1]["value"])
    return transfer, context, synthetic_information(transfer, context)


def test_valid_unicode_and_exact_bytes(case):
    transfer, context, value = case
    raw = json.dumps(value, ensure_ascii=False).encode()
    padded = raw + b" " * (32768 - len(raw))
    assert validate_transfer_information(padded, transfer, context) is None
    model = TransferInformation.model_validate_json(raw)
    assert "Synthetic" not in repr(model) and "Synthetic" not in str(model.originator.person)
    assert json.loads(raw) == value


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), "unknown"),
        (("transfer_digest",), "ab" * 32),
        (("context_digest",), "cd" * 32),
        (("asset_id",), "USDC"),
        (("amount_base_units",), "1"),
        (("amount_base_units",), 100),
        (("originator", "participant", "wallet"), "0x" + "99" * 20),
        (("beneficiary", "participant", "wallet"), "0x" + "88" * 20),
        (("originator", "person", "name"), " "),
        (("originator", "person", "name"), "name\ncontrol"),
        (("originator", "person", "name"), "x" * 101),
        (("originator", "person", "address", "lines"), []),
        (("originator", "person", "address", "lines"), [" "]),
        (("originator", "person", "address", "country"), "USA"),
        (("beneficiary", "person", "kind"), "unsupported"),
        (("beneficiary", "person", "country_of_registration"), ""),
    ],
)
def test_invalid_or_unbound_information(case, path, value):
    transfer, context, data = case
    for part in path[:-1]:
        data = data[part]
    data[path[-1]] = value
    with pytest.raises(ValueError, match="Invalid or mismatched") as error:
        validate_transfer_information(json.dumps(case[2]).encode(), transfer, context)
    assert "Synthetic" not in str(error.value)


@pytest.mark.parametrize("field", ["originator", "beneficiary", "schema_version", "amount_base_units"])
def test_required_fields(case, field):
    transfer, context, value = case
    del value[field]
    with pytest.raises(ValueError):
        validate_transfer_information(json.dumps(value).encode(), transfer, context)


def test_duplicate_keys_unknown_fields_and_person_ambiguity(case):
    transfer, context, value = case
    raw = json.dumps(value).encode()
    malformed = [b"", b"not-json", b"null", b"[]", b"NaN", b"\xff", raw + b"x" * 32768, b'{"beneficiary":{},' + raw[1:]]
    extra = copy.deepcopy(value)
    extra["beneficiary"]["person"]["name"] = "Unexpected natural name"
    malformed.append(json.dumps(extra).encode())
    for payload in malformed:
        with pytest.raises(ValueError, match="Invalid or mismatched"):
            validate_transfer_information(payload, transfer, context)


def test_parties_cannot_be_swapped(case):
    transfer, context, value = case
    value["originator"], value["beneficiary"] = value["beneficiary"], value["originator"]
    with pytest.raises(ValueError):
        validate_transfer_information(json.dumps(value).encode(), transfer, context)
