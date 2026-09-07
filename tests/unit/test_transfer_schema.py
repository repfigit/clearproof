"""Canonical transfer commitments, exact quantities and verifier context boundaries."""

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.transfer import (
    AssetDefinition,
    AssetRegistry,
    EvidenceReceipt,
    Transfer,
    VerificationContext,
    parse_transfer,
)

FIXTURES = Path(__file__).resolve().parents[2] / "specs/fixtures"
VECTOR = json.loads((FIXTURES / "transfer-v1.json").read_text())


@pytest.fixture
def registry():
    return AssetRegistry([AssetDefinition.model_validate(value) for value in VECTOR["assets"]])


@pytest.fixture
def transfer(registry):
    return parse_transfer(VECTOR["records"][0]["value"], registry)


def test_shared_vectors_and_schema_exports(registry):
    assert registry.digest == VECTOR["asset_registry_digest"]
    for vector, cls, name in zip(
        VECTOR["records"],
        [Transfer, VerificationContext, EvidenceReceipt],
        ["transfer", "verification-context", "evidence-receipt"],
    ):
        value = cls.model_validate(vector["value"])
        assert value.canonical_bytes().decode() == vector["canonical"]
        assert value.digest == vector["digest"]
        assert record_digest(vector["domain"], vector["value"]) == vector["digest"]
        assert json.loads((FIXTURES / f"{name}-v1.schema.json").read_text()) == cls.model_json_schema()


def test_catalog_identity_never_uses_symbol(registry, transfer):
    assert registry.get(VECTOR["assets"][0]["asset_id"]).symbol == registry.get(VECTOR["assets"][1]["asset_id"]).symbol
    other = transfer.model_dump()
    other["asset_id"] = VECTOR["assets"][1]["asset_id"]
    other["valuation"]["asset_id"] = other["asset_id"]
    assert parse_transfer(other, registry).digest != transfer.digest
    for asset in ["TESTUSD", "eip155:1/erc20:0x" + "a" * 40]:
        with pytest.raises(ValueError, match="Unknown asset"):
            registry.parse_amount(asset, "1")
    unknown = transfer.model_dump()
    unknown["asset_id"] = "eip155:1/erc20:0x" + "a" * 40
    unknown["valuation"]["asset_id"] = unknown["asset_id"]
    with pytest.raises(ValueError, match="Unknown asset"):
        parse_transfer(unknown, registry)


@pytest.mark.parametrize(
    "amount",
    [
        "1e3",
        "+1",
        "-1",
        "01",
        ".5",
        "1.",
        "1,000",
        " 1",
        "1\n",
        "0",
        "0.0000001",
        "1.1234567",
        1.2,
        True,
        "1." + "0" * 10000,
    ],
)
def test_ambiguous_or_unrepresentable_amounts_fail(registry, amount):
    with pytest.raises(ValueError):
        registry.parse_amount(VECTOR["assets"][0]["asset_id"], amount)


def test_exact_decimal_boundaries_without_floats(registry):
    asset = VECTOR["assets"][0]["asset_id"]
    assert registry.parse_amount(asset, "0.000001") == "1"
    assert registry.parse_amount(asset, "1000.000001") == "1000000001"
    assert registry.parse_amount(asset, "1000.000000") == "1000000000"
    with pytest.raises(ValueError):
        registry.parse_amount(asset, str(2**128))


@pytest.mark.parametrize(
    "field,value",
    [
        ("amount_base_units", "01"),
        ("amount_base_units", 100),
        ("usd_cents", "123455"),
        ("tenant_id", "other"),
        ("nonce", "2" * 64),
        ("policy_digest", "4" * 64),
        ("jurisdiction", "GB"),
    ],
)
def test_fact_changes_never_preserve_commitment(transfer, registry, field, value):
    data = transfer.model_dump()
    data[field] = value
    try:
        changed = parse_transfer(data, registry)
    except ValueError:
        return
    assert changed.digest != transfer.digest


@pytest.mark.parametrize(
    "field,value",
    [
        ("numerator", "2"),
        ("denominator", "0"),
        ("asset_id", "TESTUSD"),
        ("observed_at", 1788650001),
        ("expires_at", 1788650000),
    ],
)
def test_valuation_inconsistency_rejects(transfer, registry, field, value):
    data = transfer.model_dump()
    data["valuation"][field] = value
    with pytest.raises(ValueError):
        parse_transfer(data, registry)


def test_context_checks_tenant_transfer_policy_chain_and_time(transfer):
    original = VECTOR["records"][1]["value"]
    VerificationContext.model_validate(original).check_transfer(transfer)
    for key, value in [
        ("tenant_id", "wrong"),
        ("transfer_digest", "f" * 64),
        ("policy_digest", "f" * 64),
        ("deployment_chain_id", "31338"),
        ("evaluated_at", transfer.created_at - 1),
        ("evaluated_at", transfer.expires_at),
        ("max_transfer_age_seconds", 9),
    ]:
        changed = {**original, key: value}
        context = VerificationContext.model_validate(changed)
        assert context.digest != VerificationContext.model_validate(original).digest
        with pytest.raises(ValueError):
            context.check_transfer(transfer)


def test_unknown_fields_and_private_representations(transfer):
    assert transfer.originator.wallet not in str(transfer)
    assert transfer.amount_base_units not in repr(transfer)
    invalid = transfer.model_dump()
    invalid["originator_name"] = "do-not-accept-raw-identity"
    with pytest.raises(ValidationError) as error:
        Transfer.model_validate(invalid)
    assert "do-not-accept-raw-identity" not in str(error.value)


def test_receipt_does_not_infer_policy_or_settlement(transfer):
    data = copy.deepcopy(VECTOR["records"][2]["value"])
    data["proof_digest"] = "e" * 64
    data["cryptographic_result"] = "valid"
    receipt = EvidenceReceipt.model_validate(data)
    assert receipt.policy_result == "indeterminate"
    assert receipt.settlement_result == "not_observed"
    data["authorization_result"] = "consumed"
    with pytest.raises(ValueError):
        EvidenceReceipt.model_validate(data)


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), 1.5, 2**53, "\n", "é", {"": 1}, {"x": b"bytes"}, ["x"] * 257]
)
def test_canonical_rejects_ambiguous_values(value):
    with pytest.raises(ValueError):
        canonical_bytes(value)


def test_canonical_sorting_bounds_and_domain_separation():
    assert canonical_bytes({"2": "b", "10": "a", "a": 'quote"/\\'}) == b'{"10":"a","2":"b","a":"quote\\"/\\\\"}'
    value = {"x": "safe"}
    assert record_digest("clearproof/transfer/v1", value) != record_digest("clearproof/evidence-receipt/v1", value)
    with pytest.raises(ValueError):
        canonical_bytes(["x" * 4096] * 256)
    nested = None
    for _ in range(10):
        nested = [nested]
    with pytest.raises(ValueError):
        canonical_bytes(nested)


def test_catalog_metadata_is_immutable_and_digest_is_order_independent(registry):
    entries = [AssetDefinition.model_validate(value) for value in reversed(VECTOR["assets"])]
    assert AssetRegistry(entries).digest == registry.digest
    with pytest.raises(AttributeError):
        registry.digest = "f" * 64
    with pytest.raises(ValidationError):
        entries[0].decimals = 18


def test_preconstructed_model_cannot_bypass_amount_binding(transfer, registry):
    forged = transfer.model_copy(update={"usd_cents": "1"})
    with pytest.raises(ValueError):
        parse_transfer(forged, registry)
