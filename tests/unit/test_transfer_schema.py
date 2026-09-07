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


@pytest.mark.parametrize("kind", ["empty", "duplicate", "oversized"])
def test_catalog_rejects_invalid_inventory(kind):
    asset = AssetDefinition.model_validate(VECTOR["assets"][0])
    assets = [] if kind == "empty" else [asset] * (2 if kind == "duplicate" else 257)
    with pytest.raises(ValueError, match="1–256 unique asset identities"):
        AssetRegistry(assets)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"kind": "vasp", "vasp_did": None}, "canonical did:web"),
        ({"kind": "vasp", "vasp_did": "beneficiary.example"}, "canonical did:web"),
        ({"kind": "self_hosted", "vasp_did": "did:web:beneficiary.example"}, "cannot declare a VASP"),
        ({"wallet": "0x" + "0" * 40}, "wallet cannot be zero"),
    ],
)
def test_participant_identity_boundaries(transfer, changes, message):
    from src.protocol.transfer import Participant

    with pytest.raises(ValueError, match=message):
        Participant.model_validate({**transfer.originator.model_dump(), **changes})


@pytest.mark.parametrize("field", ["amount_base_units", "usd_cents"])
def test_transfer_rejects_zero_amount_or_valuation(transfer, field):
    with pytest.raises(ValueError, match="must be positive"):
        Transfer.model_validate({**transfer.model_dump(), field: "0"})


def test_transfer_rejects_valuation_for_another_asset(transfer):
    values = transfer.model_dump()
    values["valuation"]["asset_id"] = "eip155:1/erc20:0x" + "ab" * 20
    assert values["valuation"]["asset_id"] != values["asset_id"]
    with pytest.raises(ValueError, match="Valuation asset does not match"):
        Transfer.model_validate(values)


def test_catalog_digest_is_checked_after_asset_membership(transfer, registry):
    values = {**transfer.model_dump(), "asset_registry_digest": "00" * 32}
    with pytest.raises(ValueError, match="Asset registry digest mismatch"):
        parse_transfer(values, registry)


@pytest.mark.parametrize("chain", ["0", str(2**64)])
def test_verifier_deployment_chain_rejects_out_of_range(chain):
    with pytest.raises(ValueError, match="Invalid deployment chain ID"):
        VerificationContext.model_validate({**VECTOR["records"][1]["value"], "deployment_chain_id": chain})


def test_verifier_deployment_rejects_zero_address():
    with pytest.raises(ValueError, match="Deployment address cannot be zero"):
        VerificationContext.model_validate({**VECTOR["records"][1]["value"], "deployment_address": "0x" + "0" * 40})


@pytest.mark.parametrize("cryptographic_result", ["valid", "invalid"])
def test_evaluated_receipt_requires_proof_digest(cryptographic_result):
    with pytest.raises(ValueError, match="Evaluated proof requires its digest"):
        EvidenceReceipt.model_validate(
            {**VECTOR["records"][2]["value"], "cryptographic_result": cryptographic_result, "proof_digest": None}
        )


def test_catalog_order_and_digest_do_not_depend_on_inventory_order(registry):
    reversed_registry = AssetRegistry([AssetDefinition.model_validate(value) for value in reversed(VECTOR["assets"])])
    assert reversed_registry.definitions == registry.definitions
    assert tuple(asset.asset_id for asset in registry.definitions) == tuple(
        sorted(asset["asset_id"] for asset in VECTOR["assets"])
    )
    assert reversed_registry.digest == registry.digest
    with pytest.raises(ValidationError):
        registry.definitions[0].decimals = 0


@pytest.mark.parametrize(
    "domain",
    [
        "clearproof/transfer/v0",
        "clearproof/transfer/v01",
        "other/transfer/v1",
        "clearproof/Transfer/v1",
        "clearproof/transfer/v1\n",
        "clearproof/transfer/v1/extra",
    ],
)
def test_digest_rejects_noncanonical_domains(domain):
    with pytest.raises(ValueError, match="^Invalid commitment domain$"):
        record_digest(domain, {"synthetic": True})


@pytest.mark.parametrize("extra", [0, 1, 2])
def test_canonical_serialized_byte_limit_includes_json_escaping(extra):
    # Eight quoted strings have 25 bytes of array/quote/comma syntax. Quotation
    # marks double on serialization, although each counts once during validation.
    value = ['"' * 4096] * 7 + ['"' * 4083 + "a" * extra]
    expected_size = 65535 + extra
    if expected_size <= 65536:
        encoded = canonical_bytes(value)
        assert len(encoded) == expected_size
        assert json.loads(encoded) == value
    else:
        with pytest.raises(ValueError, match="^Canonical record exceeds 64 KiB$"):
            canonical_bytes(value)
