"""Real constraints for full-width valuation and private amount-tier classification."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.protocol.transfer import Transfer
from src.prover.pilot_valuation import private_tier_witness, valuation_witness
from src.registry.poseidon import BN254_SCALAR_FIELD

ROOT = Path(__file__).resolve().parents[2]
MAX = 2**128 - 1


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    if not shutil.which("circom") or not shutil.which("node"):
        pytest.skip("requires Circom and node for real arithmetic constraints")
    output = tmp_path_factory.mktemp("pilot-valuation")
    for name, template in (("valuation", "PilotValuation"), ("tier", "PilotAmountTier")):
        source = output / f"{name}.circom"
        source.write_text(
            f'pragma circom 2.1.6;\ninclude "circuits/pilot_valuation.circom";\ncomponent main = {template}();\n'
        )
        result = subprocess.run(
            ["circom", str(source), "--wasm", "--r1cs", "-l", str(ROOT), "-o", str(output)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
    return output


def calculate(compiled, tmp_path, name, data):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(data))
    js = compiled / f"{name}_js"
    return subprocess.run(
        [
            "node",
            str(js / "generate_witness.js"),
            str(js / f"{name}.wasm"),
            str(source),
            str(tmp_path / "witness.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )


def inputs(amount, numerator, denominator):
    cents, remainder = divmod(amount * numerator, denominator)
    return {
        key: str(value)
        for key, value in dict(
            amount_base_units=amount, numerator=numerator, denominator=denominator, usd_cents=cents, remainder=remainder
        ).items()
    }


def test_transfer_witness_uses_full_integer_product():
    vector = json.loads((ROOT / "specs/fixtures/transfer-v1.json").read_text())["records"][0]["value"]
    vector["amount_base_units"] = str(MAX)
    vector["valuation"]["numerator"] = str(MAX - 2)
    vector["valuation"]["denominator"] = str(MAX - 1)
    vector["usd_cents"] = str(MAX - 2)
    transfer = Transfer.model_validate(vector)
    assert valuation_witness(transfer) == inputs(MAX, MAX - 2, MAX - 1)
    with pytest.raises(ValueError):
        valuation_witness(transfer.model_copy(update={"usd_cents": "1"}))


@pytest.mark.parametrize(
    "amount,numerator,denominator",
    [
        (1, 1, 1),
        (101, 3, 2),
        (2**64 + 1, 2**64 - 1, 2**64),
        (MAX, MAX - 2, MAX - 1),
        (MAX, MAX, MAX),
        (2**127, 2**127 + 1, 2**127 - 1),
    ],
)
def test_real_full_width_valid_valuation(compiled, tmp_path, amount, numerator, denominator):
    data = inputs(amount, numerator, denominator)
    assert 0 < int(data["usd_cents"]) <= MAX
    result = calculate(compiled, tmp_path, "valuation", data)
    assert result.returncode == 0, result.stderr.decode()


def test_modular_field_alias_rejected(compiled, tmp_path):
    amount, numerator = BN254_SCALAR_FIELD // 2**128 + 1, MAX
    false_quotient = amount * numerator - BN254_SCALAR_FIELD
    assert 0 < false_quotient <= MAX
    assert (amount * numerator - false_quotient) % BN254_SCALAR_FIELD == 0
    assert amount * numerator != false_quotient
    result = calculate(
        compiled,
        tmp_path,
        "valuation",
        {
            "amount_base_units": str(amount),
            "numerator": str(numerator),
            "denominator": "1",
            "usd_cents": str(false_quotient),
            "remainder": "0",
        },
    )
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


@pytest.mark.parametrize(
    "change",
    [
        {"usd_cents": "150"},
        {"usd_cents": "150", "remainder": "3"},
        {"remainder": "0"},
        {"denominator": "0"},
        {"amount_base_units": "0"},
        {"numerator": "0"},
        {"usd_cents": "0"},
        {"remainder": "2"},
        {"amount_base_units": str(2**128)},
    ],
)
def test_invalid_division_and_ranges(compiled, tmp_path, change):
    data = {**inputs(101, 3, 2), **change}
    result = calculate(compiled, tmp_path, "valuation", data)
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


@pytest.mark.parametrize(
    "amount,tier", [(99, 1), (100, 2), (101, 2), (199, 2), (200, 3), (201, 3), (299, 3), (300, 4), (301, 4), (MAX, 4)]
)
def test_private_tier_boundaries(compiled, tmp_path, amount, tier):
    data = private_tier_witness(str(amount), ("100", "200", "300"))
    assert data["tier"] == str(tier)
    result = calculate(compiled, tmp_path, "tier", data)
    assert result.returncode == 0, result.stderr.decode()
    # A forged tier fails; there is no SAR output to disclose.
    result = calculate(compiled, tmp_path, "tier", {**data, "tier": str(tier % 4 + 1)})
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


@pytest.mark.parametrize("thresholds", [("200", "100", "300"), ("100", "100", "300"), ("0", "200", "300")])
def test_invalid_policy_order_rejected_in_python_and_circuit(compiled, tmp_path, thresholds):
    with pytest.raises(ValueError):
        private_tier_witness("100", thresholds)
    result = calculate(compiled, tmp_path, "tier", {"usd_cents": "100", "thresholds": list(thresholds), "tier": "1"})
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


@pytest.mark.parametrize("thresholds", [None, [], ["10", "20", "30"], ("10", "20"), ("10", "20", "30", "40")])
def test_private_tier_requires_exact_three_threshold_tuple(thresholds):
    with pytest.raises(ValueError, match="Three ordered policy thresholds are required"):
        private_tier_witness("1", thresholds)


@pytest.mark.parametrize("amount", ["0", "-1", "01", str(2**128)])
def test_private_tier_rejects_invalid_amount(amount):
    with pytest.raises(ValueError):
        private_tier_witness(amount, ("10", "20", "30"))
