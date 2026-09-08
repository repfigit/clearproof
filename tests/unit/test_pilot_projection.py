"""Exact transfer/context projection and real circuit substitution resistance."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.protocol.transfer import AssetDefinition, AssetRegistry, Transfer, VerificationContext
from src.prover.pilot_projection import FIELD_NAMES, TransferProjection, project_transfer
from src.registry.poseidon import BN254_SCALAR_FIELD

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def records():
    data = json.loads((ROOT / "specs/fixtures/transfer-v1.json").read_text())
    return (
        Transfer.model_validate(data["records"][0]["value"]),
        VerificationContext.model_validate(data["records"][1]["value"]),
        AssetRegistry([AssetDefinition.model_validate(asset) for asset in data["assets"]]),
    )


@pytest.fixture
def projection(records):
    return project_transfer(*records, ("10000", "100000", "1000000"))


def test_all_fields_bound_and_nullifier_stable_across_reassessment(records, projection):
    assert len(FIELD_NAMES) == len(projection.fields) == 48
    for index in range(48):
        fields = list(projection.fields)
        fields[index] ^= 1
        changed = TransferProjection(tuple(fields), projection.remainder)
        assert changed.commitment != projection.commitment, FIELD_NAMES[index]
    transfer, context, registry = records
    newer = VerificationContext.model_validate({**context.model_dump(), "evaluated_at": context.evaluated_at + 1})
    updated = project_transfer(transfer, newer, registry, ("10000", "100000", "1000000"))
    assert updated.commitment != projection.commitment
    assert updated.nullifier("123456") == projection.nullifier("123456")
    assert updated.nullifier("654321") != projection.nullifier("123456")
    fields = list(projection.fields)
    fields[27] += 1
    assert TransferProjection(tuple(fields), projection.remainder).nullifier("123456") != projection.nullifier("123456")
    assert transfer.originator.wallet not in repr(projection)


def test_field_alias_and_context_substitution_rejected(records, projection):
    fields = list(projection.fields)
    fields[0] += BN254_SCALAR_FIELD
    with pytest.raises(ValueError):
        TransferProjection(tuple(fields), projection.remainder)
    transfer, context, registry = records
    with pytest.raises(ValueError):
        project_transfer(
            transfer, context.model_copy(update={"tenant_id": "tenant-b"}), registry, ("10000", "100000", "1000000")
        )


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    if not shutil.which("circom") or not shutil.which("node"):
        pytest.skip("requires Circom and node")
    output = tmp_path_factory.mktemp("pilot-projection")
    source = output / "projection.circom"
    source.write_text(
        'pragma circom 2.1.6;\ninclude "circuits/pilot_transfer.circom";\n'
        "component main {public [projection_commitment]} = PilotTransferProjection();\n"
    )
    result = subprocess.run(
        ["circom", str(source), "--wasm", "--r1cs", "-l", str(ROOT), "-o", str(output)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return output


def calculate(compiled, tmp_path, data):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(data))
    folder = compiled / "projection_js"
    return subprocess.run(
        [
            "node",
            str(folder / "generate_witness.js"),
            str(folder / "projection.wasm"),
            str(source),
            str(tmp_path / "projection.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )


def test_real_projection_matches_python(compiled, tmp_path, projection):
    result = calculate(compiled, tmp_path, projection.witness())
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("index", [10, 11, 13, 15, 16, 17, 18, 25, 27, 28, 32, 35, 44])
def test_real_substitution_against_expected_commitment(compiled, tmp_path, projection, index):
    data = projection.witness()
    data["transfer_fields"][index] = str(int(data["transfer_fields"][index]) + 1)
    result = calculate(compiled, tmp_path, data)
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


@pytest.mark.parametrize("attack", ["expired", "future", "stale", "wrong-chain", "wrong-value", "wrong-tier"])
def test_invalid_predicates_fail_even_with_recomputed_commitment(compiled, tmp_path, projection, attack):
    fields = list(projection.fields)
    if attack == "expired":
        fields[23] = fields[22]
    elif attack == "future":
        fields[23] = fields[21] - 1
    elif attack == "stale":
        fields[24] = 0
        fields[23] = fields[21] + 1
    elif attack == "wrong-chain":
        fields[26] += 1
    elif attack == "wrong-value":
        fields[18] += 1
    elif attack == "wrong-tier":
        fields[35] = fields[35] % 4 + 1
    changed = TransferProjection(tuple(fields), projection.remainder)
    result = calculate(compiled, tmp_path, changed.witness())
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


@pytest.mark.parametrize("size", [0, 31, 33])
def test_digest_projection_requires_exact_256_bits(size):
    from src.prover.pilot_projection import hex_limbs

    with pytest.raises(ValueError, match="Expected 32-byte digest"):
        hex_limbs((b"x" * size).hex())


def test_digest_projection_preserves_high_and_low_128_bit_halves():
    from src.prover.pilot_projection import hex_limbs

    assert hex_limbs("ff" * 16 + "00" * 16) == (2**128 - 1, 0)
    assert hex_limbs("00" * 16 + "ff" * 16) == (0, 2**128 - 1)


@pytest.mark.parametrize("fields", [[], [0] * 48, (0,) * 47, (0,) * 49])
def test_projection_requires_immutable_exact_field_inventory(fields):
    with pytest.raises(ValueError, match="Projection requires a 48-field tuple"):
        TransferProjection(fields, "0")


@pytest.mark.parametrize("remainder", [None, True, 0, 1.0])
def test_projection_remainder_requires_text(remainder):
    with pytest.raises(ValueError, match="Projection remainder must be a canonical integer string"):
        TransferProjection((0,) * 48, remainder)


@pytest.mark.parametrize("remainder", ["", "-1", "01", "1.0", str(2**128)])
def test_projection_remainder_rejects_noncanonical_or_out_of_range_integers(remainder):
    with pytest.raises(ValueError):
        TransferProjection((0,) * 48, remainder)


@pytest.mark.parametrize("value", [True, "1", -1, 2**128])
def test_projection_rejects_invalid_digest_limb(value):
    fields = (value,) + (0,) * 47
    with pytest.raises(ValueError, match="Projection field is outside its integer range"):
        TransferProjection(fields, "0")


def test_projection_values_are_immutable_after_validation():
    from dataclasses import FrozenInstanceError

    projection = TransferProjection((0,) * 48, "0")
    with pytest.raises(FrozenInstanceError):
        projection.fields = ()
    assert len(projection.fields) == 48
