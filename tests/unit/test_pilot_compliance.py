"""Synthetic composed witnesses and actual WASM adversarial checks."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.protocol.credential import PilotCredential, holder_commitment
from src.protocol.transfer import AssetDefinition, AssetRegistry, Transfer, VerificationContext
from src.protocol.valuation_approval import ValuationApproval, ValuationAuthority, ValuationTrustStore, sign_valuation
from src.prover.pilot_compliance import PUBLIC_SIGNALS, compliance_witness
from src.registry.pilot_sanctions import PilotSanctionsTree
from src.registry.pilot_tree import PilotTree

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def witness():
    fixture = json.loads((ROOT / "specs/fixtures/transfer-v1.json").read_text())
    transfer = Transfer.model_validate(fixture["records"][0]["value"])
    context = VerificationContext.model_validate(
        {**fixture["records"][1]["value"], "proof_profile": "pilot-transfer-v1"}
    )
    registry = AssetRegistry([AssetDefinition.model_validate(a) for a in fixture["assets"]])
    credential = PilotCredential(
        tenant_id=transfer.tenant_id,
        credential_nonce="ab" * 32,
        issuer_did="did:web:issuer.example",
        subject_wallet=transfer.originator.wallet,
        holder_commitment=holder_commitment("123456"),
        jurisdiction=transfer.jurisdiction,
        kyc_tier=2,
        sanctions_clear=True,
        issued_at=transfer.created_at,
        expires_at=transfer.expires_at,
    )
    issuance = PilotTree([("credential", credential.commitment)], depth=8)
    issuers = PilotTree([("issuer", credential.authorized_issuer_leaf(issuance.root))], depth=8)
    quote_key = Ed25519PrivateKey.generate()
    quote_authority = ValuationAuthority(
        public_key=quote_key.public_key().public_bytes_raw().hex(),
        tenant_id=transfer.tenant_id,
        asset_registry_digest=registry.digest,
        asset_ids=(transfer.asset_id,),
        source_ids=(transfer.valuation.source_id,),
        not_before=transfer.valuation.observed_at,
        not_after=transfer.valuation.expires_at,
        max_quote_lifetime_seconds=600,
        max_observation_age_seconds=300,
    )
    quote_approval = sign_valuation(
        ValuationApproval(
            tenant_id=transfer.tenant_id,
            asset_registry_digest=registry.digest,
            valuation=transfer.valuation,
            signed_at=transfer.created_at,
            key_id=quote_authority.key_id,
        ),
        quote_key,
    )
    return compliance_witness(
        transfer,
        context,
        registry,
        ("10000", "100000", "1000000"),
        credential,
        secret="123456",
        issuance_path=issuance.membership("credential"),
        issuer_path=issuers.membership("issuer"),
        sanctions=PilotSanctionsTree([]),
        valuation_approval=quote_approval,
        valuation_trust=ValuationTrustStore([quote_authority]),
    )


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    if not shutil.which("circom") or not shutil.which("node"):
        pytest.skip("requires Circom and Node")
    output = tmp_path_factory.mktemp("pilot-composed")
    result = subprocess.run(
        ["circom", str(ROOT / "circuits/pilot_compliance.circom"), "--wasm", "--r1cs", "-o", str(output)],
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode()
    return output


def calculate(compiled, tmp_path, witness):
    source = tmp_path / "synthetic.json"
    source.write_text(json.dumps(witness))
    folder = compiled / "pilot_compliance_js"
    return subprocess.run(
        [
            "node",
            str(folder / "generate_witness.js"),
            str(folder / "pilot_compliance.wasm"),
            str(source),
            str(tmp_path / "synthetic.wtns"),
        ],
        capture_output=True,
        timeout=30,
    )


def test_composed_valid(compiled, tmp_path, witness):
    assert len(PUBLIC_SIGNALS) == 8
    result = calculate(compiled, tmp_path, witness)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize(
    "name,index",
    [
        ("holder_secret", None),
        ("credential_commitment", None),
        ("authorized_issuer_root", None),
        ("issuance_root", None),
        ("sanctions_root", None),
        ("authorization_nullifier", None),
        ("domain_chain_id", None),
        ("domain_registry", None),
        ("projection_commitment", None),
        ("proof_expires_at", None),
        ("transfer_fields", 10),
        ("transfer_fields", 11),
        ("credential_fields", 6),
        ("credential_fields", 2),
        ("credential_fields", 8),
    ],
)
def test_composed_mutation_rejected(compiled, tmp_path, witness, name, index):
    if index is None:
        witness[name] = str(int(witness[name]) + 1)
    else:
        witness[name][index] = str(int(witness[name][index]) + 1)
    result = calculate(compiled, tmp_path, witness)
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


@pytest.mark.parametrize("party", [0, 1])
def test_sanctioned_wallet_cannot_use_unrelated_gap(compiled, tmp_path, witness, party):
    wallet = int(witness["transfer_fields"][10 + party])
    tree = PilotSanctionsTree([f"0x{wallet:040x}"])
    witness["sanctions_root"] = tree.root
    # A real valid gap for another wallet must not screen the bound participant.
    for p in range(2):
        key = int(witness["transfer_fields"][10 + p])
        gap = tree.gap(f"0x{key + (1 if p == party else 0):040x}")
        for target, source in [
            ("left_keys", "left_key"),
            ("right_keys", "right_key"),
            ("left_siblings", "left_siblings"),
            ("right_siblings", "right_siblings"),
            ("left_indices", "left_indices"),
            ("right_indices", "right_indices"),
        ]:
            witness["sanctions_" + target][p] = copy.deepcopy(gap[source])
    result = calculate(compiled, tmp_path, witness)
    assert result.returncode != 0 and b"Assert Failed" in result.stderr


def test_sanctions_order_sentinels_and_invalid_inputs():
    addresses = [f"0x{x:040x}" for x in (1, 100, 2**160 - 1)]
    tree = PilotSanctionsTree(addresses)
    assert tree.root == PilotSanctionsTree(list(reversed(addresses))).root
    assert tree.source_digest == PilotSanctionsTree(list(reversed(addresses))).source_digest
    gap = tree.gap(f"0x{99:040x}")
    assert (gap["left_key"], gap["right_key"]) == ("1", "100")
    for address in addresses + ["name.eth", "0x" + "0" * 40, "0x" + "A" * 40]:
        with pytest.raises(ValueError):
            tree.gap(address)
    with pytest.raises(ValueError):
        PilotSanctionsTree(addresses + addresses)
