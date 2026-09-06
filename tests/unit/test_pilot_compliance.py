"""Synthetic composed witnesses and actual WASM adversarial checks."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account

from src.policy.model import PilotPolicy, PolicyRule, PolicySource, PolicyTrustStore
from src.protocol.credential import PilotCredential, holder_commitment
from src.protocol.root_snapshot import RootAuthority, RootSnapshot, RootTrustStore, sign_root
from src.protocol.transfer import AssetDefinition, AssetRegistry, Transfer, VerificationContext
from src.protocol.valuation_approval import ValuationApproval, ValuationAuthority, ValuationTrustStore, sign_valuation
from src.prover.pilot_compliance import PUBLIC_SIGNALS, compliance_witness
from src.prover.pilot_roots import CurrentRootPins
from src.registry.pilot_sanctions import PilotSanctionsTree
from src.registry.pilot_tree import PilotTree

ROOT = Path(__file__).resolve().parents[2]


def synthetic_case(*, artifact_manifest_digest=None, alternate_credential=False, with_trust=False, authorization=False):
    fixture = json.loads((ROOT / "specs/fixtures/transfer-v1.json").read_text())
    transfer = Transfer.model_validate(fixture["records"][0]["value"])
    if authorization:
        transfer = Transfer.model_validate(
            {
                **transfer.model_dump(),
                "beneficiary": {
                    **transfer.beneficiary.model_dump(),
                    "kind": "vasp",
                    "vasp_did": "did:web:recipient.example",
                },
            }
        )
    if with_trust:
        # Public EOA simulator key so the durable enrollment service can verify consent.
        wallet = Account.from_key(bytes([8]) * 32)
        transfer = Transfer.model_validate(
            {
                **transfer.model_dump(),
                "originator": {**transfer.originator.model_dump(), "wallet": wallet.address.lower()},
            }
        )
    context = VerificationContext.model_validate(
        {**fixture["records"][1]["value"], "proof_profile": "pilot-transfer-v2"}
    )
    if artifact_manifest_digest is not None:
        context = VerificationContext.model_validate(
            {**context.model_dump(), "artifact_manifest_digest": artifact_manifest_digest}
        )
    registry = AssetRegistry([AssetDefinition.model_validate(a) for a in fixture["assets"]])
    policy = PilotPolicy(
        policy_id="synthetic-policy",
        revision=1,
        tenant_id=transfer.tenant_id,
        chain_id=context.deployment_chain_id,
        registry_address=context.deployment_address,
        jurisdiction=transfer.jurisdiction,
        asset_registry_digest=registry.digest,
        effective_from=transfer.created_at,
        effective_until=transfer.valuation.expires_at,
        tier_thresholds_usd_cents=("10000", "100000", "1000000"),
        sources=(
            PolicySource(
                source_id="synthetic-rules",
                kind="synthetic",
                reference="urn:clearproof:synthetic:policy-v1",
                evidence_digest="ab" * 32,
                reviewed_at=transfer.created_at,
                valid_until=transfer.valuation.expires_at,
            ),
        ),
    )
    if authorization:
        policy = PilotPolicy.model_validate(
            {
                **policy.model_dump(),
                "rules": (
                    PolicyRule(
                        rule_id="synthetic-allow",
                        predicate="proof_valid",
                        operator="is_true",
                        effect="ALLOW",
                        source_ids=("synthetic-rules",),
                    ),
                ),
            }
        )
    transfer = Transfer.model_validate({**transfer.model_dump(), "policy_digest": policy.digest})
    context = VerificationContext.model_validate(
        {
            **context.model_dump(),
            "policy_digest": policy.digest,
            "transfer_digest": transfer.digest,
        }
    )
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
    alternate = PilotCredential.model_validate({**credential.model_dump(), "credential_nonce": "cd" * 32})
    issuance = PilotTree([("credential", credential.commitment), ("alternate", alternate.commitment)], depth=8)
    if alternate_credential:
        credential = alternate
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
    policy_trust = PolicyTrustStore([policy], current_digests=(policy.digest,))
    valuation_trust = ValuationTrustStore([quote_authority])
    sanctions = PilotSanctionsTree([])
    if with_trust:
        # Public deterministic simulator key, exclusively for synthetic test roots.
        root_key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
        authority = RootAuthority(
            public_key=root_key.public_key().public_bytes_raw().hex(),
            tenant_id=transfer.tenant_id,
            chain_id=int(context.deployment_chain_id),
            registry_address=context.deployment_address,
            kinds=("issuance-root", "issuer-root", "sanctions-root"),
            issuer_dids=(credential.issuer_did,),
            not_before=transfer.created_at,
            not_after=transfer.expires_at,
        )
        signed = [
            sign_root(
                RootSnapshot(
                    tenant_id=transfer.tenant_id,
                    chain_id=authority.chain_id,
                    registry_address=authority.registry_address,
                    kind=kind,
                    issuer_did=credential.issuer_did if kind == "issuance-root" else None,
                    root=root,
                    tree_depth=8,
                    source_digest="ef" * 32,
                    revision=1,
                    issued_at=transfer.created_at,
                    expires_at=transfer.expires_at,
                    key_id=authority.key_id,
                ),
                root_key,
            )
            for kind, root in zip(authority.kinds, (issuance.root, issuers.root, sanctions.root), strict=True)
        ]
        pins = CurrentRootPins(
            tenant_id=transfer.tenant_id,
            chain_id=authority.chain_id,
            registry_address=authority.registry_address,
            issuer_did=credential.issuer_did,
            issuance_digest=signed[0].snapshot.digest,
            issuer_digest=signed[1].snapshot.digest,
            sanctions_digest=signed[2].snapshot.digest,
        )
        context = VerificationContext.model_validate(
            {
                **context.model_dump(),
                "issuance_snapshot_digest": pins.issuance_digest,
                "issuer_snapshot_digest": pins.issuer_digest,
                "sanctions_snapshot_digest": pins.sanctions_digest,
            }
        )
        inputs = dict(
            transfer=transfer,
            context=context,
            credential=credential,
            registry=registry,
            policy_trust=policy_trust,
            valuation_approval=quote_approval,
            valuation_trust=valuation_trust,
            root_trust=RootTrustStore([authority]),
            root_pins=pins,
            issuance=signed[0],
            issuers=signed[1],
            sanctions=signed[2],
            now=context.evaluated_at,
        )
    witness = compliance_witness(
        transfer,
        context,
        registry,
        credential,
        secret="123456",
        issuance_path=issuance.membership("alternate" if alternate_credential else "credential"),
        issuer_path=issuers.membership("issuer"),
        sanctions=sanctions,
        valuation_approval=quote_approval,
        valuation_trust=valuation_trust,
        policy_trust=policy_trust,
    )
    if with_trust:
        return witness, context, inputs
    return witness, context


@pytest.fixture
def witness():
    return synthetic_case()[0]


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


def test_actual_manifest_binding_changes_proved_projection():
    first, first_context = synthetic_case(artifact_manifest_digest="ab" * 32)
    second, second_context = synthetic_case(artifact_manifest_digest="cd" * 32)
    assert first_context.artifact_manifest_digest != second_context.artifact_manifest_digest
    assert first["projection_commitment"] != second["projection_commitment"]
    # Changing artifacts must not create another spend of the same authorization.
    assert first["authorization_nullifier"] == second["authorization_nullifier"]


def test_valid_credential_substitution_requires_a_different_public_commitment(compiled, tmp_path):
    original, context = synthetic_case()
    alternate, alternate_context = synthetic_case(alternate_credential=True)
    assert context == alternate_context
    assert original["authorized_issuer_root"] == alternate["authorized_issuer_root"]
    assert original["issuance_root"] == alternate["issuance_root"]
    assert original["authorization_nullifier"] == alternate["authorization_nullifier"]
    assert original["projection_commitment"] != alternate["projection_commitment"]
    assert calculate(compiled, tmp_path, alternate).returncode == 0
    alternate["projection_commitment"] = original["projection_commitment"]
    result = calculate(compiled, tmp_path, alternate)
    assert result.returncode != 0 and b"Assert Failed" in result.stderr
