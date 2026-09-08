"""Actual legacy circuit acceptance using real fixed-depth registry builders."""

import json
import os
import time
from types import SimpleNamespace

import pytest

from src.registry.poseidon import poseidon_hash


@pytest.mark.skipif(not os.getenv("CLEARPROOF_LEGACY_TEST_ARTIFACTS"), reason="requires legacy development artifacts")
async def test_api_generates_a_real_legacy_proof(monkeypatch, tmp_path):
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("PII_ENVELOPE_MODE", "legacy-v1")
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "synthetic")
    from src.api.routes import proof
    from src.prover.snarkjs_prover import SnarkJSProver
    from src.registry.credential_registry import CredentialRegistry, zkKYCCredential
    from src.registry.issuer_registry import IssuerRegistry
    from src.registry.sanctions_list import SanctionsMerkleTree

    tree = SanctionsMerkleTree(depth=20)
    root = await tree.build_from_addresses([])
    wallet = next("0x" + format(i, "040x") for i in range(1, 100) if poseidon_hash([1, i]) < tree._MAX_SENTINEL)
    now = int(time.time())
    credential = zkKYCCredential(
        issuer_did="did:web:synthetic.example",
        subject_wallet=wallet,
        jurisdiction="US",
        kyc_tier="retail",
        sanctions_clear=True,
        issued_at=now - 60,
        expires_at=now + 7200,
    )
    registry = CredentialRegistry()
    await registry.issue(credential)
    issuer = IssuerRegistry(depth=10)
    issuer_root = await issuer.add_issuer(credential.issuer_did)
    monkeypatch.setattr(proof, "_issuer_registry", issuer)
    prover = SnarkJSProver(artifacts_dir=os.environ["CLEARPROOF_LEGACY_TEST_ARTIFACTS"], prove_timeout=120)
    monkeypatch.setattr(proof, "_prover", prover)
    monkeypatch.setenv("CIRCUIT_ARTIFACTS_DIR", str(tmp_path))
    (tmp_path / "verification_key.json").write_bytes(prover.vkey_path.read_bytes())
    (tmp_path / "sanctions_tree.json").write_text(
        json.dumps(
            {
                "root": root,
                "sorted_leaves": tree.sorted_leaves,
                "depth": tree.depth,
                "tree_layers": tree._tree,
            }
        )
    )
    request = proof.ProofGenerateRequest(
        credential_id=credential.credential_id,
        wallet_address=wallet,
        amount_usd=10,
        asset="USDC",
        destination_wallet="0x" + "2" * 40,
        jurisdiction="US",
        idempotency_key="real-proof",
    )
    result = await proof.generate_proof(
        request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db=None))), _cred_registry=registry
    )
    generated = result["compliance_proof"]
    assert await prover.verify(json.loads(generated["groth16_proof"]), generated["public_signals"])
    assert json.loads(generated["verification_key"]) == json.loads(prover.vkey_path.read_text())
    assert int(generated["public_signals"][2]) == int(root)
    assert int(generated["public_signals"][3]) == int(issuer_root)
    assert int(generated["public_signals"][5]) == generated["proof_generated_at"]
    assert int(generated["public_signals"][15]) == generated["proof_expires_at"]
