"""Actual legacy circuit acceptance for the API's assembled witness."""

import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.registry.poseidon import poseidon_hash


@pytest.mark.skipif(not os.getenv("CLEARPROOF_LEGACY_TEST_ARTIFACTS"), reason="requires legacy development artifacts")
async def test_api_generates_a_real_legacy_proof(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("PII_ENVELOPE_MODE", "legacy-v1")
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "synthetic")
    from src.api.routes import proof
    from src.prover.snarkjs_prover import SnarkJSProver
    from src.registry.credential_registry import CredentialRegistry, zkKYCCredential

    now = int(time.time())
    credential = zkKYCCredential(
        issuer_did="did:web:synthetic.example",
        subject_wallet="0x" + "1" * 40,
        jurisdiction="US",
        kyc_tier="retail",
        sanctions_clear=True,
        issued_at=now - 60,
        expires_at=now + 7200,
    )
    registry = CredentialRegistry()
    await registry.issue(credential)
    zeros = [0]
    for _ in range(20):
        zeros.append(poseidon_hash([zeros[-1], zeros[-1]]))
    issuer_root = poseidon_hash([2, proof._encode_did(credential.issuer_did)])
    for sibling in zeros[:10]:
        issuer_root = poseidon_hash([issuer_root, sibling])
    issuer = SimpleNamespace(
        root=str(issuer_root),
        get_root=Mock(return_value=str(issuer_root)),
        generate_membership_witness=AsyncMock(
            return_value={"siblings": list(map(str, zeros[:10])), "indices": [0] * 10}
        ),
    )
    monkeypatch.setattr(proof, "_issuer_registry", issuer)
    maximum = 2**252 - 1
    wallet = next("0x" + format(i, "040x") for i in range(1, 100) if poseidon_hash([1, i]) < maximum)
    root = poseidon_hash([0, maximum])
    for sibling in zeros[1:20]:
        root = poseidon_hash([root, sibling])
    witness = {
        "left_neighbor": 0,
        "right_neighbor": maximum,
        "left_path": {"siblings": list(map(str, [maximum] + zeros[1:20])), "indices": [0] * 20},
        "right_path": {"siblings": list(map(str, [0] + zeros[1:20])), "indices": [1] + [0] * 19},
    }
    tree = SimpleNamespace(root=str(root), generate_nonmembership_witness=AsyncMock(return_value=witness))
    monkeypatch.setattr(proof.SanctionsMerkleTree, "load", Mock(return_value=tree))
    prover = SnarkJSProver(artifacts_dir=os.environ["CLEARPROOF_LEGACY_TEST_ARTIFACTS"], prove_timeout=120)
    monkeypatch.setattr(proof, "_prover", prover)
    monkeypatch.setenv("CIRCUIT_ARTIFACTS_DIR", str(prover.vkey_path.parent))
    credential.subject_wallet = wallet
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
    import json

    generated = result["compliance_proof"]
    assert await prover.verify(json.loads(generated["groth16_proof"]), generated["public_signals"])
    assert int(generated["public_signals"][2]) == root
    assert int(generated["public_signals"][3]) == issuer_root
    assert int(generated["public_signals"][5]) == generated["proof_generated_at"]
    assert int(generated["public_signals"][15]) == generated["proof_expires_at"]
