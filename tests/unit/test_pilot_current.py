"""Independent current expectations without using the witness builder as verifier."""

import runpy
from pathlib import Path

import pytest

from src.policy.model import PolicyTrustStore
from src.protocol.credential import PilotCredential
from src.protocol.valuation_approval import SignedValuationApproval
from src.prover.pilot_artifacts import inspect_artifacts
from src.prover.pilot_compliance import PUBLIC_SIGNALS
from src.prover.pilot_current import expected_current_signals


@pytest.fixture
def current_case(tmp_path):
    artifacts_fixture = runpy.run_path(str(Path(__file__).with_name("test_pilot_artifacts.py")))["bundle"]
    root, _, pin = artifacts_fixture.__wrapped__(tmp_path)
    helper = runpy.run_path(str(Path(__file__).with_name("test_pilot_compliance.py")))["synthetic_case"]
    witness, _, inputs = helper(artifact_manifest_digest=pin, with_trust=True)
    return {
        **inputs,
        "artifacts": inspect_artifacts(root, trusted_digest=pin),
        "signals": [witness[name] for name in PUBLIC_SIGNALS],
    }


def test_reconstructed_statement_matches_valid_witness(current_case):
    assert expected_current_signals(**current_case) == tuple(current_case["signals"])


@pytest.mark.parametrize("change", ["expiry", "future", "stale", "quote", "policy", "credential", "issuer"])
def test_current_expectations_reject_untrusted_or_stale_evidence(current_case, change):
    args = current_case
    if change == "expiry":
        args["signals"][5] = str(args["now"])
    elif change == "future":
        args["now"] -= 1
    elif change == "stale":
        args["now"] = args["transfer"].expires_at
    elif change == "quote":
        args["valuation_approval"] = SignedValuationApproval.model_validate(
            {**args["valuation_approval"].model_dump(), "signature": "00" * 64}
        )
    elif change == "policy":
        pass  # Construct a different, valid current policy below.
    elif change == "credential":
        args["credential"] = PilotCredential.model_validate(
            {**args["credential"].model_dump(), "subject_wallet": "0x" + "34" * 20}
        )
    else:
        args["credential"] = PilotCredential.model_validate(
            {**args["credential"].model_dump(), "issuer_did": "did:web:other.example"}
        )
    if change == "policy":
        # A valid policy inventory with a different current revision must reject.
        original = args["transfer"]
        from src.policy.model import PilotPolicy, PolicySource

        policy = PilotPolicy(
            policy_id="other",
            revision=1,
            tenant_id=original.tenant_id,
            chain_id=args["context"].deployment_chain_id,
            registry_address=args["context"].deployment_address,
            jurisdiction=original.jurisdiction,
            asset_registry_digest=original.asset_registry_digest,
            effective_from=original.created_at,
            effective_until=original.expires_at,
            tier_thresholds_usd_cents=("1", "2", "3"),
            sources=(
                PolicySource(
                    source_id="test",
                    kind="synthetic",
                    reference="urn:clearproof:synthetic:test",
                    evidence_digest="ab" * 32,
                    reviewed_at=original.created_at,
                    valid_until=original.expires_at,
                ),
            ),
        )
        args["policy_trust"] = PolicyTrustStore([policy], current_digests=(policy.digest,))
    with pytest.raises(ValueError):
        expected_current_signals(**args)


def test_same_wallet_different_credential_changes_expected_statement(current_case):
    original = expected_current_signals(**current_case)
    current_case["credential"] = PilotCredential.model_validate(
        {**current_case["credential"].model_dump(), "credential_nonce": "cd" * 32}
    )
    alternate = expected_current_signals(**current_case)
    assert alternate[0] != original[0]
    assert alternate[1:] == original[1:]
