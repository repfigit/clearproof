"""Conditional replay of captured policy evidence; not historical authorization."""

import json

from src.policy.evaluator import PolicyEvaluation, evaluate_policy, with_verified_statement_facts
from src.policy.fact_approval import FactTrustStore, SignedFactApproval
from src.protocol.canonical import record_digest
from src.protocol.transfer import Transfer, VerificationContext


def replay_history_policy(bundle, statement_trust, fact_trust: FactTrustStore, signals) -> bool:
    """Called only after successful independent statement reconstruction and pairing.

    The replay conditions on the captured local non-revocation observation. It
    does not authenticate that observation or the claimed authorization time.
    """
    proof, receipt = bundle["proof"], bundle["receipt"]
    transfer = Transfer.model_validate_json(json.dumps(proof["transfer"]))
    context = VerificationContext.model_validate_json(json.dumps(proof["context"]))
    at = receipt["authorized_at"]
    status = bundle["evidence_manifest"]["credential_status"]
    if (
        status["credential_id"] != proof["credential_id"]
        or status["revocation"] != "not-present-in-local-store"
        or type(status["observed_at"]) is not int
        or status["observed_at"] != at
    ):
        raise ValueError("Captured local status observation is unavailable")
    references = proof["fact_ids"]
    if type(references) is not list or len(references) > 64 or len(set(references)) != len(references):
        raise ValueError("Invalid captured fact references")
    sources = {r["record_id"]: r["value"] for r in bundle["records"] if r["kind"] == "fact-evidence"}
    if set(sources) != set(references):
        raise ValueError("Captured facts do not match the decision")
    approvals = []
    for identity in references:
        record = sources[identity]
        if record["schema_version"] != "clearproof-retained-fact-v1":
            raise ValueError("Unsupported retained fact schema")
        signed = SignedFactApproval.model_validate_json(json.dumps(record["signed"]))
        if record_digest("clearproof/fact-evidence/v1", signed.model_dump(mode="json")) != identity:
            raise ValueError("Captured fact identity mismatch")
        approvals.append(signed)
    external = fact_trust.verify_for_context(
        tuple(approvals), transfer=transfer, context=context, tenant_id=transfer.tenant_id, now=at
    )
    facts = with_verified_statement_facts(
        external, proof_digest=proof["proof_digest"], expires_at=int(signals[5]), observed_at=at
    )
    policy = statement_trust.policy_trust.for_transfer(transfer, context, tenant_id=transfer.tenant_id, now=at)
    replayed = evaluate_policy(policy, transfer, context, facts, now=at)
    recorded = PolicyEvaluation.model_validate_json(json.dumps(proof["policy_evaluation"]))
    return replayed == recorded and replayed.outcome == receipt["outcome"]
