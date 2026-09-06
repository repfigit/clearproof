"""Witness encoder for pilot-transfer-v1; not an authorization verifier.

Callers must authenticate records, policy/quote provenance, roots and current
revocation separately. Returned private inputs must never be logged or stored
outside an encrypted envelope.
"""

from src.policy.model import PolicyTrustStore
from src.protocol.credential import PilotCredential
from src.protocol.transfer import AssetRegistry, Transfer, VerificationContext
from src.protocol.valuation_approval import SignedValuationApproval, ValuationTrustStore
from src.prover.pilot_projection import project_transfer
from src.registry.pilot_sanctions import PilotSanctionsTree

PUBLIC_SIGNALS = (
    "projection_commitment",
    "authorized_issuer_root",
    "sanctions_root",
    "authorization_nullifier",
    "evaluated_at",
    "proof_expires_at",
    "domain_chain_id",
    "domain_registry",
)
PROFILE = "pilot-transfer-v1"


def compliance_witness(
    transfer: Transfer,
    context: VerificationContext,
    registry: AssetRegistry,
    credential: PilotCredential,
    *,
    secret: str,
    issuance_path: dict,
    issuer_path: dict,
    sanctions: PilotSanctionsTree,
    valuation_approval: SignedValuationApproval,
    valuation_trust: ValuationTrustStore,
    policy_trust: PolicyTrustStore,
) -> dict:
    transfer = Transfer.model_validate(transfer)
    context = VerificationContext.model_validate(context)
    # Witness construction checks the quote at the claimed evaluation time.
    # Current authorization must independently check freshness using its clock.
    valuation_trust.verify_for_transfer(
        valuation_approval, transfer, registry, tenant_id=context.tenant_id, now=context.evaluated_at
    )
    policy = policy_trust.for_transfer(transfer, context, tenant_id=context.tenant_id, now=context.evaluated_at)
    projection = project_transfer(transfer, context, registry, policy.tier_thresholds_usd_cents)
    credential = PilotCredential.model_validate(credential)
    if context.proof_profile != PROFILE:
        raise ValueError("Unsupported composed proof profile")
    if (credential.tenant_id, credential.subject_wallet, credential.jurisdiction) != (
        transfer.tenant_id,
        transfer.originator.wallet,
        transfer.jurisdiction,
    ):
        raise ValueError("Credential does not bind the transfer originator")
    if sanctions.depth != 8 or any(len(path["siblings"]) != 8 for path in (issuance_path, issuer_path)):
        raise ValueError("Composed profile requires depth-eight trees")
    data = credential.witness(
        secret=secret,
        evaluated_at=context.evaluated_at,
        issuance_root=issuance_path["root"],
        authorized_issuer_root=issuer_path["root"],
        issuance_siblings=issuance_path["siblings"],
        issuance_indices=issuance_path["indices"],
        issuer_siblings=issuer_path["siblings"],
        issuer_indices=issuer_path["indices"],
    )
    data["credential_fields"] = data.pop("fields")
    for name in ("expected_tenant", "expected_subject", "expected_jurisdiction"):
        del data[name]
    data.update(projection.witness())
    data.update(
        sanctions_root=sanctions.root,
        authorization_nullifier=projection.nullifier(secret),
        proof_expires_at=str(min(transfer.expires_at, credential.expires_at, context.evaluated_at + 300)),
        domain_chain_id=context.deployment_chain_id,
        domain_registry=str(int(context.deployment_address, 16)),
    )
    gaps = [sanctions.gap(p.wallet) for p in (transfer.originator, transfer.beneficiary)]
    for output, source in (
        ("left_keys", "left_key"),
        ("right_keys", "right_key"),
        ("left_siblings", "left_siblings"),
        ("right_siblings", "right_siblings"),
        ("left_indices", "left_indices"),
        ("right_indices", "right_indices"),
    ):
        data["sanctions_" + output] = [gap[source] for gap in gaps]
    return data
