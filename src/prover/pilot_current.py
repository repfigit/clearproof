"""Reconstruct the current v2 statement from independent trust and exact records.

This is read-only proof inspection, not policy authorization or consumption.
Durable enrollment/revocation and authenticated business facts remain caller duties.
"""

from src.policy.model import PolicyTrustStore
from src.protocol.credential import PilotCredential
from src.protocol.root_snapshot import RootTrustStore, SignedRootSnapshot
from src.protocol.transfer import AssetRegistry, Transfer, VerificationContext
from src.protocol.valuation_approval import SignedValuationApproval, ValuationTrustStore
from src.prover.pilot_artifacts import InspectedArtifacts
from src.prover.pilot_compliance import credential_bound_projection
from src.prover.pilot_projection import project_transfer
from src.prover.pilot_roots import CurrentRootPins, verify_pilot_roots
from src.prover.pilot_verifier import PairingInspection, PilotPairingVerifier, ProofInspectionError, public_signals


def expected_current_signals(
    *,
    artifacts: InspectedArtifacts,
    transfer: Transfer,
    context: VerificationContext,
    credential: PilotCredential,
    registry: AssetRegistry,
    policy_trust: PolicyTrustStore,
    valuation_approval: SignedValuationApproval,
    valuation_trust: ValuationTrustStore,
    root_trust: RootTrustStore,
    root_pins: CurrentRootPins,
    issuance: SignedRootSnapshot,
    issuers: SignedRootSnapshot,
    sanctions: SignedRootSnapshot,
    signals: list[str],
    now: int,
) -> tuple[str, ...]:
    """Pins, trust, context, credential and clock come from authenticated server state.

    The prover supplies a nullifier and bounded expiry; the circuit proves their
    derivation/limits. All other signals are reconstructed independently. The
    caller must still check/consume the nullifier atomically with current state.
    """
    transfer = Transfer.model_validate(transfer)
    context = VerificationContext.model_validate(context)
    credential = PilotCredential.model_validate(credential)
    root_pins = CurrentRootPins.model_validate(root_pins)
    observed = public_signals(signals)
    artifacts.check_artifact_context(context)
    roots = verify_pilot_roots(
        trust=root_trust,
        pins=root_pins,
        context=context,
        issuance=issuance,
        issuers=issuers,
        sanctions=sanctions,
        now=now,
    )
    # Apply transfer freshness to the verifier clock as well as evaluation time.
    VerificationContext.model_validate({**context.model_dump(), "evaluated_at": now}).check_transfer(transfer)
    if (
        (credential.tenant_id, credential.subject_wallet, credential.jurisdiction, credential.issuer_did)
        != (transfer.tenant_id, transfer.originator.wallet, transfer.jurisdiction, roots.issuance.issuer_did)
        or not credential.issued_at <= context.evaluated_at <= now < credential.expires_at
        or not credential.sanctions_clear
    ):
        raise ProofInspectionError("credential_context_mismatch")
    policy = policy_trust.for_transfer(transfer, context, tenant_id=root_pins.tenant_id, now=now)
    for at in (context.evaluated_at, now):
        valuation_trust.verify_for_transfer(
            valuation_approval, transfer, registry, tenant_id=root_pins.tenant_id, now=at
        )
    projection = project_transfer(transfer, context, registry, policy.tier_thresholds_usd_cents)
    expiry = int(observed[5])
    if not now < expiry <= min(transfer.expires_at, credential.expires_at, context.evaluated_at + 300):
        raise ProofInspectionError("proof_expired_or_invalid_lifetime")
    return (
        credential_bound_projection(projection.commitment, credential.commitment, roots.issuance.root),
        roots.issuers.root,
        roots.sanctions.root,
        observed[3],
        str(context.evaluated_at),
        observed[5],
        context.deployment_chain_id,
        str(int(context.deployment_address, 16)),
    )


async def inspect_current_statement(
    verifier: PilotPairingVerifier, proof: bytes, *, signals: list[str], **trusted_inputs
) -> PairingInspection:
    """Pair only against reconstructed expectations; no caller-supplied expected vector."""
    expected = expected_current_signals(artifacts=verifier.artifacts, signals=signals, **trusted_inputs)
    return await verifier.inspect(proof, signals, expected_signals=list(expected))
