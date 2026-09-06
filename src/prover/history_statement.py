"""Reconstruct the captured v2 statement at its claimed authorization time."""

import base64
import json
from dataclasses import dataclass

from src.policy.model import PolicyTrustStore
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.root_snapshot import RootTrustStore, SignedRootSnapshot
from src.protocol.transfer import AssetDefinition, AssetRegistry, Transfer, VerificationContext
from src.protocol.valuation_approval import SignedValuationApproval, ValuationTrustStore
from src.prover.pilot_current import expected_current_signals
from src.prover.pilot_roots import CurrentRootPins


@dataclass(frozen=True, repr=False)
class HistoryStatementTrust:
    """Reviewer configuration for the historical scope; never inferred from a bundle."""

    policy_trust: PolicyTrustStore
    valuation_trust: ValuationTrustStore
    root_trust: RootTrustStore
    root_pins: CurrentRootPins


def reconstruct_history_statement(bundle, verifier, trust: HistoryStatementTrust, signals):
    if not isinstance(trust, HistoryStatementTrust):
        raise ValueError("Independent statement trust required")
    proof, receipt = bundle["proof"], bundle["receipt"]
    transfer = Transfer.model_validate_json(json.dumps(proof["transfer"]))
    context = VerificationContext.model_validate_json(json.dumps(proof["context"]))
    at = receipt["authorized_at"]
    if type(at) is not int or not context.evaluated_at <= at < int(signals[5]):
        raise ValueError("Invalid claimed authorization time")

    def source(kind, identity=None):
        found = [
            r["value"]
            for r in bundle["records"]
            if r["kind"] == kind and (identity is None or r["record_id"] == identity)
        ]
        if len(found) != 1:
            raise ValueError("Expected exact captured source record")
        return found[0]

    def configuration(name):
        return base64.b64decode(bundle["configuration_base64"][name], validate=True)

    enrollment = source("credential", proof["credential_id"])
    if enrollment["schema_version"] != "clearproof-enrolled-credential-v1":
        raise ValueError("Unsupported enrollment evidence")
    consent = EnrollmentConsent.model_validate_json(json.dumps(enrollment["consent"]))
    credential = consent.credential
    consent.verify_wallet_signature(enrollment["signature"])
    if (
        credential.credential_nonce != proof["credential_id"]
        or enrollment["credential_commitment"] != credential.commitment
        or consent.chain_id != trust.root_pins.chain_id
        or consent.registry_address != trust.root_pins.registry_address
        or type(enrollment["accepted_at"]) is not int
        or not credential.issued_at <= enrollment["accepted_at"] < consent.consent_expires_at
        or enrollment["accepted_at"] > at
    ):
        raise ValueError("Enrollment acceptance scope mismatch")
    captured_pins = CurrentRootPins.model_validate_json(configuration("root_pins"))
    if captured_pins != trust.root_pins:
        raise ValueError("Captured root pins are not independently approved")
    registry = AssetRegistry([AssetDefinition.model_validate(a) for a in json.loads(configuration("asset_registry"))])
    roots = {
        name: SignedRootSnapshot.model_validate_json(json.dumps(source(kind)))
        for name, kind in (("issuance", "issuance-root"), ("issuers", "issuer-root"), ("sanctions", "sanctions-root"))
    }
    return expected_current_signals(
        artifacts=verifier.artifacts,
        transfer=transfer,
        context=context,
        credential=credential,
        registry=registry,
        policy_trust=trust.policy_trust,
        valuation_trust=trust.valuation_trust,
        valuation_approval=SignedValuationApproval.model_validate_json(configuration("valuation_approval")),
        root_trust=trust.root_trust,
        root_pins=trust.root_pins,
        signals=signals,
        now=at,
        **roots,
    )
