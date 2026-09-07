"""Explicit reviewer delegation for a pilot registry's signed status observation."""

import json

from pydantic import Field, field_validator

from src.protocol.canonical import record_digest
from src.protocol.decision_attestation import DecisionAuthority, DecisionTrustStore, SignedDecision
from src.protocol.discovery_profile import parse_target
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.transfer import Hex32, VerificationContext


def status_registry_id(context: VerificationContext) -> str:
    return record_digest(
        "clearproof/local-status-registry/v1",
        {
            "tenant_id": context.tenant_id,
            "chain_id": context.deployment_chain_id,
            "registry_address": context.deployment_address,
        },
    )


class HistoryStatusAuthority(DecisionAuthority):
    """Independent approval of the signer as status authority for this issuer."""

    registry_id: Hex32
    issuer_did: str = Field(max_length=512)

    @field_validator("issuer_did")
    @classmethod
    def canonical_issuer(cls, value):
        if parse_target(value).did != value:
            raise ValueError("Expected canonical issuer identity")
        return value


class HistoryStatusTrust:
    def __init__(self, authorities: list[HistoryStatusAuthority]):
        self._authorities = tuple(HistoryStatusAuthority.model_validate(a) for a in authorities)
        scopes = {(a.key_id, a.registry_id, a.issuer_did) for a in self._authorities}
        if not 1 <= len(self._authorities) <= 256 or len(scopes) != len(self._authorities):
            raise ValueError("Expected distinct independently approved status authorities")

    def verify(self, bundle: dict, *, verified_at: int) -> None:
        """Called after bundle integrity and independent credential reconstruction."""
        proof, receipt, manifest = bundle["proof"], bundle["receipt"], bundle["evidence_manifest"]
        context = VerificationContext.model_validate_json(json.dumps(proof["context"]))
        signed = SignedDecision.model_validate_json(json.dumps(proof["decision_attestation"]))
        status = manifest["credential_status"]
        if (
            record_digest("clearproof/authorization-evidence/v1", manifest) != receipt["evidence_id"]
            or status.get("schema_version") != "clearproof-local-status-observation-v1"
            or status["registry_id"] != status_registry_id(context)
            or status["credential_id"] != proof["credential_id"]
            or status["revocation"] != "not-present-in-local-store"
            or type(status["observed_at"]) is not int
            or status["observed_at"] != receipt["authorized_at"]
            or type(manifest["captured_at"]) is not int
            or manifest["captured_at"] != status["observed_at"]
        ):
            raise ValueError("Required historical status observation is unavailable")
        records = [
            r["value"]
            for r in bundle["records"]
            if r["kind"] == "credential" and r["record_id"] == proof["credential_id"]
        ]
        if len(records) != 1:
            raise ValueError("Required credential evidence is unavailable")
        credential = EnrollmentConsent.model_validate_json(json.dumps(records[0]["consent"])).credential
        if (
            credential.credential_nonce != status["credential_id"]
            or credential.issuer_did != status["issuer_did"]
            or credential.tenant_id != context.tenant_id
        ):
            raise ValueError("Status observation credential scope mismatch")
        matches = [
            a
            for a in self._authorities
            if a.key_id == signed.statement.key_id
            and a.registry_id == status["registry_id"]
            and a.issuer_did == credential.issuer_did
        ]
        if len(matches) != 1:
            raise ValueError("Historical status authority unavailable")
        # Recheck the signature and compromise/validity policy independently of
        # decision authority. Status delegation never comes from the bundle.
        key_authority = DecisionAuthority.model_validate(
            matches[0].model_dump(include=set(DecisionAuthority.model_fields))
        )
        DecisionTrustStore([key_authority]).verify(signed, receipt, context, verified_at=verified_at)
