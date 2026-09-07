"""Explicit local authorization, distinct from observation and fund execution."""

from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.routes.pilot_proof import EvaluationBody, InspectionTarget, inspection_time, prepare_inspection
from src.auth.principal import Principal, TenantPrincipalDependency
from src.policy.fact_approval import FactTrustStore
from src.protocol.decision_attestation import DecisionSigner
from src.protocol.information_approval import InformationTrustStore
from src.protocol.transfer import OpaqueId
from src.sar.pilot_envelope import RecipientTrustStore
from src.services.authorization_input import SealedAuthorizationInformation
from src.services.enrollment import EnrollmentNotFound
from src.services.proof_authorization import AuthorizationRejected, ProofAuthorizationService
from src.storage.keyring import load_keyring
from src.storage.pilot import RecordConflict, ReplayConflict
from src.storage.pilot_cipher import RecordCipher, RecordIntegrityError

router = APIRouter(prefix="/pilot/proof", tags=["pilot-authorization"])


@dataclass(frozen=True, repr=False, kw_only=True)
class AuthorizationTarget(InspectionTarget):
    """Operator-only app.state.pilot_authorization_targets[(tenant, target_id)]."""

    information: SealedAuthorizationInformation
    information_trust: InformationTrustStore
    decision_signer: DecisionSigner
    recipient_trust: RecipientTrustStore
    recipient_key_id: str


class AuthorizationBody(EvaluationBody):
    idempotency_key: OpaqueId


@router.post("/authorize", summary="Consume a local pilot authorization or retrieve its exact retry receipt")
async def authorize_proof(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    for role in ("proof:consume", "proof:generate", "proof:inspect", "policy:read", "evidence:decrypt"):
        principal.require(role)
    if request.query_params:
        raise HTTPException(status_code=422, detail="Authorization selectors belong in the private body")
    service, target, body, proof, signals = await prepare_inspection(
        request,
        principal,
        AuthorizationBody,
        ProofAuthorizationService,
        target_attribute="pilot_authorization_targets",
        target_type=AuthorizationTarget,
    )
    try:
        if not all(
            (
                isinstance(target.fact_trust, FactTrustStore),
                isinstance(target.information_trust, InformationTrustStore),
                isinstance(target.decision_signer, DecisionSigner),
                isinstance(target.recipient_trust, RecipientTrustStore),
                isinstance(target.information, SealedAuthorizationInformation),
            )
        ):
            raise ValueError("Missing authorization authority")
        if target.verifier.artifacts.manifest.assurance != "development-unapproved":
            raise ValueError("Unsupported authorization assurance")
        pii, approval = target.information.open(
            RecordCipher(load_keyring()),
            tenant_id=principal.tenant_id,
            target_id=body.target_id,
        )
    except (KeyError, ValueError, RuntimeError, TypeError, RecordIntegrityError):
        raise HTTPException(status_code=503, detail="Pilot authorization configuration is unavailable") from None
    try:
        receipt = await service.authorize(
            body.credential_id,
            proof,
            signals,
            body.fact_ids,
            fact_trust=target.fact_trust,
            pii=pii,
            information_approval=approval,
            information_trust=target.information_trust,
            decision_signer=target.decision_signer,
            recipient_trust=target.recipient_trust,
            recipient_key_id=target.recipient_key_id,
            idempotency_key=body.idempotency_key,
            now=inspection_time(),
        )
    except (RecordConflict, ReplayConflict):
        raise HTTPException(status_code=409, detail="Authorization request or consumption conflict") from None
    except EnrollmentNotFound:
        raise HTTPException(status_code=404, detail="Pilot enrollment is unavailable") from None
    except (AuthorizationRejected, ValueError, TypeError, RuntimeError):
        raise HTTPException(status_code=422, detail="Current authorization input or trust checks rejected") from None
    except RecordIntegrityError:
        raise HTTPException(status_code=503, detail="Stored authorization evidence cannot be read") from None
    return {
        "schema_version": "clearproof-authorization-response-v1",
        "scope": "recorded-local-authorization",
        "assurance": "development-unapproved",
        "receipt": receipt,
    }
