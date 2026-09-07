"""Current v2 inspection with operator-selected trust and no authorization writes."""

import time
from dataclasses import asdict, dataclass

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field

from src.api.request_body import read_private_body
from src.auth.principal import Principal, TenantPrincipalDependency
from src.policy.fact_approval import FactTrustStore
from src.protocol.transfer import Hex32, OpaqueId, Record
from src.prover.pilot_artifacts import strict_json
from src.prover.pilot_verifier import PilotPairingVerifier, PilotProof, public_signals
from src.services.enrollment import EnrollmentNotFound
from src.services.observation_report import (
    ObservationCohort,
    ObservationPageRequest,
    list_observations,
    observation_cohort_report,
)
from src.services.proof_inspection import CurrentStatementConfiguration, ProofInspectionService
from src.services.proof_observation import ProofObservationService, read_observation
from src.storage.keyring import load_keyring
from src.storage.pilot import RecordConflict
from src.storage.pilot_cipher import RecordCipher, RecordIntegrityError

router = APIRouter(prefix="/pilot/proof", tags=["pilot-proof"])


@dataclass(frozen=True, repr=False)
class InspectionTarget:
    """Provision in app.state.pilot_inspection_targets[(tenant_id, target_id)].

    Only the operator can install targets. Request bodies cannot select artifact
    paths, runtime executables, source keys, roots, policy pins or verifier clocks.
    """

    configuration: CurrentStatementConfiguration
    verifier: PilotPairingVerifier
    fact_trust: FactTrustStore | None = None


class InspectionBody(Record):
    target_id: OpaqueId
    credential_id: OpaqueId
    proof_json: str = Field(min_length=1, max_length=8192)
    public_signals: list[str] = Field(min_length=8, max_length=8)


class EvaluationBody(InspectionBody):
    fact_ids: tuple[Hex32, ...] = Field(max_length=64)


class ObservationBody(EvaluationBody):
    idempotency_key: OpaqueId


class ObservationReadBody(Record):
    observation_id: Hex32


def inspection_time() -> int:
    return int(time.time())


async def prepare_inspection(
    request: Request,
    principal: Principal,
    model: type[InspectionBody],
    service_type: type[ProofInspectionService] = ProofInspectionService,
    *,
    target_attribute: str = "pilot_inspection_targets",
    target_type: type[InspectionTarget] = InspectionTarget,
):
    raw = await read_private_body(request, limit=16384)
    try:
        strict_json(raw, limit=16384)
        body = model.model_validate_json(raw)
        proof = body.proof_json.encode("utf-8")
        PilotProof.parse(proof)
        signals = public_signals(body.public_signals)
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid pilot proof input") from None
    targets = getattr(request.app.state, target_attribute, None)
    if not isinstance(targets, dict):
        raise HTTPException(status_code=503, detail="Pilot inspection configuration is unavailable")
    target = targets.get((principal.tenant_id, body.target_id))
    if target is None:
        raise HTTPException(status_code=404, detail="Pilot inspection target is unavailable")
    if not isinstance(target, target_type):
        raise HTTPException(status_code=503, detail="Pilot inspection configuration is unavailable")
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        service = service_type(db, RecordCipher(load_keyring()), principal, target.verifier, target.configuration)
    except (ValueError, TypeError, KeyError, RuntimeError):
        raise HTTPException(status_code=503, detail="Pilot inspection configuration is unavailable") from None
    return service, target, body, proof, signals


@router.post("/inspect", summary="Inspect a current pilot proof without authorizing or consuming it")
async def inspect_proof(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("proof:inspect")
    principal.require("evidence:decrypt")
    service, target, body, proof, signals = await prepare_inspection(request, principal, InspectionBody)
    try:
        result = await service.inspect(body.credential_id, proof, signals, now=inspection_time())
    except EnrollmentNotFound:
        raise HTTPException(status_code=404, detail="Pilot enrollment is unavailable") from None
    except (ValueError, TypeError, RuntimeError):
        raise HTTPException(status_code=422, detail="Current pilot proof or trust checks rejected") from None
    return {
        "schema_version": "clearproof-current-inspection-v1",
        "scope": "current-statement-inspection",
        "authorization_consumed": False,
        "assurance": target.verifier.artifacts.manifest.assurance,
        **asdict(result),
    }


@router.post("/evaluate", summary="Evaluate current proof and retained facts without consuming authorization")
async def evaluate_proof(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    for role in ("proof:inspect", "policy:read", "evidence:decrypt"):
        principal.require(role)
    service, target, body, proof, signals = await prepare_inspection(request, principal, EvaluationBody)
    if not isinstance(target.fact_trust, FactTrustStore):
        raise HTTPException(status_code=503, detail="Pilot fact authority configuration is unavailable")
    try:
        inspection, policy = await service.evaluate(
            body.credential_id,
            proof,
            signals,
            body.fact_ids,
            fact_trust=target.fact_trust,
            now=inspection_time(),
        )
    except EnrollmentNotFound:
        raise HTTPException(status_code=404, detail="Pilot enrollment is unavailable") from None
    except (ValueError, TypeError, RuntimeError):
        raise HTTPException(status_code=422, detail="Current pilot proof, facts or trust checks rejected") from None
    return {
        "schema_version": "clearproof-current-evaluation-v1",
        "scope": "current-policy-evaluation",
        "authorization_consumed": False,
        "assurance": target.verifier.artifacts.manifest.assurance,
        "inspection": asdict(inspection),
        "policy": policy.model_dump(mode="json") if policy is not None else None,
    }


@router.post("/observe", summary="Retain a non-enforcing proof observation with idempotent retries")
async def observe_proof(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    for role in ("observations:write", "proof:inspect", "policy:read", "evidence:decrypt"):
        principal.require(role)
    service, target, body, proof, signals = await prepare_inspection(
        request, principal, ObservationBody, ProofObservationService
    )
    if not isinstance(target.fact_trust, FactTrustStore):
        raise HTTPException(status_code=503, detail="Pilot fact authority configuration is unavailable")
    try:
        return await service.observe(
            body.credential_id,
            proof,
            signals,
            body.fact_ids,
            fact_trust=target.fact_trust,
            idempotency_key=body.idempotency_key,
            now=inspection_time(),
        )
    except RecordConflict:
        raise HTTPException(status_code=409, detail="Observation request or idempotency conflict") from None
    except EnrollmentNotFound:
        raise HTTPException(status_code=404, detail="Pilot enrollment is unavailable") from None
    except (ValueError, TypeError, RuntimeError):
        raise HTTPException(status_code=422, detail="Current observation input or trust checks rejected") from None


@router.post("/observations/read", summary="Read a retained tenant observation without current reevaluation")
async def get_observation(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    for role in ("policy:read", "evidence:decrypt"):
        principal.require(role)
    raw = await read_private_body(request, limit=1024)
    try:
        strict_json(raw, limit=1024)
        body = ObservationReadBody.model_validate_json(raw)
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid observation reference") from None
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        cipher = RecordCipher(load_keyring())
    except (KeyError, ValueError, RuntimeError):
        raise HTTPException(status_code=503, detail="Pilot encryption configuration is unavailable") from None
    try:
        report = await read_observation(db, cipher, principal, body.observation_id)
    except (ValueError, TypeError, RecordIntegrityError):
        raise HTTPException(status_code=503, detail="Stored observation cannot be read") from None
    if report is None:
        raise HTTPException(status_code=404, detail="Observation is unavailable")
    return report


@router.post("/observations/report", summary="Summarize an explicit cohort of retained tenant observations")
async def report_observations(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    for role in ("policy:read", "evidence:decrypt"):
        principal.require(role)
    raw = await read_private_body(request, limit=16384)
    try:
        strict_json(raw, limit=16384)
        cohort = ObservationCohort.model_validate_json(raw)
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid observation cohort") from None
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        cipher = RecordCipher(load_keyring())
        return await observation_cohort_report(db, cipher, principal, cohort)
    except (KeyError, ValueError, RuntimeError, TypeError, RecordIntegrityError):
        raise HTTPException(status_code=503, detail="Observation cohort cannot be read") from None


@router.post("/observations/list", summary="Discover retained tenant observations with bounded live pagination")
async def discover_observations(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    for role in ("policy:read", "evidence:decrypt"):
        principal.require(role)
    raw = await read_private_body(request, limit=1024)
    try:
        strict_json(raw, limit=1024)
        page = ObservationPageRequest.model_validate_json(raw)
        if request.query_params:
            raise ValueError("Selectors belong in the private body")
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid observation page") from None
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        return await list_observations(db, RecordCipher(load_keyring()), principal, page)
    except (KeyError, ValueError, RuntimeError, TypeError, RecordIntegrityError):
        raise HTTPException(status_code=503, detail="Observation page cannot be read") from None
