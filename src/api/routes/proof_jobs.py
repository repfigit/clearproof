"""Durable current-profile proving admission, retrieval, cancellation and retry."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from psycopg import Error as DatabaseError

from src.api.request_body import read_private_body
from src.auth.principal import Principal, TenantPrincipalDependency
from src.prover.pilot_artifacts import strict_json
from src.services.proof_jobs import GenerationBody, ProofJobService
from src.storage.keyring import load_keyring
from src.storage.pilot_cipher import RecordCipher, RecordIntegrityError
from src.storage.proof_jobs import ProofJobError, authorize

router = APIRouter(prefix="/pilot/proof/jobs", tags=["pilot-proof-jobs"])


def service(request: Request, principal: Principal):
    authorize(principal)
    if request.query_params:
        raise HTTPException(status_code=422, detail="Job selectors cannot be supplied in query parameters")
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        return ProofJobService(
            db, RecordCipher(load_keyring()), getattr(request.app.state, "pilot_proving_targets", None)
        )
    except (ValueError, TypeError, KeyError, RuntimeError):
        raise HTTPException(status_code=503, detail="Pilot proving configuration is unavailable") from None


def rejection(exc: ProofJobError):
    code = str(exc)
    if code in ("job_not_found", "proving_target_not_found"):
        return HTTPException(status_code=404, detail="Pilot proof job or target is unavailable")
    if code == "proof_queue_full":
        return HTTPException(status_code=429, detail="Pilot proving queue is full", headers={"Retry-After": "5"})
    if code in ("job_idempotency_conflict", "job_already_completed", "job_retry_unavailable"):
        return HTTPException(status_code=409, detail="Pilot proof job conflicts with its retained state")
    if code == "proving_configuration_unavailable":
        return HTTPException(status_code=503, detail="Pilot proving configuration is unavailable")
    return HTTPException(status_code=422, detail="Invalid pilot proof job input")


@router.post("", status_code=202, summary="Queue an encrypted current pilot proving request")
async def enqueue_job(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    jobs = service(request, principal)
    raw = await read_private_body(request, limit=2048)
    try:
        strict_json(raw, limit=2048)
        body = GenerationBody.model_validate_json(raw)
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid pilot proving request") from None
    try:
        job = await jobs.enqueue(principal, body)
    except ProofJobError as exc:
        raise rejection(exc) from None
    except (DatabaseError, RecordIntegrityError, RuntimeError, TypeError, ValueError):
        raise HTTPException(status_code=503, detail="Pilot proof job cannot be retained") from None
    return JSONResponse(
        {"schema_version": "clearproof-proof-job-v1", "authorization_consumed": False, **job.metadata()},
        status_code=202,
        headers={"Cache-Control": "no-store", "Location": f"/pilot/proof/jobs/{job.job_id}"},
    )


@router.get("/{job_id}", summary="Read owned job metadata and a currently valid completed result")
async def read_job(job_id: str, request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    jobs = service(request, principal)
    try:
        response = await jobs.read(principal, job_id)
    except ProofJobError as exc:
        raise rejection(exc) from None
    except (DatabaseError, RecordIntegrityError, ValueError, TypeError, RuntimeError):
        raise HTTPException(status_code=503, detail="Stored pilot proof job cannot be read") from None
    return JSONResponse(response, headers={"Cache-Control": "no-store"})


async def change_job(job_id, request, principal, *, retry):
    jobs = service(request, principal)
    # Authenticate and authorize before even reading an optional body. No
    # overrides, deadlines, replacement inputs or reset-attempt flags are allowed.
    if await read_private_body(request, limit=2) not in (b"", b"{}"):
        raise HTTPException(status_code=422, detail="Job operation does not accept input")
    try:
        status = await (jobs.queue.retry if retry else jobs.queue.cancel)(principal, job_id)
    except ProofJobError as exc:
        raise rejection(exc) from None
    except (DatabaseError, RecordIntegrityError, RuntimeError):
        raise HTTPException(status_code=503, detail="Pilot proof job operation is unavailable") from None
    return JSONResponse(
        {"job_id": job_id, "status": status, "authorization_consumed": False},
        status_code=202 if status in ("queued", "proving", "cancelling") else 200,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/{job_id}/cancel", summary="Cancel an owned queued or running proof job")
async def cancel_job(job_id: str, request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    return await change_job(job_id, request, principal, retry=False)


@router.post("/{job_id}/retry", summary="Retry an owned failed job within its original deadline and attempt limit")
async def retry_job(job_id: str, request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    return await change_job(job_id, request, principal, retry=True)
