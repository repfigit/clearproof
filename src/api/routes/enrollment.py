"""Authenticated pilot enrollment; acceptance is not proof authorization."""

import os
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field

from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.enrollment import EnrollmentConsent, EnrollmentError
from src.protocol.transfer import OpaqueId, Record
from src.services.enrollment import EnrollmentService
from src.storage.keyring import load_keyring
from src.storage.pilot import RecordConflict
from src.storage.pilot_cipher import RecordCipher

router = APIRouter(prefix="/pilot/credential", tags=["pilot-credential"])


class EnrollmentRequest(Record):
    consent: EnrollmentConsent
    signature: str = Field(pattern=r"^0x[0-9a-f]{130}$", min_length=132, max_length=132)
    idempotency_key: OpaqueId


def enrollment_service(
    request: Request, principal: Principal = Depends(TenantPrincipalDependency)
) -> EnrollmentService:
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        chain_id = int(os.environ["PILOT_CHAIN_ID"])
        registry = os.environ["PILOT_REGISTRY_ADDRESS"]
        cipher = RecordCipher(load_keyring())
    except (KeyError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Pilot enrollment configuration is unavailable") from exc
    return EnrollmentService(db, cipher, principal, chain_id=chain_id, registry_address=registry)


@router.post("/enroll", summary="Record wallet-authorized enrollment pending root publication")
async def enroll(request: EnrollmentRequest, service: EnrollmentService = Depends(enrollment_service)):
    try:
        return await service.enroll(
            request.consent, request.signature, idempotency_key=request.idempotency_key, now=int(time.time())
        )
    except EnrollmentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RecordConflict as exc:
        raise HTTPException(status_code=409, detail="Enrollment or idempotency key already exists") from exc
