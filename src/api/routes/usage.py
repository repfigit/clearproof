"""Role-scoped operational metadata; no decryption or billing side effects."""

import time

from fastapi import APIRouter, Depends, HTTPException, Request

from src.auth.principal import Principal, TenantPrincipalDependency
from src.services.usage import usage_inventory

router = APIRouter(prefix="/pilot/usage", tags=["pilot-usage"])


@router.get("", summary="Read retained tenant record counters, not billable charges")
async def read_usage(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("usage:read")
    if request.query_params:
        raise HTTPException(status_code=422, detail="Usage inventory does not accept query selectors")
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    return (await usage_inventory(db, principal, now=int(time.time()))).model_dump(mode="json")
