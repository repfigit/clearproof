"""Authenticated relay intake; both a tenant JWT and provider signature are required."""

import time

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request

from src.adapters.fireblocks import FireblocksError
from src.api.config import FireblocksConfig, FireblocksIntegration, FireblocksIntegrations, get_fireblocks_config
from src.api.middleware.rate_limit import pilot_fireblocks_limiter
from src.api.request_body import read_private_body
from src.api.routes.events import event_service
from src.auth.principal import Principal, TenantPrincipalDependency
from src.services.event_ingestion import EventAuthorityError
from src.services.fireblocks_intake import FireblocksIntake
from src.storage.pilot import RecordConflict

__all__ = ["FireblocksIntegration", "FireblocksIntegrations", "receive_fireblocks", "router"]

router = APIRouter(
    prefix="/pilot/fireblocks",
    tags=["pilot-fireblocks"],
    dependencies=[Depends(pilot_fireblocks_limiter)],
)


@router.post("/{integration_id}", summary="Verify and retain a signed Fireblocks notification from a tenant relay")
async def receive_fireblocks(
    integration_id: str, request: Request, principal: Principal = Depends(TenantPrincipalDependency)
):
    principal.require("events:ingest")
    principal.require("evidence:decrypt")
    try:
        config = get_fireblocks_config(request)
    except (KeyError, ValueError, TypeError, RecursionError, jwt.PyJWTError):
        raise HTTPException(status_code=503, detail="Fireblocks relay configuration is unavailable") from None
    if not isinstance(config, FireblocksConfig):
        raise HTTPException(status_code=503, detail="Fireblocks relay configuration is unavailable")
    try:
        compiled = config.lookup(integration_id, principal.tenant_id)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise HTTPException(status_code=503, detail="Fireblocks verification configuration is unavailable") from None
    if compiled is None:
        raise HTTPException(status_code=404, detail="Fireblocks integration is unavailable")
    signatures = request.headers.getlist("fireblocks-webhook-signature")
    if len(signatures) != 1:
        raise HTTPException(status_code=401, detail="A single provider signature is required")
    raw = await read_private_body(request, limit=65536)
    intake = FireblocksIntake(event_service(request, principal, ingestion=True), compiled.verifier)
    try:
        return await intake.ingest(raw, signatures[0], compiled.integration.binding, now_ms=time.time_ns() // 1000000)
    except FireblocksError:
        raise HTTPException(status_code=422, detail="Provider signature, binding or notification rejected") from None
    except EventAuthorityError:
        raise HTTPException(status_code=403, detail="Relay actor is outside the configured source authority") from None
    except RecordConflict:
        raise HTTPException(status_code=409, detail="Provider notification conflicts with retained evidence") from None
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Provider notification cannot be retained") from None
