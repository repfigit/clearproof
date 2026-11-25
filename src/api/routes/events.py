"""Tenant-authorized internal observations and read-only investigation."""

import time

from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.config import AuthorityConfig, EventConfig, LinkConfig, require_record_cipher
from src.api.middleware.rate_limit import pilot_events_limiter
from src.api.request_body import read_private_body
from src.auth.principal import Principal, TenantPrincipalDependency
from src.prover.pilot_artifacts import strict_json
from src.reconciliation.events import SourceEvent, TransferScope
from src.reconciliation.queue import QueueRequest
from src.services.event_ingestion import EventAuthorityError, EventIngestionService
from src.storage.pilot import RecordConflict

__all__ = ["AuthorityConfig", "LinkConfig", "event_service", "router"]

router = APIRouter(prefix="/pilot/events", tags=["pilot-events"], dependencies=[Depends(pilot_events_limiter)])


def event_service(request: Request, principal: Principal, *, ingestion: bool) -> EventIngestionService:
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        config = getattr(request.app.state, "event_config", None)
        if not isinstance(config, EventConfig):
            raise RuntimeError("Pilot event configuration is not installed on app.state")
        authorities = ()
        if ingestion:
            if config.authorities is None:
                raise KeyError("PILOT_EVENT_AUTHORITIES")
            authorities = config.authorities
        links = () if ingestion else config.links
        cipher = require_record_cipher(request)
        return EventIngestionService(db, cipher, principal, authorities=authorities, links=links)
    except (KeyError, ValueError, TypeError, RuntimeError, RecursionError):
        raise HTTPException(status_code=503, detail="Pilot event configuration is unavailable") from None


@router.post("/ingest", summary="Retain an observation from an authorized internal source actor")
async def ingest_event(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("events:ingest")
    principal.require("evidence:decrypt")
    raw = await read_private_body(request, limit=65536)
    try:
        strict_json(raw, limit=65536)
        event = SourceEvent.model_validate_json(raw)
        return await event_service(request, principal, ingestion=True).ingest(event, now=int(time.time()))
    except EventAuthorityError:
        raise HTTPException(status_code=403, detail="Event source is outside the authorized scope") from None
    except RecordConflict:
        raise HTTPException(status_code=409, detail="Event identity or sequence conflicts") from None
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid source event") from None


@router.post("/investigate", summary="Replay retained observations without moving funds or consuming authorization")
async def investigate_events(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("evidence:read")
    principal.require("evidence:decrypt")
    raw = await read_private_body(request, limit=4096)
    try:
        strict_json(raw, limit=4096)
        scope = TransferScope.model_validate_json(raw)
        report = await event_service(request, principal, ingestion=False).investigate(scope, now=int(time.time()))
        return report.model_dump(mode="json")
    except EventAuthorityError:
        raise HTTPException(status_code=403, detail="Investigation is outside the authenticated tenant") from None
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid investigation scope or retained event") from None


@router.post("/queue", summary="Page through tenant investigations with aged unresolved findings")
async def investigation_queue(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("evidence:read")
    principal.require("evidence:decrypt")
    raw = await read_private_body(request, limit=4096)
    try:
        strict_json(raw, limit=4096)
        page = QueueRequest.model_validate_json(raw)
        result = await event_service(request, principal, ingestion=False).queue(page, now=int(time.time()))
        return result.model_dump(mode="json")
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid queue request or retained evidence") from None
