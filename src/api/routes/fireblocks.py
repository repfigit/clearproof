"""Authenticated relay intake; both a tenant JWT and provider signature are required."""

import json
import os
import time

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field, model_validator

from src.adapters.fireblocks import FireblocksBinding, FireblocksError, FireblocksVerifier
from src.api.request_body import read_private_body
from src.api.routes.events import event_service
from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.transfer import Epoch, OpaqueId, Record
from src.prover.pilot_artifacts import strict_json
from src.services.event_ingestion import EventAuthorityError
from src.services.fireblocks_intake import FireblocksIntake
from src.storage.pilot import RecordConflict

router = APIRouter(prefix="/pilot/fireblocks", tags=["pilot-fireblocks"])


class FireblocksIntegration(Record):
    integration_id: OpaqueId
    binding: FireblocksBinding
    jwks: dict
    key_valid_from_ms: Epoch
    key_valid_until_ms: Epoch
    max_age_ms: int = Field(ge=1, le=30 * 86400000)


class FireblocksIntegrations(Record):
    integrations: tuple[FireblocksIntegration, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def unique(self):
        if len({item.integration_id for item in self.integrations}) != len(self.integrations):
            raise ValueError("Duplicate integration ID")
        return self


@router.post("/{integration_id}", summary="Verify and retain a signed Fireblocks notification from a tenant relay")
async def receive_fireblocks(
    integration_id: str, request: Request, principal: Principal = Depends(TenantPrincipalDependency)
):
    principal.require("events:ingest")
    principal.require("evidence:decrypt")
    try:
        raw_config = os.environ["PILOT_FIREBLOCKS_INTEGRATIONS"].encode()
        strict_json(raw_config, limit=65536)
        config = FireblocksIntegrations.model_validate_json(raw_config)
    except (KeyError, ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=503, detail="Fireblocks relay configuration is unavailable") from None
    integration = next(
        (
            item
            for item in config.integrations
            if item.integration_id == integration_id and item.binding.scope.tenant_id == principal.tenant_id
        ),
        None,
    )
    if integration is None:
        raise HTTPException(status_code=404, detail="Fireblocks integration is unavailable")
    signatures = request.headers.getlist("fireblocks-webhook-signature")
    if len(signatures) != 1:
        raise HTTPException(status_code=401, detail="A single provider signature is required")
    try:
        verifier = FireblocksVerifier(
            json.dumps(integration.jwks).encode(),
            valid_from=integration.key_valid_from_ms,
            valid_until=integration.key_valid_until_ms,
            max_age_ms=integration.max_age_ms,
        )
    except (ValueError, TypeError, KeyError, RecursionError, jwt.PyJWTError):
        raise HTTPException(status_code=503, detail="Fireblocks verification configuration is unavailable") from None
    raw = await read_private_body(request, limit=65536)
    intake = FireblocksIntake(event_service(request, principal, ingestion=True), verifier)
    try:
        return await intake.ingest(raw, signatures[0], integration.binding, now_ms=time.time_ns() // 1000000)
    except FireblocksError:
        raise HTTPException(status_code=422, detail="Provider signature, binding or notification rejected") from None
    except EventAuthorityError:
        raise HTTPException(status_code=403, detail="Relay actor is outside the configured source authority") from None
    except RecordConflict:
        raise HTTPException(status_code=409, detail="Provider notification conflicts with retained evidence") from None
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Provider notification cannot be retained") from None
