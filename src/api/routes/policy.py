"""Authenticated, bounded policy replay; no approval, persistence or consumption."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request

from src.auth.principal import Principal, TenantPrincipalDependency
from src.policy.diff import MAX_INPUT_BYTES, PolicyDiffRequest, compare_policies

router = APIRouter(prefix="/pilot/policy", tags=["pilot-policy"])


@router.post("/diff", summary="Compare policy versions against tenant-provided evidence snapshots")
async def policy_diff(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("policy:read")
    principal.require("evidence:decrypt")
    body = bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_INPUT_BYTES:
                    raise HTTPException(status_code=413, detail="Policy comparison exceeds the input limit")
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(status_code=408, detail="Policy comparison upload timed out") from None
    try:
        comparison = PolicyDiffRequest.parse(bytes(body))
    except (ValueError, TypeError, RecursionError):
        # FastAPI's default validation body can echo sensitive rejected inputs.
        raise HTTPException(status_code=422, detail="Invalid policy comparison input") from None
    if comparison.before.tenant_id != principal.tenant_id or any(
        case.transfer.tenant_id != principal.tenant_id
        or case.context.tenant_id != principal.tenant_id
        or case.facts.tenant_id != principal.tenant_id
        for case in comparison.cases
    ):
        raise HTTPException(status_code=403, detail="Comparison is outside the authenticated tenant")
    try:
        return compare_policies(comparison).model_dump(mode="json")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Policy comparison scope or evidence is invalid") from None
