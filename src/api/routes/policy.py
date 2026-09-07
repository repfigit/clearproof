"""Authenticated bounded policy review and read-only comparison."""

import time

from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.request_body import read_private_body as read_policy_body
from src.auth.principal import Principal, TenantPrincipalDependency
from src.policy.diff import MAX_INPUT_BYTES, PolicyDiffRequest, compare_policies
from src.protocol.transfer import OpaqueId, Record
from src.prover.pilot_artifacts import strict_json
from src.services.policy_review import (
    PolicyRecordMissing,
    PolicyReviewRequest,
    PolicyReviewService,
    StoredPolicyComparison,
)
from src.storage.keyring import load_keyring
from src.storage.pilot import RecordConflict
from src.storage.pilot_cipher import RecordCipher

router = APIRouter(prefix="/pilot/policy", tags=["pilot-policy"])


@router.post("/diff", summary="Compare policy versions against tenant-provided evidence snapshots")
async def policy_diff(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("policy:read")
    principal.require("evidence:decrypt")
    raw = await read_policy_body(request)
    try:
        comparison = PolicyDiffRequest.parse(raw)
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


class ApprovalBody(Record):
    review: PolicyReviewRequest
    idempotency_key: OpaqueId


def review_service(request: Request, principal: Principal) -> PolicyReviewService:
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        cipher = RecordCipher(load_keyring())
    except (KeyError, ValueError, RuntimeError):
        raise HTTPException(status_code=503, detail="Pilot encryption configuration is unavailable") from None
    return PolicyReviewService(db, cipher, principal)


@router.post("/approve", summary="Retain reviewed policy and expected cases without activating it")
async def approve_policy(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("policy:approve")
    principal.require("evidence:decrypt")
    raw = await read_policy_body(request)
    try:
        strict_json(raw, limit=MAX_INPUT_BYTES)
        body = ApprovalBody.model_validate_json(raw)
        if body.review.policy.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=403, detail="Policy is outside the authenticated tenant")
        return await review_service(request, principal).approve(
            body.review, idempotency_key=body.idempotency_key, now=int(time.time())
        )
    except RecordConflict:
        raise HTTPException(status_code=409, detail="Policy approval or idempotency conflict") from None
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid policy review") from None


@router.post("/diff/stored", summary="Compare retained policies and cases in the authenticated tenant")
async def diff_stored_policy(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("policy:read")
    principal.require("evidence:decrypt")
    raw = await read_policy_body(request)
    try:
        strict_json(raw, limit=MAX_INPUT_BYTES)
        body = StoredPolicyComparison.model_validate_json(raw)
        result = await review_service(request, principal).compare_stored(body)
        return result.model_dump(mode="json")
    except PolicyRecordMissing:
        raise HTTPException(status_code=404, detail="Retained policy or case is unavailable") from None
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid retained policy comparison") from None
