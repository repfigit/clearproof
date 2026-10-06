# SPDX-License-Identifier: Apache-2.0
"""Bounded, tenant-scoped configuration preflight; no proof or authorization."""

import asyncio
import os
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from src.api.routes.pilot_proof import InspectionTarget
from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.transfer import Epoch, OpaqueId, Record, VerificationContext
from src.prover.pilot_native_prover import PilotNativeProver
from src.prover.pilot_prover import PilotProver
from src.prover.pilot_roots import verify_pilot_roots
from src.prover.pilot_verifier import PilotPairingVerifier
from src.services.proof_inspection import CurrentStatementConfiguration
from src.services.proof_jobs import ProvingTarget
from src.storage.database import SCHEMA_VERSION
from src.storage.keyring import load_keyring
from src.storage.pilot_cipher import RecordCipher

router = APIRouter(prefix="/pilot/readiness", tags=["pilot-readiness"])
Capability = Literal["inspection", "proving"]


class ReadinessChecks(Record):
    database: bool
    migration_history: bool
    storage_key: bool
    target_configuration: bool


class ReadinessReport(Record):
    schema_version: Literal["clearproof-pilot-readiness-v1"] = "clearproof-pilot-readiness-v1"
    scope: Literal["configured-target-preflight"] = "configured-target-preflight"
    status: Literal["ready", "not_ready"]
    capability: Capability
    checked_at: Epoch
    checks: ReadinessChecks
    current_state_checked: Literal[False] = False
    authorization_consumed: Literal[False] = False
    production_eligible: Literal[False] = False


def check_target(request: Request, principal: Principal, capability: Capability, target_id: str, now: int) -> None:
    """Check operator-selected loaded inputs, never caller-supplied trust."""
    attribute = "pilot_inspection_targets" if capability == "inspection" else "pilot_proving_targets"
    targets = getattr(request.app.state, attribute, None)
    if type(targets) is not dict or len(targets) > 256:
        raise ValueError("Unavailable target configuration")
    target = targets.get((principal.tenant_id, target_id))
    expected = InspectionTarget if capability == "inspection" else ProvingTarget
    if not isinstance(target, expected) or not isinstance(target.configuration, CurrentStatementConfiguration):
        raise ValueError("Unavailable target configuration")
    config = target.configuration
    if (config.context.tenant_id, config.transfer.tenant_id, config.root_pins.tenant_id) != (principal.tenant_id,) * 3:
        raise ValueError("Unavailable target configuration")
    verifier = target.verifier if capability == "inspection" else target.prover.verifier
    if not isinstance(verifier, PilotPairingVerifier):
        raise ValueError("Unavailable verifier configuration")
    verifier.artifacts.check_artifact_context(config.context)
    if not verifier.node.is_absolute() or not verifier.node.is_file() or not os.access(verifier.node, os.X_OK):
        raise ValueError("Unavailable verifier runtime")
    VerificationContext.model_validate({**config.context.model_dump(), "evaluated_at": now}).check_transfer(
        config.transfer
    )
    config.policy_trust.for_transfer(config.transfer, config.context, tenant_id=principal.tenant_id, now=now)
    for at in (config.context.evaluated_at, now):
        config.valuation_trust.verify_for_transfer(
            config.valuation_approval, config.transfer, config.registry, tenant_id=principal.tenant_id, now=at
        )
    verify_pilot_roots(
        trust=config.root_trust,
        pins=config.root_pins,
        context=config.context,
        issuance=config.issuance,
        issuers=config.issuers,
        sanctions=config.sanctions,
        now=now,
    )
    if capability == "proving":
        if target.sanctions.root != config.sanctions.snapshot.root:
            raise ValueError("Unavailable target configuration")
        prover = target.prover
        if not isinstance(prover, (PilotProver, PilotNativeProver)):
            raise ValueError("Unavailable prover configuration")
        javascript = prover.javascript if isinstance(prover, PilotNativeProver) else prover
        for role in ("wasm", "proving_key"):
            artifact = getattr(verifier.artifacts.manifest, role)
            path = javascript.root / artifact.filename
            if not path.is_file() or path.stat().st_size != artifact.size:
                raise ValueError("Unavailable proving artifact")
        if isinstance(prover, PilotNativeProver) and (
            not prover.binary.is_absolute() or not prover.binary.is_file() or not os.access(prover.binary, os.X_OK)
        ):
            raise ValueError("Unavailable native runtime")


@router.get(
    "/{capability}/{target_id}",
    summary="Check scoped target configuration, storage keys and database without proving or consumption",
    responses={503: {"model": ReadinessReport, "description": "One or more configuration preflight checks failed"}},
)
async def readiness(
    request: Request,
    response: Response,
    capability: Capability,
    target_id: OpaqueId,
    principal: Principal = Depends(TenantPrincipalDependency),
) -> ReadinessReport:
    principal.require("usage:read")
    if request.query_params:
        raise HTTPException(status_code=422, detail="Readiness does not accept query selectors")
    checks = dict(database=False, migration_history=False, storage_key=False, target_configuration=False)
    db = getattr(request.app.state, "db", None)
    if db is not None and db.is_ready:
        try:
            async with asyncio.timeout(2):
                async with db.connection() as conn, conn.transaction(), conn.cursor() as cur:
                    await cur.execute("SET TRANSACTION READ ONLY")
                    await cur.execute("SET LOCAL statement_timeout = '1500ms'")
                    await cur.execute("SELECT 1")
                    if await cur.fetchone() != (1,):
                        raise ValueError("Database probe failed")
                    checks["database"] = True
                    await cur.execute(
                        "SELECT version FROM schema_migrations ORDER BY version LIMIT %s", (SCHEMA_VERSION + 1,)
                    )
                    checks["migration_history"] = await cur.fetchall() == [(n,) for n in range(1, SCHEMA_VERSION + 1)]
        except Exception:
            checks["migration_history"] = False
    try:
        cipher = RecordCipher(load_keyring())
        value = {"probe": "synthetic-readiness-v1"}
        row = {**cipher.seal(principal.tenant_id, "readiness", "synthetic-probe", 1, value), "revision": 1}
        checks["storage_key"] = cipher.open(principal.tenant_id, "readiness", "synthetic-probe", row) == value
    except Exception:
        pass
    now = int(time.time())
    try:
        check_target(request, principal, capability, target_id, now)
        checks["target_configuration"] = True
    except Exception:
        pass
    ready = all(checks.values())
    response.status_code = 200 if ready else 503
    response.headers["Cache-Control"] = "no-store"
    return ReadinessReport(
        status="ready" if ready else "not_ready", capability=capability, checked_at=now, checks=checks
    )
