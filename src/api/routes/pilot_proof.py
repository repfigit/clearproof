"""Current v2 inspection with operator-selected trust and no authorization writes."""

import time
from dataclasses import asdict, dataclass

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field

from src.api.request_body import read_private_body
from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.transfer import OpaqueId, Record
from src.prover.pilot_artifacts import strict_json
from src.prover.pilot_verifier import PilotPairingVerifier, PilotProof, public_signals
from src.services.enrollment import EnrollmentNotFound
from src.services.proof_inspection import CurrentStatementConfiguration, ProofInspectionService
from src.storage.keyring import load_keyring
from src.storage.pilot_cipher import RecordCipher

router = APIRouter(prefix="/pilot/proof", tags=["pilot-proof"])


@dataclass(frozen=True, repr=False)
class InspectionTarget:
    """Provision in app.state.pilot_inspection_targets[(tenant_id, target_id)].

    Only the operator can install targets. Request bodies cannot select artifact
    paths, runtime executables, source keys, roots, policy pins or verifier clocks.
    """

    configuration: CurrentStatementConfiguration
    verifier: PilotPairingVerifier


class InspectionBody(Record):
    target_id: OpaqueId
    credential_id: OpaqueId
    proof_json: str = Field(min_length=1, max_length=8192)
    public_signals: list[str] = Field(min_length=8, max_length=8)


def inspection_time() -> int:
    return int(time.time())


@router.post("/inspect", summary="Inspect a current pilot proof without authorizing or consuming it")
async def inspect_proof(request: Request, principal: Principal = Depends(TenantPrincipalDependency)):
    principal.require("proof:inspect")
    principal.require("evidence:decrypt")
    raw = await read_private_body(request, limit=16384)
    try:
        strict_json(raw, limit=16384)
        body = InspectionBody.model_validate_json(raw)
        proof = body.proof_json.encode("utf-8")
        PilotProof.parse(proof)
        signals = public_signals(body.public_signals)
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="Invalid pilot proof input") from None
    targets = getattr(request.app.state, "pilot_inspection_targets", None)
    if not isinstance(targets, dict):
        raise HTTPException(status_code=503, detail="Pilot inspection configuration is unavailable")
    target = targets.get((principal.tenant_id, body.target_id))
    if target is None:
        raise HTTPException(status_code=404, detail="Pilot inspection target is unavailable")
    if not isinstance(target, InspectionTarget):
        raise HTTPException(status_code=503, detail="Pilot inspection configuration is unavailable")
    db = getattr(request.app.state, "db", None)
    if db is None or not db.is_ready:
        raise HTTPException(status_code=503, detail="Pilot database is unavailable")
    try:
        service = ProofInspectionService(
            db, RecordCipher(load_keyring()), principal, target.verifier, target.configuration
        )
    except (ValueError, TypeError, KeyError, RuntimeError):
        raise HTTPException(status_code=503, detail="Pilot inspection configuration is unavailable") from None
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
