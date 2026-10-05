"""Operator-selected proving jobs with encrypted inputs and current-state handoff."""

import hashlib
import time
from dataclasses import dataclass

from pydantic import field_validator

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.protocol.credential import Scalar, scalar
from src.protocol.transfer import Hex32, OpaqueId, Record
from src.prover.generated_signals import PROOF_LIFETIME_SECONDS
from src.prover.pilot_compliance import PUBLIC_SIGNALS
from src.prover.pilot_prover import PilotProver
from src.prover.pilot_verifier import PilotProof, public_signals
from src.registry.pilot_sanctions import PilotSanctionsTree
from src.services.proof_inspection import CurrentStatementConfiguration
from src.services.proof_preparation import ProofPreparationService
from src.storage.database import Database
from src.storage.pilot_cipher import RecordCipher
from src.storage.proof_jobs import JobClaim, ProofJobError, ProofJobQueue, authorize


class ProvingInput(Record):
    target_id: OpaqueId
    credential_id: OpaqueId
    holder_secret: Scalar

    @field_validator("holder_secret")
    @classmethod
    def nonzero_secret(cls, value):
        scalar(value, nonzero=True)
        return value


class GenerationBody(ProvingInput):
    idempotency_key: OpaqueId


class RetainedProvingInput(ProvingInput):
    configuration_digest: Hex32


@dataclass(frozen=True, repr=False)
class ProvingTarget:
    """Installed by an operator in both API and worker, never from an upload.

    Trust is revalidated at each use; the retained digest prevents a target ID
    from silently selecting a different transfer, context, approval or runtime.
    """

    configuration: CurrentStatementConfiguration
    prover: PilotProver
    sanctions: PilotSanctionsTree

    @property
    def digest(self):
        cfg = self.configuration
        return record_digest(
            "clearproof/proving-target/v1",
            {
                "records": {
                    name: getattr(cfg, name).model_dump(mode="json")
                    for name in (
                        "transfer",
                        "context",
                        "valuation_approval",
                        "root_pins",
                        "issuance",
                        "issuers",
                        "sanctions",
                    )
                },
                "registry_digest": cfg.registry.digest,
                "sanctions_source_digest": self.sanctions.source_digest,
                "manifest_digest": self.prover.verifier.artifacts.manifest.digest,
                "runtime_digest": hashlib.sha256(self.prover.verifier.bundle).hexdigest(),
            },
        )

    @property
    def deadline(self):
        cfg = self.configuration
        return min(
            cfg.context.evaluated_at + PROOF_LIFETIME_SECONDS,
            cfg.transfer.expires_at,
            *(getattr(cfg, name).snapshot.expires_at for name in ("issuance", "issuers", "sanctions")),
        )


class ProofJobService:
    def __init__(self, db: Database, cipher: RecordCipher, targets: dict):
        if type(targets) is not dict:
            raise ProofJobError("proving_configuration_unavailable")
        self.db, self.cipher, self.targets = db, cipher, targets
        self.queue = ProofJobQueue(db, cipher)

    def target(self, principal: Principal, target_id: str, *, digest: str | None = None):
        target = self.targets.get((principal.tenant_id, target_id))
        if target is None:
            raise ProofJobError("proving_target_not_found")
        if not isinstance(target, ProvingTarget):
            raise ProofJobError("proving_configuration_unavailable")
        if target.configuration.context.tenant_id != principal.tenant_id:
            raise ProofJobError("proving_configuration_unavailable")
        if digest is not None and target.digest != digest:
            raise ProofJobError("configuration_changed")
        return target

    def preparation(self, principal, target):
        return ProofPreparationService(self.db, self.cipher, principal, target.prover.verifier, target.configuration)

    async def enqueue(self, principal: Principal, body: GenerationBody):
        authorize(principal)
        target = self.target(principal, body.target_id)
        # No witness construction, tree reconstruction or proving on the HTTP
        # admission path. All business-state checks run under the worker lease.
        request = RetainedProvingInput(
            **body.model_dump(exclude={"idempotency_key"}), configuration_digest=target.digest
        )
        return await self.queue.enqueue(
            principal, body.idempotency_key, request.model_dump(mode="json"), expires_at=target.deadline
        )

    async def execute(self, claim: JobClaim):
        """Generate outside the tenant lock, then publish under a current-state lock."""
        job = claim.snapshot
        body = RetainedProvingInput.model_validate(job.request)
        target = self.target(job.principal, body.target_id, digest=body.configuration_digest)
        service = self.preparation(job.principal, target)
        witness = await service.prepare_witness(
            body.credential_id, secret=body.holder_secret, sanctions_tree=target.sanctions, now=int(time.time())
        )
        result = await target.prover.prove(
            witness,
            expected_signals=[witness[name] for name in PUBLIC_SIGNALS],
            timeout=max(1, min(120, job.expires_at - int(time.time()))),
        )
        # Re-resolve operator configuration after expensive work; an in-flight
        # target replacement must not publish a proof for the previous statement.
        target = self.target(job.principal, body.target_id, digest=body.configuration_digest)
        service = self.preparation(job.principal, target)
        async with service.current_result(body.credential_id, list(result.public_signals), now=int(time.time())):
            return await self.queue.finish(
                claim,
                result={
                    "proof_json": result.proof.decode("ascii"),
                    "public_signals": list(result.public_signals),
                    "assurance": target.prover.verifier.artifacts.manifest.assurance,
                },
            )

    async def read(self, principal: Principal, job_id: str):
        job = await self.queue.read(principal, job_id)
        response = {"schema_version": "clearproof-proof-job-v1", "authorization_consumed": False, **job.metadata()}
        if job.status != "completed":
            return response
        # Completion retains evidence. It never grants fresh authorization or
        # permission to hand out stale proof bytes after a root/policy change.
        response["result_available"] = False
        if job.expires_at <= int(time.time()):
            response["result_error"] = "job_expired"
            return response
        try:
            body = RetainedProvingInput.model_validate(job.request)
            target = self.target(principal, body.target_id, digest=body.configuration_digest)
            if type(job.result) is not dict or set(job.result) != {"proof_json", "public_signals", "assurance"}:
                raise ValueError("shape")
            PilotProof.parse(job.result["proof_json"].encode("ascii"))
            signals = public_signals(job.result["public_signals"])
            async with self.preparation(principal, target).current_result(
                body.credential_id, list(signals), now=int(time.time())
            ):
                response.update(result_available=True, result=job.result)
        except (ValueError, TypeError, KeyError, RuntimeError):
            response["result_error"] = "current_state_rejected"
        return response
