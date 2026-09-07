"""Prepare a current audit mirror of an already-consumed PostgreSQL authorization."""

import base64
import hashlib

from pydantic import model_validator

from src.policy.fact_approval import FactTrustStore, SignedFactApproval
from src.protocol.canonical import record_digest
from src.protocol.decision_attestation import DecisionTrustStore, SignedDecision
from src.protocol.information_approval import InformationTrustStore, SignedInformationApproval
from src.protocol.root_snapshot import root_scope_id
from src.protocol.transfer import Address, Epoch, Hex32, Record
from src.protocol.transfer_information import validate_transfer_information
from src.prover.pilot_verifier import PilotProof, public_signals
from src.sar.pilot_envelope import RecipientTrustStore
from src.services.policy_activation import activation_scope
from src.services.proof_inspection import ProofInspectionService


class MirrorDestination(Record):
    consumer: Address

    @model_validator(mode="after")
    def nonzero(self):
        if int(self.consumer, 16) == 0:
            raise ValueError("Mirror consumer must be configured")
        return self


class MirrorRequest(Record):
    receipt_id: Hex32
    now: Epoch


class AuthorizationMirrorService(ProofInspectionService):
    """Server-owned trust/consumer configuration. No RPC, publication or new consumption."""

    def __init__(self, *args, consumer: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._destination = MirrorDestination(consumer=consumer)

    async def prepare(
        self,
        receipt_id: str,
        *,
        pii: bytes,
        fact_trust: FactTrustStore,
        decision_trust: DecisionTrustStore,
        information_trust: InformationTrustStore,
        recipient_trust: RecipientTrustStore,
        now: int,
    ) -> dict:
        for role in ("tenant:admin", "evidence:export", "evidence:decrypt", "proof:inspect", "policy:read"):
            self._principal.require(role)
        MirrorRequest(receipt_id=receipt_id, now=now)
        transfer, context = self._inputs["transfer"], self._context
        validate_transfer_information(pii, transfer, context)
        async with self._store.transaction() as tx:
            receipt = await tx.get("receipt", receipt_id)
            if (
                receipt is None
                or receipt.get("schema_version") != "clearproof-local-authorization-v1"
                or (
                    receipt.get("tenant_id") != tx.tenant_id
                    or receipt.get("context_digest") != context.digest
                    or receipt.get("transfer_digest") != transfer.digest
                    or receipt.get("outcome") != "ALLOW"
                    or receipt.get("execution") != "not-requested"
                    or record_digest("clearproof/local-authorization/v1", receipt) != receipt_id
                )
            ):
                raise ValueError("Consumed authorization receipt is unavailable")
            record = await tx.get("proof", receipt["proof_id"])
            if record is None or record.get("schema_version") != "clearproof-retained-proof-v1":
                raise ValueError("Retained authorization proof is unavailable")
            proof = base64.b64decode(record["proof_base64"], validate=True)
            parsed = PilotProof.parse(proof)
            signals = public_signals(record["signals"])
            nullifier = format(int(signals[3]), "064x")
            request = {
                k: record[k]
                for k in (
                    "credential_id",
                    "proof_digest",
                    "signals",
                    "fact_ids",
                    "transfer_digest",
                    "context_digest",
                    "recipient_key_id",
                    "information_signature_digest",
                )
            }
            envelope = record["recipient_envelope"]
            if (
                request["proof_digest"] != hashlib.sha256(proof).hexdigest()
                or record["context"] != context.model_dump(mode="json")
                or record["transfer"] != transfer.model_dump(mode="json")
                or request["context_digest"] != context.digest
                or request["transfer_digest"] != transfer.digest
                or receipt["nullifier"] != nullifier
                or receipt["expires_at"] != int(signals[5])
                or record_digest("clearproof/pilot-envelope/v1", envelope) != receipt["envelope_digest"]
                or record_digest(
                    "clearproof/authorized-proof/v1", {**request, "envelope_digest": receipt["envelope_digest"]}
                )
                != receipt["proof_id"]
                or await tx.consumed_proof_id(nullifier) != receipt["proof_id"]
            ):
                raise ValueError("Authorization binding or consumption does not match")
            signed = SignedDecision.model_validate(record["decision_attestation"])
            decision_trust.verify(signed, receipt, context, verified_at=now)
            information = SignedInformationApproval.model_validate(record["information_approval"])
            information_trust.verify(
                information, pii, transfer, context, credential_id=request["credential_id"], now=now
            )
            if (
                hashlib.sha256(bytes.fromhex(information.signature)).hexdigest()
                != request["information_signature_digest"]
                or receipt["information_signature_digest"] != request["information_signature_digest"]
                or receipt["recipient_key_id"] != request["recipient_key_id"]
            ):
                raise ValueError("Authorization information binding does not match")
            recipient = recipient_trust.select(request["recipient_key_id"], transfer, context, now=now)
            expected_binding = {
                "tenant_id": tx.tenant_id,
                "transfer_digest": transfer.digest,
                "context_digest": context.digest,
                "proof_digest": request["proof_digest"],
                "recipient_did": recipient.recipient_did,
                "recipient_key_id": recipient.key_id,
                "sealed_at": receipt["authorized_at"],
            }
            if envelope.get("binding") != expected_binding:
                raise ValueError("Recipient envelope binding does not match")
            inspection, decision = await self._evaluate_transaction(
                tx,
                request["credential_id"],
                proof,
                signals,
                tuple(request["fact_ids"]),
                fact_trust=fact_trust,
                now=now,
            )
            if (
                not inspection.cryptographic_valid
                or decision is None
                or decision.outcome != "ALLOW"
                or (
                    receipt["policy_digest"] != decision.policy_digest
                    or receipt["proof_profile"] != inspection.proof_profile
                    or receipt["manifest_digest"] != inspection.manifest_digest
                )
            ):
                raise ValueError("Current authorization checks did not confirm ALLOW")
            policy = self._inputs["policy_trust"].for_transfer(transfer, context, tenant_id=tx.tenant_id, now=now)
            activation = await tx.read("policy-activation", activation_scope(policy))
            credential = await tx.read("credential", request["credential_id"])
            if activation is None or credential is None:
                raise ValueError("Current source records are unavailable")
            heads = []

            def head(kind, scope, digest, value, until, start=None):
                valid_until = min(int(signals[5]), until)
                valid_from = max(context.evaluated_at, start or context.evaluated_at)
                if not valid_from <= now < valid_until:
                    raise ValueError("Mirror checkpoint interval is not current")
                heads.append(
                    dict(
                        kind=kind,
                        scope=scope,
                        digest=digest,
                        value=str(value),
                        valid_from=valid_from,
                        valid_until=valid_until,
                        enabled=True,
                    )
                )

            for kind, name in enumerate(("issuance", "issuers", "sanctions")):
                snapshot = self._inputs[name].snapshot
                head(kind, root_scope_id(snapshot), snapshot.digest, snapshot.root, snapshot.expires_at)
            head(
                3,
                request["credential_id"],
                record_digest("clearproof/credential-checkpoint/v1", credential.value),
                0,
                transfer.expires_at,
            )
            head(
                4,
                activation_scope(policy),
                record_digest("clearproof/policy-checkpoint/v1", activation.value),
                0,
                min(policy.effective_until, *(source.valid_until for source in policy.sources)),
            )
            head(
                5,
                transfer.digest,
                record_digest(
                    "clearproof/valuation-checkpoint/v1", self._inputs["valuation_approval"].model_dump(mode="json")
                ),
                0,
                self._inputs["valuation_trust"].current_valid_until(
                    self._inputs["valuation_approval"],
                    transfer,
                    self._inputs["registry"],
                    tenant_id=tx.tenant_id,
                    now=now,
                ),
            )
            facts = []
            for identifier in request["fact_ids"]:
                value = await tx.get("fact-evidence", identifier)
                facts.append(SignedFactApproval.model_validate(value["signed"]))
            if not facts:
                raise ValueError("Mirror requires retained participant evidence")
            head(
                6,
                context.digest,
                record_digest(
                    "clearproof/participant-checkpoint/v1",
                    {"context_digest": context.digest, "fact_ids": sorted(request["fact_ids"])},
                ),
                0,
                fact_trust.current_valid_until(
                    tuple(facts), transfer=transfer, context=context, tenant_id=tx.tenant_id, now=now
                ),
                max(f.approval.signed_at for f in facts),
            )
            head(
                7,
                context.digest,
                receipt_id,
                1,
                min(information.approval.expires_at, recipient.not_after),
                receipt["authorized_at"],
            )
            return dict(
                schema_version="clearproof-authorization-mirror-plan-v1",
                consumption_owner="postgresql",
                contract_effect="audit-mirror-only",
                publication_state="not-published",
                assurance="development-unapproved",
                tenant_digest=record_digest("clearproof/tenant-checkpoint/v1", {"tenant_id": tx.tenant_id}),
                receipt_id=receipt_id,
                proof_id=receipt["proof_id"],
                nullifier=nullifier,
                context_digest=context.digest,
                transfer_digest=transfer.digest,
                prepared_at=now,
                evaluated_at=context.evaluated_at,
                valid_until=int(signals[5]),
                publish_before=min(h["valid_until"] for h in heads),
                consumer=self._destination.consumer,
                manifest_digest=inspection.manifest_digest,
                proof=parsed.model_dump(mode="json"),
                public_signals=list(signals),
                heads=heads,
            )
