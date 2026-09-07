"""Local negotiated bilateral profile, not a claim of TRP wire interoperability."""

import hashlib
from typing import Literal

from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.decision_attestation import SignedDecision
from src.protocol.information_approval import SignedInformationApproval
from src.protocol.transfer_information import validate_transfer_information
from src.sar.pilot_envelope import open_pilot_envelope

PROFILE = "clearproof-local-bilateral-v1"
REQUEST_FIELDS = (
    "credential_id",
    "proof_digest",
    "signals",
    "fact_ids",
    "transfer_digest",
    "context_digest",
    "recipient_key_id",
    "information_signature_digest",
)


def build_pilot_request(record: dict, receipt: dict) -> dict:
    """Build minimized local exchange material from a retained authorization; receiver verifies it independently."""
    value = dict(
        profile=PROFILE,
        receipt_id=receipt["receipt_id"],
        receipt={k: v for k, v in receipt.items() if k != "receipt_id"},
        authorization_request={key: record[key] for key in REQUEST_FIELDS},
        envelope=record["recipient_envelope"],
        decision=record["decision_attestation"],
        information_approval=record["information_approval"],
    )
    canonical_bytes(value)
    return value


class LocalBilateralCounterparty:
    """In-process deterministic counterparty with independently configured scope, trust and recipient private keys."""

    def __init__(self, *, transfer, context, decision_trust, information_trust, recipient_trust, private_keys):
        context.check_transfer(transfer)
        if transfer.beneficiary.kind != "vasp":
            raise ValueError("The bilateral simulator requires a beneficiary VASP")
        self.transfer, self.context = transfer, context
        self.decision_trust, self.information_trust = decision_trust, information_trust
        self.recipient_trust = recipient_trust
        self.private_keys = {key: bytes(value) for key, value in private_keys.items()}

    def receive(
        self,
        request: dict,
        *,
        now: int,
        behavior: Literal["accept", "reject", "request-information", "timeout"] = "accept",
        deadline: int | None = None,
    ) -> dict:
        """No network, persistence, fund execution, source refresh or authorization consumption."""
        try:
            return self._receive(request, now=now, behavior=behavior, deadline=deadline)
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ValueError("Invalid local bilateral message or recipient configuration") from None

    def _receive(self, request, *, now, behavior, deadline):
        if behavior not in ("accept", "reject", "request-information", "timeout") or type(now) is not int or now < 0:
            raise ValueError("Invalid local counterparty configuration")
        canonical_bytes(request)
        if set(request) != {
            "profile",
            "receipt_id",
            "receipt",
            "authorization_request",
            "envelope",
            "decision",
            "information_approval",
        }:
            raise ValueError("Invalid bilateral message fields")
        request_id = record_digest("clearproof/bilateral-request/v1", request)

        def response(outcome, reason):
            return dict(
                schema_version="clearproof-local-counterparty-result-v1",
                profile=PROFILE,
                request_id=request_id,
                outcome=outcome,
                reason=reason,
                observed_at=now,
                peer_did=self.transfer.beneficiary.vasp_did,
                source_authenticity="local-simulator",
                assurance="development-unapproved",
                authorization="not-created",
                execution="not-requested",
            )

        if request["profile"] != PROFILE:
            return response("unsupported-version", "profile-not-negotiated")
        receipt, authorization = request["receipt"], request["authorization_request"]
        if (
            type(receipt) is not dict
            or type(authorization) is not dict
            or set(authorization) != set(REQUEST_FIELDS)
            or request["receipt_id"] != record_digest("clearproof/local-authorization/v1", receipt)
            or receipt.get("tenant_id") != self.transfer.tenant_id
            or receipt.get("transfer_digest") != self.transfer.digest
            or receipt.get("context_digest") != self.context.digest
            or receipt.get("proof_profile") != "pilot-transfer-v2"
            or receipt.get("execution") != "not-requested"
            or not receipt["authorized_at"] <= now < receipt["expires_at"]
        ):
            raise ValueError("Bilateral authorization scope is invalid or expired")
        self.decision_trust.verify(
            SignedDecision.model_validate(request["decision"]), receipt, self.context, verified_at=now
        )
        envelope_digest = record_digest("clearproof/pilot-envelope/v1", request["envelope"])
        if (
            receipt["envelope_digest"] != envelope_digest
            or record_digest("clearproof/authorized-proof/v1", {**authorization, "envelope_digest": envelope_digest})
            != receipt["proof_id"]
            or authorization["transfer_digest"] != self.transfer.digest
            or authorization["context_digest"] != self.context.digest
            or authorization["recipient_key_id"] != receipt["recipient_key_id"]
        ):
            raise ValueError("Bilateral request does not bind the authorized envelope")
        authority = self.recipient_trust.select(receipt["recipient_key_id"], self.transfer, self.context, now=now)
        private = self.private_keys.get(authority.key_id)
        if private is None:
            raise ValueError("Authorized recipient key is unavailable; no encryption fallback")
        binding = dict(
            tenant_id=self.transfer.tenant_id,
            transfer_digest=self.transfer.digest,
            context_digest=self.context.digest,
            proof_digest=authorization["proof_digest"],
            recipient_did=authority.recipient_did,
            recipient_key_id=authority.key_id,
            sealed_at=receipt["authorized_at"],
        )
        plaintext = open_pilot_envelope(request["envelope"], private, expected_binding=binding)
        validate_transfer_information(plaintext, self.transfer, self.context)
        approval = SignedInformationApproval.model_validate(request["information_approval"])
        signature_digest = hashlib.sha256(bytes.fromhex(approval.signature)).hexdigest()
        if (
            signature_digest != authorization["information_signature_digest"]
            or signature_digest != receipt["information_signature_digest"]
        ):
            raise ValueError("Bilateral information approval differs from authorized evidence")
        self.information_trust.verify(
            approval, plaintext, self.transfer, self.context, credential_id=authorization["credential_id"], now=now
        )
        if behavior == "timeout":
            if type(deadline) is not int or not receipt["authorized_at"] < deadline < receipt["expires_at"]:
                raise ValueError("Timeout requires an independently configured deadline within receipt validity")
            return response("timeout" if now >= deadline else "pending", "simulated-counterparty-delay")
        return response(
            {"accept": "accepted", "reject": "rejected", "request-information": "information-requested"}[behavior],
            "simulated-counterparty-" + behavior,
        )
