"""Offline bundle integrity and pairing; historical authority checks remain explicit."""

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.transfer import Transfer, VerificationContext
from src.prover.history_statement import HistoryStatementTrust, reconstruct_history_statement
from src.prover.pilot_verifier import PilotPairingVerifier, PilotProof, public_signals


@dataclass(frozen=True)
class HistoryInspection:
    outcome: Literal["contradicted", "indeterminate"]
    integrity_valid: bool
    cryptographic_valid: bool | None
    verified_at: int
    reasons: tuple[str, ...]
    statement_valid: bool | None = None


class MissingHistoryEvidence(ValueError):
    pass


def _check(condition):
    if not condition:
        raise ValueError("History evidence integrity mismatch")


def _decode(value):
    _check(type(value) is str and len(value) <= 200000)
    return base64.b64decode(value, validate=True)


def _integrity(bundle, verifier, expected_receipt_id, expected_tenant):
    _check(bundle["schema_version"] == "clearproof-history-bundle-v1")
    _check(bundle["receipt_id"] == expected_receipt_id and bundle["tenant_id"] == expected_tenant)
    receipt, proof, manifest = bundle["receipt"], bundle["proof"], bundle["evidence_manifest"]
    _check(receipt["schema_version"] == "clearproof-local-authorization-v1")
    _check(proof["schema_version"] == "clearproof-retained-proof-v1")
    _check(manifest["schema_version"] == "clearproof-authorization-evidence-v1")
    _check(record_digest("clearproof/local-authorization/v1", receipt) == expected_receipt_id)
    _check(record_digest("clearproof/authorization-evidence/v1", manifest) == receipt["evidence_id"])
    _check(receipt["tenant_id"] == manifest["tenant_id"] == expected_tenant)
    transfer = Transfer.model_validate_json(json.dumps(proof["transfer"]))
    context = VerificationContext.model_validate_json(json.dumps(proof["context"]))
    context.check_transfer(transfer)
    _check(transfer.tenant_id == expected_tenant)
    for name, value in (("transfer_digest", transfer.digest), ("context_digest", context.digest)):
        _check(receipt[name] == manifest[name] == proof[name] == value)
    _check(receipt["manifest_digest"] == context.artifact_manifest_digest == verifier.artifacts.manifest.digest)
    _check(receipt["proof_profile"] == context.proof_profile == verifier.artifacts.manifest.proof_profile)
    _check(manifest["runtime_sha256"] == hashlib.sha256(verifier.bundle).hexdigest())
    raw_proof = _decode(proof["proof_base64"])
    PilotProof.parse(raw_proof)
    _check(hashlib.sha256(raw_proof).hexdigest() == proof["proof_digest"])
    signals = public_signals(proof["signals"])
    _check(receipt["nullifier"] == format(int(signals[3]), "064x"))
    _check(type(receipt["expires_at"]) is int and receipt["expires_at"] == int(signals[5]))
    _check(int(signals[4]) == context.evaluated_at)
    _check(int(signals[6]) == int(context.deployment_chain_id))
    _check(int(signals[7]) == int(context.deployment_address, 16))
    _check(receipt["policy_digest"] == transfer.policy_digest == context.policy_digest)
    _check(receipt["outcome"] == proof["policy_evaluation"]["outcome"] == "ALLOW")
    _check(proof["policy_evaluation"]["policy_digest"] == receipt["policy_digest"])
    _check(proof["policy_evaluation"]["transfer_digest"] == transfer.digest)
    _check(proof["policy_evaluation"]["evaluated_at"] == receipt["authorized_at"])
    _check(record_digest("clearproof/pilot-envelope/v1", proof["recipient_envelope"]) == receipt["envelope_digest"])
    binding = proof["recipient_envelope"]["binding"]
    _check(binding["tenant_id"] == expected_tenant)
    _check(binding["transfer_digest"] == transfer.digest and binding["context_digest"] == context.digest)
    _check(binding["proof_digest"] == proof["proof_digest"])
    _check(binding["recipient_key_id"] == receipt["recipient_key_id"] == proof["recipient_key_id"])
    _check(binding["recipient_did"] == transfer.beneficiary.vasp_did)
    _check(proof["recipient_envelope"]["hpke"]["aad"] == record_digest("clearproof/pilot-envelope-binding/v1", binding))
    _check(proof["recipient_envelope"]["hpke"]["kid"] == binding["recipient_key_id"])
    signature_hash = hashlib.sha256(bytes.fromhex(proof["information_approval"]["signature"])).hexdigest()
    _check(signature_hash == proof["information_signature_digest"] == receipt["information_signature_digest"])
    request = {
        key: proof[key]
        for key in (
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
    _check(
        record_digest("clearproof/authorized-proof/v1", {**request, "envelope_digest": receipt["envelope_digest"]})
        == receipt["proof_id"]
    )
    _check(type(bundle["records"]) is list and len(bundle["records"]) <= 80)
    records = {}
    for record in bundle["records"]:
        key = (record["kind"], record["record_id"], record["revision"])
        _check(key not in records)
        records[key] = record
    _check(type(manifest["records"]) is list and 1 <= len(manifest["records"]) <= 80)
    expected_records = set()
    for reference in manifest["records"]:
        key = (reference["kind"], reference["record_id"], reference["revision"])
        _check(key not in expected_records)
        expected_records.add(key)
        if key not in records:
            raise MissingHistoryEvidence()
        record = records[key]
        _check(record["sha256"] == reference["sha256"] == hashlib.sha256(canonical_bytes(record["value"])).hexdigest())
    _check(set(records) == expected_records)
    configuration = bundle["configuration_base64"]
    if set(manifest["configuration"]) - set(configuration):
        raise MissingHistoryEvidence()
    _check(set(configuration) == set(manifest["configuration"]))
    captured = {}
    for name, descriptor in manifest["configuration"].items():
        raw = _decode(configuration[name])
        _check(type(descriptor["size"]) is int and len(raw) == descriptor["size"])
        _check(hashlib.sha256(raw).hexdigest() == descriptor["sha256"])
        captured[name] = raw
    _check(captured["artifact_manifest"] == canonical_bytes(verifier.artifacts.manifest.model_dump(mode="json")))
    _check(captured["verification_key"] == verifier.artifacts.verification_key_bytes)
    return raw_proof, signals


async def inspect_history_bundle(
    bundle: dict,
    verifier: PilotPairingVerifier,
    *,
    expected_receipt_id: str,
    expected_tenant: str,
    verified_at: int,
    statement_trust: HistoryStatementTrust | None = None,
) -> HistoryInspection:
    """Pins and verifier come from the reviewer, never from the exported bundle.

    Optional independent statement trust enables reconstruction at the claimed
    authorization time. Decision authority and historical non-revocation/timing
    still require evidence before a supported outcome. This function cannot consume.
    """
    if type(verified_at) is not int or not 0 <= verified_at < 2**53:
        raise ValueError("Invalid history verification clock")
    try:
        raw_proof, signals = _integrity(bundle, verifier, expected_receipt_id, expected_tenant)
    except (KeyError, MissingHistoryEvidence):
        return HistoryInspection("indeterminate", False, None, verified_at, ("missing_evidence",))
    except (ValueError, TypeError, OverflowError, RecursionError):
        return HistoryInspection("contradicted", False, None, verified_at, ("bundle_integrity_mismatch",))
    expected = signals
    statement_valid = None
    if statement_trust is not None:
        try:
            expected = reconstruct_history_statement(bundle, verifier, statement_trust, signals)
        except (ValueError, KeyError, TypeError):
            return HistoryInspection("indeterminate", True, None, verified_at, ("statement_trust_unavailable",), False)
        if expected != signals:
            return HistoryInspection("contradicted", True, None, verified_at, ("statement_signal_mismatch",), False)
        statement_valid = True
    try:
        inspection = await verifier.inspect(raw_proof, signals, expected_signals=expected)
    except (ValueError, OSError):
        return HistoryInspection("indeterminate", True, None, verified_at, ("pairing_unavailable",), statement_valid)
    if not inspection.cryptographic_valid:
        return HistoryInspection("contradicted", True, False, verified_at, ("invalid_pairing",), statement_valid)
    return HistoryInspection(
        "indeterminate",
        True,
        True,
        verified_at,
        (
            *(("statement_semantics_unverified",) if statement_valid is None else ()),
            "decision_authority_unverified",
            "historical_revocation_evidence_missing",
            "independent_timing_evidence_missing",
        ),
        statement_valid,
    )
