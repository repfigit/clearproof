"""Offline export recipient and envelope boundaries using synthetic records."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.protocol.canonical import record_digest
from src.sar.hpke_envelope import derive_key_id, seal_envelope
from src.services.evidence_export import EvidenceRecipient, open_evidence_bundle


@pytest.fixture
def export_case():
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    binding = {
        "tenant_id": "synthetic-tenant",
        "receipt_id": "ab" * 32,
        "reviewer_id": "synthetic-reviewer",
        "key_id": derive_key_id(public),
        "exported_at": 100,
    }
    bundle = {
        "schema_version": "clearproof-history-bundle-v1",
        "tenant_id": binding["tenant_id"],
        "receipt_id": binding["receipt_id"],
        "exported_at": binding["exported_at"],
    }

    def envelope(value=bundle):
        return {
            "schema_version": "clearproof-encrypted-history-v1",
            "binding": binding.copy(),
            "hpke": seal_envelope(
                json.dumps(value).encode(),
                public,
                record_digest("clearproof/history-export-binding/v1", binding),
            ),
        }

    return private.private_bytes_raw(), public, binding, bundle, envelope


def test_valid_offline_bundle_roundtrip(export_case):
    private, _, binding, bundle, envelope = export_case
    assert open_evidence_bundle(json.dumps(envelope()).encode(), private, expected_binding=binding) == bundle


@pytest.mark.parametrize("mutation", ["array", "missing", "extra", "version", "binding"])
def test_outer_envelope_rejects_shape_and_scope_changes(export_case, mutation):
    private, _, binding, _, envelope = export_case
    value = envelope()
    if mutation == "array":
        value = []
    elif mutation == "missing":
        del value["hpke"]
    elif mutation == "extra":
        value["extra"] = "synthetic"
    elif mutation == "version":
        value["schema_version"] = "unsupported"
    else:
        value["binding"]["tenant_id"] = "different-tenant"
    with pytest.raises(ValueError, match="^Evidence export binding mismatch$"):
        open_evidence_bundle(json.dumps(value).encode(), private, expected_binding=binding)


@pytest.mark.parametrize("mutation", ["array", "missing", "extra", "key", "expected-key", "aad"])
def test_hpke_descriptor_rejects_recipient_substitution(export_case, mutation):
    private, _, binding, _, envelope = export_case
    value = envelope()
    expected = binding.copy()
    if mutation == "array":
        value["hpke"] = []
    elif mutation == "missing":
        del value["hpke"]["ct"]
    elif mutation == "extra":
        value["hpke"]["extra"] = "synthetic"
    elif mutation == "key":
        value["hpke"]["kid"] = "00" * 32
    elif mutation == "expected-key":
        expected["key_id"] = "00" * 32
        value["binding"] = expected
    else:
        value["hpke"]["aad"] = "00" * 32
    with pytest.raises(ValueError, match="^Evidence export recipient mismatch$"):
        open_evidence_bundle(json.dumps(value).encode(), private, expected_binding=expected)


@pytest.mark.parametrize("mutation", ["array", "version", "tenant_id", "receipt_id", "exported_at", "missing"])
def test_authenticated_plaintext_must_match_outer_scope(export_case, mutation):
    private, _, binding, original, envelope = export_case
    bundle = original.copy()
    if mutation == "array":
        bundle = []
    elif mutation == "version":
        bundle["schema_version"] = "unsupported"
    elif mutation == "missing":
        del bundle["receipt_id"]
    else:
        bundle[mutation] = 101 if mutation == "exported_at" else "different"
    with pytest.raises(ValueError, match="^Evidence bundle scope mismatch$"):
        open_evidence_bundle(json.dumps(envelope(bundle)).encode(), private, expected_binding=binding)


@pytest.mark.parametrize("interval", [(100, 100), (101, 100)])
def test_recipient_requires_positive_validity_interval(export_case, interval):
    _, public, _, _, _ = export_case
    with pytest.raises(ValueError, match="Invalid evidence recipient validity"):
        EvidenceRecipient(
            tenant_id="synthetic-tenant",
            reviewer_id="synthetic-reviewer",
            public_key=public.hex(),
            not_before=interval[0],
            not_after=interval[1],
        )


def test_recipient_rejects_low_order_key():
    with pytest.raises(ValueError):
        EvidenceRecipient(
            tenant_id="synthetic-tenant",
            reviewer_id="synthetic-reviewer",
            public_key="00" * 32,
            not_before=100,
            not_after=101,
        )


@pytest.fixture
def retained_case(export_case, monkeypatch):
    import base64
    import hashlib
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from src.auth.principal import Principal
    from src.protocol.canonical import canonical_bytes
    from src.services import evidence_export

    private, public, binding, _, _ = export_case
    principal = Principal(
        tenant_id=binding["tenant_id"],
        actor_id="synthetic-actor",
        roles=("evidence:export", "evidence:decrypt"),
    )
    recipient = EvidenceRecipient(
        tenant_id=principal.tenant_id,
        reviewer_id=binding["reviewer_id"],
        public_key=public.hex(),
        not_before=100,
        not_after=200,
    )
    row = {"synthetic": "retained-record"}
    chunk = {"data": [base64.b64encode(b"{}").decode()]}
    chunk_id = record_digest("clearproof/evidence-chunk/v1", chunk)
    manifest = {
        "schema_version": "clearproof-authorization-evidence-v1",
        "tenant_id": principal.tenant_id,
        "transfer_digest": "cd" * 32,
        "context_digest": "ef" * 32,
        "records": [
            {
                "kind": "transfer",
                "record_id": "synthetic-record",
                "revision": 1,
                "sha256": hashlib.sha256(canonical_bytes(row)).hexdigest(),
            }
        ],
        "configuration": {
            name: {"chunks": [chunk_id], "size": 2, "sha256": hashlib.sha256(b"{}").hexdigest()}
            for name in ("artifact_manifest", "verification_key", "asset_registry", "valuation_approval", "root_pins")
        },
    }
    proof = {
        "schema_version": "clearproof-retained-proof-v1",
        "transfer_digest": manifest["transfer_digest"],
        "context_digest": manifest["context_digest"],
    }
    receipt = {
        "schema_version": "clearproof-local-authorization-v1",
        "tenant_id": principal.tenant_id,
        "proof_id": "synthetic-proof",
        "transfer_digest": manifest["transfer_digest"],
        "context_digest": manifest["context_digest"],
    }
    state = SimpleNamespace(manifest=manifest, proof=proof, receipt=receipt, row=row, chunk=chunk, records={})

    def pin():
        evidence_id = record_digest("clearproof/authorization-evidence/v1", manifest)
        receipt["evidence_id"] = evidence_id
        receipt_id = record_digest("clearproof/local-authorization/v1", receipt)
        state.records = {
            ("receipt", receipt_id): receipt,
            ("proof", receipt["proof_id"]): proof,
            ("authorization-evidence", evidence_id): manifest,
            ("authorization-evidence", chunk_id): chunk,
        }
        return receipt_id

    class ReadOnlyStore:
        tenant_id = principal.tenant_id

        @asynccontextmanager
        async def transaction(self):
            yield self

        async def get(self, kind, identity):
            return state.records.get((kind, identity))

        async def read(self, kind, identity, *, revision):
            assert (kind, identity, revision) == ("transfer", "synthetic-record", 1)
            return None if state.row is None else SimpleNamespace(value=state.row)

    monkeypatch.setattr(evidence_export, "PilotStore", lambda *args: ReadOnlyStore())
    service = evidence_export.EvidenceExportService(None, None, principal, recipient)
    return state, pin, service, private


async def test_export_roundtrip_with_pinned_synthetic_records(retained_case):
    state, pin, service, private = retained_case
    receipt_id = pin()
    raw = await service.export(receipt_id, now=100)
    binding = json.loads(raw)["binding"]
    bundle = open_evidence_bundle(raw, private, expected_binding=binding)
    assert bundle["receipt"] == state.receipt
    assert bundle["records"][0]["value"] == state.row
    assert bundle["exported_by"] == service.principal.actor_id
    assert "decision_timestamp" not in bundle


@pytest.mark.parametrize(
    "attack,message",
    [
        ("missing-receipt", "Authorization receipt unavailable"),
        ("receipt-identity", "Authorization receipt identity mismatch"),
        ("missing-proof", "Authorization evidence identity mismatch"),
        ("empty-records", "Invalid evidence reference count"),
        ("missing-row", "Pinned evidence record unavailable or changed"),
        ("changed-row", "Pinned evidence record unavailable or changed"),
        ("configuration", "Unsupported evidence configuration"),
        ("empty-chunks", "Invalid configuration chunk count"),
        ("missing-chunk", "Pinned evidence chunk unavailable or changed"),
        ("size", "Captured configuration digest mismatch"),
        ("digest", "Captured configuration digest mismatch"),
        ("bundle-limit", "Evidence bundle exceeds export limit"),
    ],
)
async def test_export_rejects_incomplete_or_changed_retained_evidence(retained_case, monkeypatch, attack, message):
    from src.services import evidence_export

    state, pin, service, _ = retained_case
    descriptor = state.manifest["configuration"]["artifact_manifest"]
    if attack == "empty-records":
        state.manifest["records"] = []
    elif attack == "configuration":
        del state.manifest["configuration"]["root_pins"]
    elif attack == "empty-chunks":
        descriptor["chunks"] = []
    elif attack == "size":
        descriptor["size"] = 3
    elif attack == "digest":
        descriptor["sha256"] = "00" * 32
    receipt_id = pin()
    if attack == "missing-receipt":
        state.records.pop(("receipt", receipt_id))
    elif attack == "receipt-identity":
        state.receipt["tenant_id"] = "different-tenant"
    elif attack == "missing-proof":
        state.records.pop(("proof", state.receipt["proof_id"]))
    elif attack == "missing-row":
        state.row = None
    elif attack == "changed-row":
        state.row["synthetic"] = "changed"
    elif attack == "missing-chunk":
        state.records.pop(("authorization-evidence", descriptor["chunks"][0]))
    elif attack == "bundle-limit":
        monkeypatch.setattr(evidence_export, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(ValueError, match=f"^{message}$"):
        await service.export(receipt_id, now=100)


@pytest.mark.parametrize("now", [99, 200, True, 100.0])
async def test_export_requires_current_recipient_approval(retained_case, now):
    _, pin, service, _ = retained_case
    with pytest.raises(ValueError, match="^Evidence recipient is not currently approved$"):
        await service.export(pin(), now=now)


def test_recipient_cannot_cross_authenticated_tenant(retained_case):
    from src.services.evidence_export import EvidenceExportService

    _, _, service, _ = retained_case
    recipient = EvidenceRecipient.model_validate({**service.recipient.model_dump(), "tenant_id": "different-tenant"})
    with pytest.raises(ValueError, match="^Evidence recipient tenant mismatch$"):
        EvidenceExportService(None, None, service.principal, recipient)


async def test_export_preserves_retained_timestamp_without_claiming_verification(retained_case):
    import base64

    from src.services.timestamp_evidence import timestamp_record_id

    state, pin, service, private = retained_case
    receipt_id = pin()
    # Export only retains bytes; timestamp signature verification is a separate service.
    timestamp = {
        "schema_version": "clearproof-retained-timestamp-v1",
        "tenant_id": service.principal.tenant_id,
        "receipt_id": receipt_id,
        "response": [base64.b64encode(b"synthetic-timestamp").decode()],
    }
    state.records[("authorization-evidence", timestamp_record_id(receipt_id))] = timestamp
    raw = await service.export(receipt_id, now=100)
    bundle = open_evidence_bundle(raw, private, expected_binding=json.loads(raw)["binding"])
    assert bundle["decision_timestamp"] == timestamp
    assert bundle["timing_authority"] == "operator-clock-only"
