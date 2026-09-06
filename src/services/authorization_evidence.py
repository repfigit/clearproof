"""Preserve exact local authorization inputs for subsequent evidence export."""

import base64
import hashlib

from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.root_snapshot import root_scope_id
from src.services.policy_activation import activation_scope


async def retain_authorization_evidence(tx, *, inputs, verifier, credential_id, fact_ids, policy, now):
    """Caller must hold the verified authorization's tenant transaction.

    References pin retained revisions, never whatever is current at export time.
    An absent local revocation is an observation, not authenticated global history.
    """
    references = []
    selected = [
        ("credential", credential_id),
        ("policy", policy.digest),
        ("policy-activation", activation_scope(policy)),
        *(
            (inputs[name].snapshot.kind, root_scope_id(inputs[name].snapshot))
            for name in ("issuance", "issuers", "sanctions")
        ),
        *(("fact-evidence", identity) for identity in fact_ids),
    ]
    for kind, identity in selected:
        row = await tx.read(kind, identity)
        if row is None:
            raise ValueError("Required authorization evidence is unavailable")
        references.append(
            {
                "kind": kind,
                "record_id": identity,
                "revision": row.revision,
                "sha256": hashlib.sha256(canonical_bytes(row.value)).hexdigest(),
            }
        )
    if await tx.get("revocation", credential_id) is not None:
        raise ValueError("Credential was revoked during authorization")
    config = {
        "artifact_manifest": canonical_bytes(verifier.artifacts.manifest.model_dump(mode="json")),
        "verification_key": verifier.artifacts.verification_key_bytes,
        "asset_registry": canonical_bytes([a.model_dump(mode="json") for a in inputs["registry"].definitions]),
        "valuation_approval": canonical_bytes(inputs["valuation_approval"].model_dump(mode="json")),
        "root_pins": canonical_bytes(inputs["root_pins"].model_dump(mode="json")),
    }
    captured = {}
    for name, raw in config.items():
        if not 1 <= len(raw) <= 131072:
            raise ValueError("Authorization configuration exceeds capture limit")
        chunks = []
        for start in range(0, len(raw), 32768):
            encoded = base64.b64encode(raw[start : start + 32768]).decode("ascii")
            value = {
                "schema_version": "clearproof-evidence-chunk-v1",
                "data": [encoded[i : i + 2048] for i in range(0, len(encoded), 2048)],
            }
            identity = record_digest("clearproof/evidence-chunk/v1", value)
            previous = await tx.get("authorization-evidence", identity)
            if previous is None:
                await tx.put("authorization-evidence", identity, value)
            elif previous != value:
                raise ValueError("Authorization evidence chunk mismatch")
            chunks.append(identity)
        captured[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "chunks": chunks}
    manifest = {
        "schema_version": "clearproof-authorization-evidence-v1",
        "tenant_id": tx.tenant_id,
        "transfer_digest": inputs["transfer"].digest,
        "context_digest": inputs["context"].digest,
        "captured_at": now,
        "timing_authority": "operator-clock-only",
        "credential_status": {
            "credential_id": credential_id,
            "revocation": "not-present-in-local-store",
            "observed_at": now,
        },
        "records": references,
        "configuration": captured,
        "runtime_sha256": hashlib.sha256(verifier.bundle).hexdigest(),
    }
    identity = record_digest("clearproof/authorization-evidence/v1", manifest)
    await tx.put("authorization-evidence", identity, manifest)
    return identity
