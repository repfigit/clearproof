"""Atomically retain a verified Fireblocks observation and encrypted exact bytes."""

import base64
import hashlib
import json

import jwt

from src.adapters.fireblocks import FireblocksBinding, FireblocksVerifier, decode_segment
from src.protocol.canonical import record_digest
from src.prover.pilot_artifacts import strict_json
from src.services.event_ingestion import EventIngestionService


class FireblocksIntake:
    def __init__(self, events: EventIngestionService, verifier: FireblocksVerifier):
        self.events, self.verifier = events, verifier

    async def ingest(self, raw: bytes, signature: str, binding: FireblocksBinding, *, now_ms: int) -> dict:
        event = self.verifier.verify(raw, signature, binding, now_ms=now_ms)
        # Provider data may contain arbitrary PII/Unicode. Encode exact bytes into
        # small encrypted records instead of storing unencrypted raw payloads.
        chunks = tuple(
            {
                "schema_version": "clearproof-provider-body-chunk-v1",
                "base64": base64.b64encode(raw[offset : offset + 2048]).decode(),
            }
            for offset in range(0, len(raw), 2048)
        )
        header = strict_json(decode_segment(signature.split(".")[0]), limit=1024)
        selected = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.verifier.keys[header["kid"]]))
        manifest = {
            "schema_version": "clearproof-fireblocks-evidence-v1",
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_size": len(raw),
            "chunks": [record_digest("clearproof/provider-evidence/v1", chunk) for chunk in chunks],
            "signature": signature,
            "public_jwk": selected,
            "kid": header["kid"],
            "key_valid_from_ms": self.verifier.valid_from,
            "key_valid_until_ms": self.verifier.valid_until,
            "max_age_ms": self.verifier.max_age_ms,
            "binding": binding.model_dump(mode="json"),
        }
        # This is an internal adapter call, not a request-controlled storage hook.
        return await self.events._ingest_with_evidence(event, now=now_ms // 1000, evidence=(*chunks, manifest))
