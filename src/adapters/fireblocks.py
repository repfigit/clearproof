"""Fireblocks V2 detached RS512 verification and bounded custody projection.

Operator-provisioned JWKS and transfer bindings are mandatory; no network fetch,
transaction submission, raw payload logging or persistence occurs here.
"""

import base64
import hashlib
import re
from types import MappingProxyType

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import Field

from src.protocol.transfer import OpaqueId, Record
from src.prover.pilot_artifacts import strict_json
from src.reconciliation.events import SourceEvent, TransferScope

STATUS = {
    "SUBMITTED": "created",
    "BROADCASTING": "submitted",
    "CONFIRMING": "submitted",
    "COMPLETED": "completed",
    "FAILED": "failed",
    "CANCELLED": "cancelled",
}


class FireblocksError(ValueError):
    pass


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_segment(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise FireblocksError("Invalid detached signature")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64encode(raw) != value:
        raise FireblocksError("Noncanonical signature encoding")
    return raw


class FireblocksBinding(Record):
    workspace_id: OpaqueId
    transaction_id: OpaqueId
    external_transaction_id: OpaqueId
    provider_asset_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    source_id: OpaqueId
    scope: TransferScope


class FireblocksVerifier:
    def __init__(self, jwks: bytes, *, valid_from: int, valid_until: int, max_age_ms: int = 86400000):
        if (
            type(valid_from) is not int
            or type(valid_until) is not int
            or not 0 <= valid_from < valid_until <= 2**53 - 1
        ):
            raise ValueError("Invalid operator key snapshot interval")
        if type(max_age_ms) is not int or not 1 <= max_age_ms <= 30 * 86400000:
            raise ValueError("Invalid notification age bound")
        value = strict_json(jwks)
        if (
            type(value) is not dict
            or set(value) != {"keys"}
            or type(value["keys"]) is not list
            or not 1 <= len(value["keys"]) <= 16
        ):
            raise ValueError("Invalid JWKS inventory")
        keys = {}
        for item in value["keys"]:
            if (
                type(item) is not dict
                or set(item) != {"kty", "kid", "use", "alg", "n", "e"}
                or item["kty"] != "RSA"
                or item["use"] != "sig"
                or item["alg"] != "RS512"
                or type(item["kid"]) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", item["kid"])
                or item["kid"] in keys
            ):
                raise ValueError("Unsupported or duplicate webhook key")
            decode_segment(item["n"])
            decode_segment(item["e"])
            key = jwt.PyJWK.from_dict(item).key
            if not isinstance(key, RSAPublicKey) or not 2048 <= key.key_size <= 4096:
                raise ValueError("Unsupported RSA key size")
            keys[item["kid"]] = key
        self.keys = MappingProxyType(keys)
        self.valid_from, self.valid_until, self.max_age_ms = valid_from, valid_until, max_age_ms

    def verify(self, raw: bytes, signature: str, binding: FireblocksBinding, *, now_ms: int) -> SourceEvent:
        try:
            return self._verify(raw, signature, binding, now_ms=now_ms)
        except (ValueError, TypeError, KeyError, jwt.PyJWTError, RecursionError):
            raise FireblocksError("Webhook signature, scope or payload rejected") from None

    def _verify(self, raw: bytes, signature: str, binding: FireblocksBinding, *, now_ms: int) -> SourceEvent:
        if type(raw) is not bytes or not 1 <= len(raw) <= 65536 or type(signature) is not str or len(signature) > 2048:
            raise ValueError("Invalid webhook bounds")
        if type(now_ms) is not int or not self.valid_from <= now_ms < self.valid_until:
            raise ValueError("Key snapshot is not current")
        parts = signature.split(".")
        if len(parts) != 3 or parts[1] != "":
            raise ValueError("Expected detached JWS")
        header = strict_json(decode_segment(parts[0]), limit=1024)
        if type(header) is not dict or set(header) != {"alg", "kid"} or header["alg"] != "RS512":
            raise ValueError("Unsupported protected header")
        decode_segment(parts[2])
        key = self.keys[header["kid"]]
        signed = parts[0] + "." + b64encode(raw) + "." + parts[2]
        jwt.api_jws.decode_complete(signed, key=key, algorithms=["RS512"])
        # Parse the exact verified bytes only after signature validation.
        value = strict_json(raw)
        binding = FireblocksBinding.model_validate(binding)
        if type(value) is not dict or value.get("eventType") not in {
            "transaction.created",
            "transaction.status.updated",
        }:
            raise ValueError("Unsupported notification")
        data = value["data"]
        created = value["createdAt"]
        if (
            type(created) is not int
            or not 1 <= created <= now_ms
            or now_ms - created > self.max_age_ms
            or created < self.valid_from
            or type(data) is not dict
            or value["workspaceId"] != binding.workspace_id
            or value.get("resourceId", binding.transaction_id) != binding.transaction_id
            or data["id"] != binding.transaction_id
            or data["externalTxId"] != binding.external_transaction_id
            or data["assetId"] != binding.provider_asset_id
            or data.get("operation") != "TRANSFER"
        ):
            raise ValueError("Notification does not match the authorized transaction")
        return SourceEvent(
            scope=binding.scope,
            source_id=binding.source_id,
            source_event_id=value["id"],
            source_sequence=created,
            dimension="custody",
            state=STATUS[data["status"]],
            occurred_at=created // 1000,
            evidence_digest=hashlib.sha256(raw).hexdigest(),
        )
