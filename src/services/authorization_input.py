"""Operator-provisioned encrypted input for the local authorization endpoint."""

import base64
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from src.protocol.information_approval import SignedInformationApproval
from src.protocol.transfer import OpaqueId, Record
from src.storage.pilot_cipher import RecordCipher


class InputScope(Record):
    tenant_id: OpaqueId
    target_id: OpaqueId


@dataclass(frozen=True, repr=False)
class SealedAuthorizationInformation:
    """PII is retained only as authenticated ciphertext in server configuration.

    Provision using a trusted ingestion process; encryption alone is not approval.
    The authorization service verifies the independent information signature and
    exact transfer/credential/clock binding before any new consumption.
    """

    row: Mapping = field(repr=False)

    @classmethod
    def seal(
        cls, cipher: RecordCipher, *, tenant_id: str, target_id: str, pii: bytes, approval: SignedInformationApproval
    ):
        InputScope(tenant_id=tenant_id, target_id=target_id)
        if type(pii) is not bytes or not 1 <= len(pii) <= 32768:
            raise ValueError("Invalid authorization information size")
        approval = SignedInformationApproval.model_validate(approval)
        encoded = base64.b64encode(pii).decode("ascii")
        row = cipher.seal(
            tenant_id,
            "authorization-input",
            target_id,
            1,
            {
                "schema_version": "clearproof-authorization-input-v1",
                "payload_base64_chunks": [encoded[i : i + 4096] for i in range(0, len(encoded), 4096)],
                "approval": approval.model_dump(mode="json"),
            },
        )
        return cls(MappingProxyType({**row, "revision": 1}))

    def open(self, cipher: RecordCipher, *, tenant_id: str, target_id: str):
        InputScope(tenant_id=tenant_id, target_id=target_id)
        if self.row.get("revision") != 1 or not isinstance(self.row.get("ciphertext"), bytes):
            raise ValueError("Invalid encrypted authorization information")
        if not 16 <= len(self.row["ciphertext"]) <= 65552:
            raise ValueError("Invalid encrypted authorization information size")
        value = cipher.open(tenant_id, "authorization-input", target_id, dict(self.row))
        if set(value) != {"schema_version", "payload_base64_chunks", "approval"} or (
            value["schema_version"] != "clearproof-authorization-input-v1"
        ):
            raise ValueError("Unsupported authorization information")
        chunks = value["payload_base64_chunks"]
        if (
            type(chunks) is not list
            or not 1 <= len(chunks) <= 11
            or any(type(chunk) is not str or not 1 <= len(chunk) <= 4096 for chunk in chunks)
            or any(len(chunk) != 4096 for chunk in chunks[:-1])
        ):
            raise ValueError("Invalid encrypted information chunks")
        encoded = "".join(chunks)
        pii = base64.b64decode(encoded, validate=True)
        if base64.b64encode(pii).decode("ascii") != encoded:
            raise ValueError("Noncanonical information encoding")
        if not 1 <= len(pii) <= 32768:
            raise ValueError("Invalid authorization information size")
        approval = SignedInformationApproval.model_validate(value["approval"])
        return pii, approval
