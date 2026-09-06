"""Tenant-bound encrypted records and atomic operations for the pilot service.

This is a storage boundary, not a proof verifier. Application services must
validate credential/proof authenticity and current policy before consuming.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.storage.database import Database
from src.storage.pilot_cipher import RecordCipher

_WRITE_ROLES = {
    "credential": "credential:issue",
    "issuance-root": "credential:issue",
    "proof": "proof:generate",
    "transfer": "proof:generate",
    "receipt": "proof:generate",
    "event": "events:ingest",
    "provider-evidence": "events:ingest",
    "policy": "policy:approve",
    "revocation": "credential:revoke",
    "issuer-root": "tenant:admin",
    "sanctions-root": "tenant:admin",
    "root-source": "tenant:admin",
}
_OPERATIONS = {
    "issue-credential": "credential:issue",
    "revoke-credential": "credential:revoke",
    "record-proof": "proof:generate",
    "consume-proof": "proof:consume",
    "ingest-event": "events:ingest",
    "approve-policy": "policy:approve",
    "update-root": "tenant:admin",
}


class RecordConflict(Exception):
    """Existing immutable record, changed request or stale expected revision."""


class ReplayConflict(Exception):
    """Authorization nullifier is already consumed in this tenant."""


@dataclass(frozen=True)
class RecordSnapshot:
    revision: int
    value: dict = field(repr=False)


def _identifier(value: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise ValueError("Expected opaque record identifier")
    return value


def _kind(value: str) -> str:
    if value not in _WRITE_ROLES:
        raise ValueError("Unsupported pilot record kind")
    return value


class PilotStore:
    def __init__(self, db: Database, cipher: RecordCipher, principal: Principal):
        self._db, self._cipher = db, cipher
        self._principal = Principal.model_validate(principal)

    @property
    def tenant_id(self) -> str:
        return self._principal.tenant_id

    @asynccontextmanager
    async def transaction(self):
        # Serialize mutations within a tenant, not across the deployment. A hash
        # collision can only add contention; every query still uses full tenant ID.
        lock = int.from_bytes(
            hashlib.sha256(("clearproof/pilot/" + self.tenant_id).encode()).digest()[:8], "big", signed=True
        )
        async with asyncio.timeout(30):
            async with self._db.connection() as conn:
                await conn.execute("SELECT pg_advisory_xact_lock(%s)", (lock,))
                tx = PilotTransaction(conn, self._cipher, self._principal)
                try:
                    yield tx
                finally:
                    tx._closed = True

    async def read(self, kind: str, record_id: str, *, revision: int | None = None) -> RecordSnapshot | None:
        self._principal.require("evidence:decrypt")
        _kind(kind)
        _identifier(record_id)
        async with self._db.connection() as conn:
            tx = PilotTransaction(conn, self._cipher, self._principal)
            try:
                return await tx.read(kind, record_id, revision=revision)
            finally:
                tx._closed = True

    async def get(self, kind: str, record_id: str) -> dict | None:
        snapshot = await self.read(kind, record_id)
        return snapshot.value if snapshot else None

    async def run_idempotent(
        self,
        operation: str,
        key: str,
        request: dict,
        callback: Callable[["PilotTransaction"], Awaitable[dict]],
    ) -> dict:
        if operation not in _OPERATIONS:
            raise ValueError("Unsupported pilot operation")
        self._principal.require(_OPERATIONS[operation])
        _identifier(key)
        request_digest = record_digest(
            "clearproof/idempotent-request/v1",
            {
                "actor_id": self._principal.actor_id,
                "operation": operation,
                "request": request,
            },
        )
        record_id = hashlib.sha256((operation + "\0" + key).encode()).hexdigest()
        async with self.transaction() as tx:
            row = await tx._row("idempotency", record_id)
            if row:
                cached = self._cipher.open(self.tenant_id, "idempotency", record_id, row)
                if not hmac.compare_digest(cached["request_digest"], request_digest):
                    raise RecordConflict("Idempotency key belongs to a different request or actor")
                return cached["result"]
            result = await callback(tx)
            if type(result) is not dict:
                raise ValueError("Idempotent operation result must be an object")
            await tx._put("idempotency", record_id, {"request_digest": request_digest, "result": result}, None)
            return result


class PilotTransaction:
    def __init__(self, conn, cipher: RecordCipher, principal: Principal):
        self._conn, self._cipher, self._principal = conn, cipher, principal
        self._closed = False

    @property
    def tenant_id(self) -> str:
        return self._principal.tenant_id

    def _check_open(self):
        if self._closed:
            raise RuntimeError("Pilot transaction is closed")

    def require_issuer(self, issuer_did: str) -> None:
        self._check_open()
        self._principal.require_issuer(issuer_did)

    def require_admin(self) -> None:
        self._check_open()
        self._principal.require("tenant:admin")

    async def _row(self, kind: str, record_id: str, revision: int | None = None) -> dict | None:
        self._check_open()
        if revision is not None and (type(revision) is not int or not 1 <= revision <= 2**53 - 1):
            raise ValueError("Revision must be a positive safe integer")
        query = "SELECT * FROM pilot_records WHERE tenant_id=%s AND kind=%s AND record_id=%s"
        params = [self._principal.tenant_id, kind, record_id]
        if revision is not None:
            query += " AND revision=%s"
            params.append(revision)
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(query + " ORDER BY revision DESC LIMIT 1", params)
            return await cur.fetchone()

    async def read(self, kind: str, record_id: str, *, revision: int | None = None) -> RecordSnapshot | None:
        self._principal.require("evidence:decrypt")
        row = await self._row(_kind(kind), _identifier(record_id), revision)
        if row is None:
            return None
        return RecordSnapshot(row["revision"], self._cipher.open(self._principal.tenant_id, kind, record_id, row))

    async def get(self, kind: str, record_id: str) -> dict | None:
        snapshot = await self.read(kind, record_id)
        return snapshot.value if snapshot else None

    async def put(self, kind: str, record_id: str, value: dict, *, expected_revision: int | None = None) -> int:
        self._principal.require(_WRITE_ROLES[_kind(kind)])
        return await self._put(kind, _identifier(record_id), value, expected_revision)

    async def record_ids(self, kind: str, *, after: str | None = None, limit: int = 256) -> list[str]:
        """Bounded, tenant-filtered keyset scan within the held transaction."""
        self._check_open()
        self._principal.require("evidence:decrypt")
        _kind(kind)
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("Scan limit must be 1–256")
        if after is not None:
            _identifier(after)
        rows = await (
            await self._conn.execute(
                "SELECT DISTINCT record_id FROM pilot_records WHERE tenant_id=%s AND kind=%s "
                "AND record_id > %s ORDER BY record_id LIMIT %s",
                (self.tenant_id, kind, after or "", limit),
            )
        ).fetchall()
        return [row[0] for row in rows]

    async def _put(self, kind: str, record_id: str, value: dict, expected_revision: int | None) -> int:
        self._check_open()
        if expected_revision is not None and (
            type(expected_revision) is not int or not 1 <= expected_revision < 2**53 - 1
        ):
            raise ValueError("Expected revision must allow a positive safe-integer successor")
        row = await self._row(kind, record_id)
        if (row is None and expected_revision is not None) or (row and row["revision"] != expected_revision):
            raise RecordConflict("Record already exists or expected revision differs")
        # Proofs/events/receipts/revocations/idempotency results are append-only.
        if row and kind not in ("issuance-root", "issuer-root", "sanctions-root"):
            raise RecordConflict("Pilot record is immutable")
        revision = (row["revision"] if row else 0) + 1
        sealed = self._cipher.seal(self._principal.tenant_id, kind, record_id, revision, value)
        await self._conn.execute(
            """INSERT INTO pilot_records
            (tenant_id,kind,record_id,revision,key_id,content_tag,nonce,ciphertext)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                self._principal.tenant_id,
                kind,
                record_id,
                revision,
                sealed["key_id"],
                sealed["content_tag"],
                sealed["nonce"],
                sealed["ciphertext"],
            ),
        )
        return revision

    async def event_scopes(self, *, after: str | None, limit: int) -> list[str]:
        self._check_open()
        self._principal.require("evidence:decrypt")
        if type(limit) is not int or not 1 <= limit <= 16:
            raise ValueError("Invalid scope page limit")
        rows = await (
            await self._conn.execute(
                "SELECT DISTINCT scope_digest FROM pilot_event_index WHERE tenant_id=%s AND scope_digest>%s "
                "ORDER BY scope_digest LIMIT %s",
                (self.tenant_id, _identifier(after) if after else "", limit + 1),
            )
        ).fetchall()
        return [row[0] for row in rows]

    async def event_ids(self, scope_digest: str) -> list[str]:
        self._check_open()
        self._principal.require("evidence:decrypt")
        rows = await (
            await self._conn.execute(
                "SELECT record_id FROM pilot_event_index WHERE tenant_id=%s AND scope_digest=%s "
                "ORDER BY record_id LIMIT 257",
                (self.tenant_id, _identifier(scope_digest)),
            )
        ).fetchall()
        if len(rows) > 256:
            raise ValueError("Transfer event capacity exceeded")
        return [row[0] for row in rows]

    async def index_event(self, record_id: str, scope_digest: str, stream_digest: str, sequence: int) -> None:
        self._check_open()
        self._principal.require("events:ingest")
        if type(sequence) is not int or not 1 <= sequence <= 2**53 - 1:
            raise ValueError("Invalid source sequence")
        try:
            await self._conn.execute(
                "INSERT INTO pilot_event_index (tenant_id, record_id, scope_digest, stream_digest, source_sequence) "
                "VALUES (%s,%s,%s,%s,%s)",
                (
                    self.tenant_id,
                    _identifier(record_id),
                    _identifier(scope_digest),
                    _identifier(stream_digest),
                    sequence,
                ),
            )
        except UniqueViolation:
            raise RecordConflict("Event identity or source sequence already exists") from None

    async def consume(self, nullifier: str, proof_id: str) -> None:
        self._check_open()
        self._principal.require("proof:consume")
        _identifier(proof_id)
        if type(nullifier) is not str or not re.fullmatch(r"[0-9a-f]{64}", nullifier):
            raise ValueError("Expected canonical 32-byte nullifier")
        result = await self._conn.execute(
            """INSERT INTO pilot_consumptions (tenant_id,nullifier,proof_id)
            VALUES (%s,%s,%s) ON CONFLICT (tenant_id,nullifier) DO NOTHING RETURNING nullifier""",
            (self._principal.tenant_id, nullifier, proof_id),
        )
        if await result.fetchone() is None:
            raise ReplayConflict("Authorization is already consumed")

    async def is_consumed(self, nullifier: str) -> bool:
        self._check_open()
        self._principal.require("proof:inspect")
        if type(nullifier) is not str or not re.fullmatch(r"[0-9a-f]{64}", nullifier):
            raise ValueError("Expected canonical 32-byte nullifier")
        result = await self._conn.execute(
            "SELECT 1 FROM pilot_consumptions WHERE tenant_id=%s AND nullifier=%s",
            (self._principal.tenant_id, nullifier),
        )
        return await result.fetchone() is not None
