from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Mapping
from typing import Any, Optional

from psycopg.rows import dict_row

from src.storage.database import Database
from src.storage.models import StoredAuditEntry

logger = logging.getLogger(__name__)


class PersistentAuditLog:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def append(
        self,
        entry_type: str,
        actor: str,
        transaction_ref: str,
        data: bytes,
    ) -> StoredAuditEntry:
        prev = await self._get_prev_hash()
        now = int(time.time())
        data_hash = hashlib.sha256(data).hexdigest()
        seq = await self._next_sequence()

        entry_hash = StoredAuditEntry.compute_hash(data_hash, prev, seq)

        entry = StoredAuditEntry(
            sequence_number=seq,
            timestamp=now,
            entry_type=entry_type,
            actor=actor,
            transaction_ref=transaction_ref,
            data_hash=data_hash,
            prev_entry_hash=prev,
            entry_hash=entry_hash,
        )

        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO audit_entries
                        (sequence_number, timestamp, entry_type, actor, transaction_ref,
                         data_hash, prev_entry_hash, entry_hash)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        seq,
                        now,
                        entry_type,
                        actor,
                        transaction_ref,
                        data_hash,
                        prev,
                        entry_hash,
                    ),
                )

        return entry

    async def get_entries(
        self,
        entry_type: Optional[str] = None,
        transaction_ref: Optional[str] = None,
        limit: int = 100,
    ) -> list[StoredAuditEntry]:
        conditions = []
        params: list = []

        if entry_type:
            conditions.append("entry_type = %s")
            params.append(entry_type)
        if transaction_ref:
            conditions.append("transaction_ref = %s")
            params.append(transaction_ref)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        async with self._db.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    f"SELECT * FROM audit_entries {where} ORDER BY sequence_number DESC LIMIT %s",
                    [*params, limit],
                )
                rows = await cur.fetchall()
                return [self._row_to_entry(r) for r in rows]

    async def verify_chain(self, start_seq: int = 0) -> bool:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT sequence_number, data_hash, prev_entry_hash, "
                    "entry_hash FROM audit_entries ORDER BY sequence_number ASC"
                )
                rows = await cur.fetchall()

            for seq, data_hash, stored_prev, stored_hash in rows:
                if seq > start_seq:
                    expected_hash = StoredAuditEntry.compute_hash(data_hash, stored_prev, seq)
                    if stored_hash != expected_hash:
                        return False

            return True

    async def _get_prev_hash(self) -> str:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT entry_hash FROM audit_entries ORDER BY sequence_number DESC LIMIT 1")
                row = await cur.fetchone()
                return row[0] if row else "0" * 64

    async def _next_sequence(self) -> int:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT COALESCE(MAX(sequence_number), 0) FROM audit_entries")
                row = await cur.fetchone()
                return (row[0] or 0) + 1

    @staticmethod
    def _row_to_entry(row: Mapping[str, Any]) -> StoredAuditEntry:
        return StoredAuditEntry.model_validate(row)
