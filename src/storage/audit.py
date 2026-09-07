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
        data_hash = hashlib.sha256(data).hexdigest()
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                # Serialize head selection and insertion in the same transaction.
                # The lock is scoped to this schema's audit table; other schemas
                # and databases sharing a server remain independent.
                await cur.execute("LOCK TABLE audit_entries IN SHARE ROW EXCLUSIVE MODE")
                await cur.execute(
                    "SELECT sequence_number, entry_hash FROM audit_entries ORDER BY sequence_number DESC LIMIT 1"
                )
                head = await cur.fetchone()
                seq = head[0] + 1 if head else 1
                prev = head[1] if head else "0" * 64
                now = int(time.time())
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

            previous_seq = 0
            previous_hash = "0" * 64
            for seq, data_hash, stored_prev, stored_hash in rows:
                if seq > start_seq:
                    if seq != previous_seq + 1 or stored_prev != previous_hash:
                        return False
                    expected_hash = StoredAuditEntry.compute_hash(data_hash, stored_prev, seq)
                    if stored_hash != expected_hash:
                        return False
                previous_seq = seq
                previous_hash = stored_hash

            return True

    @staticmethod
    def _row_to_entry(row: Mapping[str, Any]) -> StoredAuditEntry:
        return StoredAuditEntry.model_validate(row)
