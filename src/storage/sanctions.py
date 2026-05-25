from __future__ import annotations

import logging
from typing import Optional

from src.storage.database import Database
from src.storage.models import StoredSanctionsRoot

logger = logging.getLogger(__name__)


class SanctionsStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def get_current(self) -> Optional[StoredSanctionsRoot]:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM sanctions_roots WHERE is_current = TRUE ORDER BY updated_at DESC LIMIT 1"
                )
                row = await cur.fetchone()
                return self._row_to_root(row) if row else None

    async def get_latest(self, limit: int = 10) -> list[StoredSanctionsRoot]:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM sanctions_roots ORDER BY updated_at DESC LIMIT %s",
                    (limit,),
                )
                rows = await cur.fetchall()
                return [self._row_to_root(r) for r in rows]

    async def record_root(
        self,
        root_hash: str,
        leaf_count: int,
        source: str,
    ) -> StoredSanctionsRoot:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("UPDATE sanctions_roots SET is_current = FALSE WHERE is_current = TRUE")
                await cur.execute(
                    """
                    INSERT INTO sanctions_roots (root_hash, leaf_count, source, is_current)
                    VALUES (%s, %s, %s, TRUE)
                    RETURNING *
                    """,
                    (root_hash, leaf_count, source),
                )
                row = await cur.fetchone()
                return self._row_to_root(row)

    @staticmethod
    def _row_to_root(row) -> StoredSanctionsRoot:
        columns = [desc[0] for desc in row.cursor.description]
        return StoredSanctionsRoot(**dict(zip(columns, row)))
