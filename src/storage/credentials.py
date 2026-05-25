from __future__ import annotations

import logging
from typing import Optional

from src.storage.database import Database
from src.storage.models import StoredCredential

logger = logging.getLogger(__name__)


class CredentialStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def get_by_id(self, credential_id: str) -> Optional[StoredCredential]:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT * FROM credentials WHERE credential_id = %s", (credential_id,))
                row = await cur.fetchone()
                return self._row_to_credential(row) if row else None

    async def get_by_wallet(self, wallet: str) -> list[StoredCredential]:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM credentials WHERE subject_wallet = %s ORDER BY issued_at DESC",
                    (wallet,),
                )
                rows = await cur.fetchall()
                return [self._row_to_credential(r) for r in rows]

    async def get_by_commitment(self, commitment: str) -> Optional[StoredCredential]:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT * FROM credentials WHERE commitment = %s", (commitment,))
                row = await cur.fetchone()
                return self._row_to_credential(row) if row else None

    async def upsert(self, credential: StoredCredential) -> None:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO credentials
                        (credential_id, issuer_did, subject_wallet, jurisdiction,
                         kyc_tier, sanctions_clear, issued_at, expires_at, revoked, commitment)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (credential_id) DO UPDATE SET
                        revoked = EXCLUDED.revoked,
                        updated_at = now()
                    """,
                    (
                        credential.credential_id,
                        credential.issuer_did,
                        credential.subject_wallet,
                        credential.jurisdiction,
                        credential.kyc_tier,
                        credential.sanctions_clear,
                        credential.issued_at,
                        credential.expires_at,
                        credential.revoked,
                        credential.commitment,
                    ),
                )

    async def revoke(self, credential_id: str) -> bool:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE credentials SET revoked = TRUE, updated_at = now() WHERE credential_id = %s",
                    (credential_id,),
                )
                return (await cur.rowcount()) > 0

    async def is_revoked(self, credential_id: str) -> bool:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT revoked FROM credentials WHERE credential_id = %s", (credential_id,))
                row = await cur.fetchone()
                return row[0] if row else False

    async def is_expired(self, credential_id: str) -> bool:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT expires_at FROM credentials WHERE credential_id = %s",
                    (credential_id,),
                )
                row = await cur.fetchone()
                if not row:
                    return True
                import time

                return int(time.time()) > row[0]

    @staticmethod
    def _row_to_credential(row) -> StoredCredential:
        columns = [desc[0] for desc in row.cursor.description]
        return StoredCredential(**dict(zip(columns, row)))
