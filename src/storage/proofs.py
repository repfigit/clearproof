from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from typing import Any, Optional

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from src.storage.database import Database
from src.storage.models import StoredNullifier, StoredProof
from src.storage.signals import validate_public_signals

logger = logging.getLogger(__name__)


class ProofStore:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def get_by_id(self, proof_id: str) -> Optional[StoredProof]:
        async with self._db.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute("SELECT * FROM proofs WHERE proof_id = %s", (proof_id,))
                row = await cur.fetchone()
                return self._row_to_proof(row) if row else None

    async def get_by_transfer_id(self, transfer_id: str) -> Optional[StoredProof]:
        async with self._db.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute("SELECT * FROM proofs WHERE transfer_id = %s", (transfer_id,))
                row = await cur.fetchone()
                return self._row_to_proof(row) if row else None

    async def store(self, proof: StoredProof) -> None:
        signals = validate_public_signals(proof.public_signals)
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO proofs
                        (proof_id, transfer_id, groth16_proof, public_signals,
                         verification_key, originator_vasp_did, beneficiary_vasp_did,
                         jurisdiction, amount_tier, proof_generated_at, proof_expires_at, is_expired)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (proof_id) DO NOTHING
                    """,
                    (
                        proof.proof_id,
                        proof.transfer_id,
                        proof.groth16_proof,
                        Jsonb(signals),
                        proof.verification_key,
                        proof.originator_vasp_did,
                        proof.beneficiary_vasp_did,
                        proof.jurisdiction,
                        proof.amount_tier,
                        proof.proof_generated_at,
                        proof.proof_expires_at,
                        proof.is_expired,
                    ),
                )

    async def add_nullifier(self, nullifier: StoredNullifier) -> bool:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO nullifiers (nullifier_hash, credential_commitment, transfer_id, proof_id)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (nullifier_hash) DO NOTHING
                    RETURNING nullifier_hash
                    """,
                    (
                        nullifier.nullifier_hash,
                        nullifier.credential_commitment,
                        nullifier.transfer_id,
                        nullifier.proof_id,
                    ),
                )
                return await cur.fetchone() is not None

    async def nullifier_exists(self, nullifier_hash: str) -> bool:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT 1 FROM nullifiers WHERE nullifier_hash = %s",
                    (nullifier_hash,),
                )
                return await cur.fetchone() is not None

    async def check_idempotency(self, key: str) -> Optional[str]:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT result_hash FROM idempotency_keys WHERE key = %s AND expires_at > %s",
                    (key, int(time.time())),
                )
                row = await cur.fetchone()
                return row[0] if row else None

    async def record_idempotency(self, key: str, wallet: str, result_hash: str, ttl_seconds: int = 3600) -> None:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO idempotency_keys (key, wallet_address, result_hash, expires_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (key) DO NOTHING
                    """,
                    (key, wallet, result_hash, int(time.time()) + ttl_seconds),
                )

    async def cleanup_expired(self, max_age_hours: int = 72) -> int:
        async with self._db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM idempotency_keys WHERE expires_at < %s",
                    (int(time.time()) - (max_age_hours * 3600),),
                )
                return cur.rowcount

    @staticmethod
    def _row_to_proof(row: Mapping[str, Any]) -> StoredProof:
        return StoredProof.model_validate(row)
