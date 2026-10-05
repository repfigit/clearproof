"""Tenant-bound encrypted jobs, global admission and fenced worker leases.

Only queue metadata is plaintext. Requests, principals, secrets and results use
the existing versioned RecordCipher; neither plain fingerprints nor exceptions
retain private data. PostgreSQL's clock owns expiry and lease decisions.
"""

from __future__ import annotations

import hmac
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from psycopg.rows import dict_row

from src.auth.principal import Principal
from src.protocol.canonical import canonical_bytes
from src.storage.database import Database
from src.storage.pilot import _identifier
from src.storage.pilot_cipher import RecordCipher, RecordIntegrityError

LEASE_SECONDS = 30
ERRORS = frozenset(
    {
        "job_expired",
        "prover_failed",
        "current_state_rejected",
        "configuration_changed",
        "worker_interrupted",
        "retry_exhausted",
        "stored_input_rejected",
    }
)


class ProofJobError(ValueError):
    """Stable queue diagnostics; never inputs or database values."""


class LeaseLost(ProofJobError):
    pass


def authorize(principal: Principal):
    for role in ("proof:generate", "policy:read", "evidence:decrypt"):
        principal.require(role)


def job_identifier(value: str):
    import re

    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ProofJobError("invalid_job_id")
    return value


@dataclass(frozen=True)
class JobSnapshot:
    job_id: str
    status: str
    attempts: int
    created_at: int
    expires_at: int
    last_error: str | None
    principal: Principal = field(repr=False)
    request: dict = field(repr=False)
    result: dict | None = field(repr=False)

    def metadata(self):
        return {
            key: getattr(self, key)
            for key in ("job_id", "status", "attempts", "created_at", "expires_at", "last_error")
        }


@dataclass(frozen=True)
class JobClaim:
    snapshot: JobSnapshot
    token: str = field(repr=False)


class ProofJobQueue:
    def __init__(self, db: Database, cipher: RecordCipher):
        self._db, self._cipher = db, cipher

    @asynccontextmanager
    async def _transaction(self):
        async with self._db.connection() as conn:
            async with conn.transaction():
                async with conn.cursor(row_factory=dict_row) as cur:
                    yield cur

    async def _clock(self, cur):
        await cur.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint AS now")
        return (await cur.fetchone())["now"]

    async def _control(self, cur):
        await cur.execute("SELECT * FROM proof_job_control WHERE singleton FOR UPDATE")
        return await cur.fetchone()

    def _open(self, row, prefix):
        return self._cipher.open(
            row["tenant_id"],
            "proof-job-" + prefix,
            row["job_id"],
            {
                "revision": 1,
                "key_id": row[prefix + "_key_id"],
                "content_tag": row[prefix + "_content_tag"],
                "nonce": row[prefix + "_nonce"],
                "ciphertext": row[prefix + "_ciphertext"],
            },
        )

    def _snapshot(self, row):
        value = self._open(row, "request")
        try:
            principal = Principal.model_validate_json(canonical_bytes(value["principal"]))
            if principal.tenant_id != row["tenant_id"] or principal.actor_id != row["actor_id"]:
                raise ValueError("scope")
            request = value["input"]
            if type(request) is not dict:
                raise ValueError("shape")
        except (KeyError, ValueError, TypeError):
            raise RecordIntegrityError("Stored job scope is inconsistent") from None
        result = self._open(row, "result") if row["result_ciphertext"] is not None else None
        return JobSnapshot(
            row["job_id"],
            row["status"],
            row["attempts"],
            row["created_at"],
            row["expires_at"],
            row["last_error"],
            principal,
            request,
            result,
        )

    async def _recover(self, cur, now):
        # Running cancellations retain their slot until a reaped acknowledgement
        # or an expired lease. Graceful failures requeue only after child cleanup.
        await cur.execute(
            """
            UPDATE proof_jobs SET status=CASE
                WHEN status='cancelling' THEN 'cancelled'
                WHEN expires_at<=%s OR attempts>=3 THEN 'failed' ELSE 'queued' END,
                last_error=CASE WHEN status='cancelling' THEN NULL
                    WHEN expires_at<=%s THEN 'job_expired' ELSE 'worker_interrupted' END,
                lease_token=NULL, lease_expires_at=NULL, available_at=%s
            WHERE status IN ('proving','cancelling') AND lease_expires_at<=%s
        """,
            (now, now, now, now),
        )
        await cur.execute(
            """
            UPDATE proof_jobs SET status='failed', last_error='job_expired'
            WHERE status='queued' AND expires_at<=%s
        """,
            (now,),
        )
        await cur.execute(
            "DELETE FROM proof_jobs WHERE retain_until<=%s AND status NOT IN ('proving','cancelling')", (now,)
        )

    async def _admit(self, cur, control, tenant):
        await cur.execute(
            """
            SELECT count(*) AS total, count(*) FILTER (WHERE tenant_id=%s) AS tenant
            FROM proof_jobs WHERE status IN ('queued','proving','cancelling')
        """,
            (tenant,),
        )
        counts = await cur.fetchone()
        if counts["total"] >= control["max_pending"] or counts["tenant"] >= control["max_tenant_pending"]:
            raise ProofJobError("proof_queue_full")

    async def enqueue(self, principal: Principal, key: str, request: dict, *, expires_at: int) -> JobSnapshot:
        authorize(principal)
        _identifier(key)
        try:
            encoded = canonical_bytes(request)
            if type(request) is not dict or len(encoded) > 16384 or type(expires_at) is not int:
                raise ValueError("shape")
        except (ValueError, TypeError, RecursionError):
            raise ProofJobError("invalid_job_request") from None
        async with self._transaction() as cur:
            control = await self._control(cur)
            now = await self._clock(cur)
            await self._recover(cur, now)
            await cur.execute(
                "SELECT * FROM proof_jobs WHERE tenant_id=%s AND idempotency_key=%s", (principal.tenant_id, key)
            )
            previous = await cur.fetchone()
            if previous:
                if previous["actor_id"] != principal.actor_id:
                    raise ProofJobError("job_idempotency_conflict")
                snapshot = self._snapshot(previous)
                if snapshot.expires_at != expires_at or not hmac.compare_digest(
                    canonical_bytes(snapshot.request), encoded
                ):
                    raise ProofJobError("job_idempotency_conflict")
                return snapshot
            if not now < expires_at <= now + 300:
                raise ProofJobError("invalid_job_expiry")
            await self._admit(cur, control, principal.tenant_id)
            job = secrets.token_hex(32)
            seal = self._cipher.seal(
                principal.tenant_id,
                "proof-job-request",
                job,
                1,
                {"principal": principal.model_dump(mode="json"), "input": request},
            )
            await cur.execute(
                """
                INSERT INTO proof_jobs(tenant_id,job_id,actor_id,idempotency_key,status,created_at,expires_at,
                    retain_until,available_at,request_key_id,request_content_tag,request_nonce,request_ciphertext)
                VALUES (%s,%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
            """,
                (
                    principal.tenant_id,
                    job,
                    principal.actor_id,
                    key,
                    now,
                    expires_at,
                    now + 86400,
                    now,
                    seal["key_id"],
                    seal["content_tag"],
                    seal["nonce"],
                    seal["ciphertext"],
                ),
            )
            return self._snapshot(await cur.fetchone())

    async def read(self, principal: Principal, job_id: str) -> JobSnapshot:
        authorize(principal)
        job_identifier(job_id)
        async with self._transaction() as cur:
            now = await self._clock(cur)
            await cur.execute(
                """SELECT * FROM proof_jobs WHERE tenant_id=%s AND actor_id=%s AND job_id=%s
                AND retain_until>%s""",
                (principal.tenant_id, principal.actor_id, job_id, now),
            )
            row = await cur.fetchone()
            if row is None:
                raise ProofJobError("job_not_found")
            try:
                return self._snapshot(row)
            except RecordIntegrityError:
                if row["status"] != "failed" or row["last_error"] != "stored_input_rejected":
                    raise
                # Public failure metadata contains no decrypted request or result.
                return JobSnapshot(
                    row["job_id"],
                    row["status"],
                    row["attempts"],
                    row["created_at"],
                    row["expires_at"],
                    row["last_error"],
                    principal,
                    {},
                    None,
                )

    async def claim(self) -> JobClaim | None:
        """Trusted worker operation; serialized global control prevents overclaiming."""
        async with self._transaction() as cur:
            control = await self._control(cur)
            now = await self._clock(cur)
            await self._recover(cur, now)
            await cur.execute("SELECT count(*) AS count FROM proof_jobs WHERE status IN ('proving','cancelling')")
            if (await cur.fetchone())["count"] >= control["max_concurrent"]:
                return None
            await cur.execute(
                """SELECT * FROM proof_jobs WHERE status='queued' AND available_at<=%s
                AND expires_at>%s AND attempts<3 ORDER BY created_at,job_id FOR UPDATE SKIP LOCKED LIMIT 1""",
                (now, now),
            )
            row = await cur.fetchone()
            if row is None:
                return None
            token = secrets.token_hex(32)
            await cur.execute(
                """UPDATE proof_jobs SET status='proving', attempts=attempts+1,lease_token=%s,
                lease_expires_at=%s WHERE tenant_id=%s AND job_id=%s RETURNING *""",
                (token, now + LEASE_SECONDS, row["tenant_id"], row["job_id"]),
            )
            row = await cur.fetchone()
            try:
                snapshot = self._snapshot(row)
            except RecordIntegrityError:
                # Preserve encrypted evidence, quarantine this job, and allow
                # the next poll to progress instead of poisoning the FIFO head.
                await cur.execute(
                    """UPDATE proof_jobs SET status='failed',last_error='stored_input_rejected',
                    lease_token=NULL,lease_expires_at=NULL WHERE tenant_id=%s AND job_id=%s""",
                    (row["tenant_id"], row["job_id"]),
                )
                return None
            return JobClaim(snapshot, token)

    async def heartbeat(self, claim: JobClaim) -> str:
        async with self._transaction() as cur:
            now = await self._clock(cur)
            await cur.execute(
                """UPDATE proof_jobs SET lease_expires_at=%s WHERE tenant_id=%s AND job_id=%s
                AND lease_token=%s AND lease_expires_at>%s AND status IN ('proving','cancelling') RETURNING *""",
                (now + LEASE_SECONDS, claim.snapshot.principal.tenant_id, claim.snapshot.job_id, claim.token, now),
            )
            row = await cur.fetchone()
            if row is None:
                raise LeaseLost("job_lease_lost")
            return "job_expired" if row["expires_at"] <= now else row["status"]

    async def cancel(self, principal: Principal, job_id: str) -> str:
        authorize(principal)
        job_identifier(job_id)
        async with self._transaction() as cur:
            await cur.execute(
                """SELECT * FROM proof_jobs WHERE tenant_id=%s AND actor_id=%s AND job_id=%s FOR UPDATE""",
                (principal.tenant_id, principal.actor_id, job_id),
            )
            row = await cur.fetchone()
            if row is None:
                raise ProofJobError("job_not_found")
            if row["status"] == "completed":
                raise ProofJobError("job_already_completed")
            status = {"queued": "cancelled", "proving": "cancelling"}.get(row["status"], row["status"])
            await cur.execute(
                "UPDATE proof_jobs SET status=%s WHERE tenant_id=%s AND job_id=%s",
                (status, principal.tenant_id, job_id),
            )
            return status

    async def retry(self, principal: Principal, job_id: str) -> str:
        authorize(principal)
        job_identifier(job_id)
        async with self._transaction() as cur:
            control = await self._control(cur)
            now = await self._clock(cur)
            await self._recover(cur, now)
            await cur.execute(
                """SELECT * FROM proof_jobs WHERE tenant_id=%s AND actor_id=%s AND job_id=%s FOR UPDATE""",
                (principal.tenant_id, principal.actor_id, job_id),
            )
            row = await cur.fetchone()
            if row is None:
                raise ProofJobError("job_not_found")
            if row["status"] in ("queued", "proving"):
                return row["status"]
            if row["status"] != "failed" or row["attempts"] >= 3 or row["expires_at"] <= now:
                raise ProofJobError("job_retry_unavailable")
            await self._admit(cur, control, principal.tenant_id)
            await cur.execute(
                "UPDATE proof_jobs SET status='queued',available_at=%s WHERE tenant_id=%s AND job_id=%s",
                (now, principal.tenant_id, job_id),
            )
            return "queued"

    async def finish(self, claim: JobClaim, *, result: dict | None = None, error: str | None = None, retryable=False):
        """Call only after owned subprocesses are reaped. A stale lease never writes."""
        if (result is None) == (error is None) or (
            error is not None and (type(error) is not str or error not in ERRORS)
        ):
            raise ProofJobError("invalid_job_completion")
        if type(retryable) is not bool:
            raise ProofJobError("invalid_job_completion")
        if result is not None:
            try:
                if type(result) is not dict or len(canonical_bytes(result)) > 16384:
                    raise ValueError("shape")
            except (ValueError, TypeError, RecursionError):
                raise ProofJobError("invalid_job_result") from None
        async with self._transaction() as cur:
            now = await self._clock(cur)
            await cur.execute(
                """SELECT * FROM proof_jobs WHERE tenant_id=%s AND job_id=%s AND lease_token=%s
                AND lease_expires_at>%s AND status IN ('proving','cancelling') FOR UPDATE""",
                (claim.snapshot.principal.tenant_id, claim.snapshot.job_id, claim.token, now),
            )
            row = await cur.fetchone()
            if row is None:
                raise LeaseLost("job_lease_lost")
            seal = {"key_id": None, "content_tag": None, "nonce": None, "ciphertext": None}
            if row["status"] == "cancelling":
                status, error = "cancelled", None
            elif row["expires_at"] <= now:
                status, error = "failed", "job_expired"
            elif result is not None:
                status = "completed"
                seal = self._cipher.seal(row["tenant_id"], "proof-job-result", row["job_id"], 1, result)
            elif retryable and row["attempts"] < 3:
                status = "queued"
            else:
                status = "failed"
            await cur.execute(
                """UPDATE proof_jobs SET status=%s,last_error=%s,available_at=%s,
                lease_token=NULL,lease_expires_at=NULL,result_key_id=%s,result_content_tag=%s,
                result_nonce=%s,result_ciphertext=%s WHERE tenant_id=%s AND job_id=%s""",
                (
                    status,
                    error,
                    now + 2 ** row["attempts"],
                    seal["key_id"],
                    seal["content_tag"],
                    seal["nonce"],
                    seal["ciphertext"],
                    row["tenant_id"],
                    row["job_id"],
                ),
            )
            return status

    async def configure(self, *, max_concurrent: int, max_pending: int, max_tenant_pending: int):
        """Operator-only configuration; never exposed as a tenant API operation."""
        for value, high in ((max_concurrent, 4), (max_pending, 1024), (max_tenant_pending, 64)):
            if type(value) is not int or not 1 <= value <= high:
                raise ProofJobError("invalid_queue_limit")
        async with self._transaction() as cur:
            await self._control(cur)
            await cur.execute("SELECT count(*) AS count FROM proof_jobs WHERE status IN ('proving','cancelling')")
            if (await cur.fetchone())["count"]:
                raise ProofJobError("queue_has_active_workers")
            await cur.execute(
                """UPDATE proof_job_control SET max_concurrent=%s,max_pending=%s,max_tenant_pending=%s
                WHERE singleton""",
                (max_concurrent, max_pending, max_tenant_pending),
            )
