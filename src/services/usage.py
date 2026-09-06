"""Tenant metadata inventory for operational review; never an invoice or proof of validity."""

from typing import Annotated, Literal

from pydantic import Field

from src.auth.principal import Principal
from src.protocol.transfer import Epoch, OpaqueId, Record
from src.storage.database import Database

Counter = Annotated[int, Field(ge=0, le=2**53 - 1)]


class UsageCounters(Record):
    encrypted_records: Counter
    ciphertext_bytes: Counter
    retained_observations: Counter
    retained_events: Counter
    retained_proofs: Counter
    retained_receipts: Counter
    retained_policy_versions: Counter
    consumed_nullifiers: Counter


class UsageInventory(Record):
    schema_version: Literal["clearproof-usage-inventory-v1"] = "clearproof-usage-inventory-v1"
    scope: Literal["retained-tenant-records"] = "retained-tenant-records"
    billing_status: Literal["not-an-invoice"] = "not-an-invoice"
    tenant_id: OpaqueId
    sampled_at: Epoch
    counters: UsageCounters


async def usage_inventory(db: Database, principal: Principal, *, now: int) -> UsageInventory:
    principal = Principal.model_validate(principal)
    principal.require("usage:read")
    # A single SQL statement takes one database snapshot across both tables.
    async with db.connection() as conn:
        row = await (
            await conn.execute(
                """SELECT count(*), COALESCE(sum(octet_length(ciphertext)), 0)::bigint,
                count(*) FILTER (WHERE kind='observation'), count(*) FILTER (WHERE kind='event'),
                count(*) FILTER (WHERE kind='proof'), count(*) FILTER (WHERE kind='receipt'),
                count(*) FILTER (WHERE kind='policy'),
                (SELECT count(*) FROM pilot_consumptions WHERE tenant_id=%s)
                FROM pilot_records WHERE tenant_id=%s""",
                (principal.tenant_id, principal.tenant_id),
            )
        ).fetchone()
    return UsageInventory(
        tenant_id=principal.tenant_id,
        sampled_at=now,
        counters=UsageCounters(**dict(zip(UsageCounters.model_fields, row, strict=True))),
    )
