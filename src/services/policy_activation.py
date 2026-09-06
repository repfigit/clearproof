"""Explicit reviewed-policy activation with encrypted revision history."""

import json

from pydantic import Field

from src.auth.principal import Principal
from src.policy.model import PilotPolicy
from src.protocol.canonical import record_digest
from src.protocol.transfer import Hex32, Record
from src.storage.pilot import PilotStore, PilotTransaction, RecordConflict


class PolicyActivationRequest(Record):
    policy_digest: Hex32
    expected_revision: int | None = Field(default=None, ge=1, le=2**53 - 1)


def activation_scope(policy: PilotPolicy) -> str:
    return record_digest("clearproof/policy-activation-scope/v1", list(policy.scope))


async def reviewed_policy(tx, digest: str, *, now: int) -> PilotPolicy:
    record = await tx.get("policy", digest)
    if record is None or record.get("schema_version") != "clearproof-policy-approval-v1":
        raise ValueError("Reviewed policy unavailable")
    policy = PilotPolicy.model_validate_json(json.dumps(record["policy"]))
    if (
        policy.digest != digest
        or policy.tenant_id != tx.tenant_id
        or type(record.get("approved_at")) is not int
        or record["approved_at"] > now
        or not policy.effective_from <= now < policy.effective_until
    ):
        raise ValueError("Reviewed policy is outside current scope or validity")
    return policy


class PolicyActivationService:
    def __init__(self, db, cipher, principal: Principal):
        self.principal = Principal.model_validate(principal)
        self.store = PilotStore(db, cipher, self.principal)

    async def activate(self, request: PolicyActivationRequest, *, idempotency_key: str, now: int) -> dict:
        self.principal.require("policy:activate")
        self.principal.require("evidence:decrypt")
        request = PolicyActivationRequest.model_validate(request)
        if type(now) is not int or not 0 <= now < 2**53:
            raise ValueError("Invalid activation clock")

        async def persist(tx):
            policy = await reviewed_policy(tx, request.policy_digest, now=now)
            scope = activation_scope(policy)
            previous = await tx.read("policy-activation", scope)
            if previous and (
                previous.value.get("schema_version") != "clearproof-policy-activation-v1"
                or previous.value.get("scope_digest") != scope
                or type(previous.value.get("revision")) is not int
                or previous.value["revision"] != previous.revision
                or type(previous.value.get("activated_at")) is not int
            ):
                raise ValueError("Invalid predecessor activation")
            if (previous.revision if previous else None) != request.expected_revision:
                raise RecordConflict("Policy activation revision changed")
            if previous and (previous.value["activated_at"] > now or previous.value["policy_digest"] == policy.digest):
                raise RecordConflict("Policy activation is redundant or precedes its predecessor")
            revision = (previous.revision if previous else 0) + 1
            value = {
                "schema_version": "clearproof-policy-activation-v1",
                "scope_digest": scope,
                "policy_digest": policy.digest,
                "revision": revision,
                "previous_digest": record_digest("clearproof/policy-activation/v1", previous.value)
                if previous
                else None,
                "activated_at": now,
                "actor_id": self.principal.actor_id,
            }
            await tx.put("policy-activation", scope, value, expected_revision=request.expected_revision)
            return {"scope_digest": scope, "policy_digest": policy.digest, "revision": revision, "activated_at": now}

        return await self.store.run_idempotent(
            "activate-policy", idempotency_key, request.model_dump(mode="json"), persist
        )

    async def current(self, scope_digest: str, *, now: int) -> PilotPolicy:
        self.principal.require("policy:read")
        self.principal.require("evidence:decrypt")
        async with self.store.transaction() as tx:
            return await load_active_policy(tx, scope_digest, now=now)


async def load_active_policy(
    tx: PilotTransaction,
    scope_digest: str,
    *,
    now: int,
    evaluated_at: int | None = None,
) -> PilotPolicy:
    """Read the active selection inside the caller's authenticated tenant transaction."""
    if type(now) is not int or not 0 <= now < 2**53:
        raise ValueError("Invalid activation clock")
    head = await tx.read("policy-activation", scope_digest)
    if head is None:
        raise ValueError("No active policy in this tenant scope")
    value = head.value
    if (
        value.get("schema_version") != "clearproof-policy-activation-v1"
        or value.get("scope_digest") != scope_digest
        or type(value.get("revision")) is not int
        or value.get("revision") != head.revision
        or type(value.get("activated_at")) is not int
        or value["activated_at"] > now
    ):
        raise ValueError("Invalid policy activation head")
    if evaluated_at is not None and (type(evaluated_at) is not int or not value["activated_at"] <= evaluated_at <= now):
        raise ValueError("Policy activation does not cover proof evaluation time")
    policy = await reviewed_policy(tx, value["policy_digest"], now=now)
    if activation_scope(policy) != scope_digest:
        raise ValueError("Active policy scope mismatch")
    return policy
