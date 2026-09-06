"""Tenant/role binding for the pilot API; authentication precedes authorization."""

from __future__ import annotations

import os
from typing import Literal

from fastapi import Depends, HTTPException
from pydantic import Field, ValidationError, model_validator

from src.api.middleware.auth import JWTAuthDependency
from src.protocol.discovery_profile import DiscoveryError, parse_target
from src.protocol.transfer import OpaqueId, Record

Role = Literal[
    "credential:issue",
    "credential:revoke",
    "proof:generate",
    "proof:inspect",
    "proof:consume",
    "evidence:read",
    "evidence:decrypt",
    "events:ingest",
    "policy:read",
    "policy:approve",
    "tenant:admin",
]


class Principal(Record):
    tenant_id: OpaqueId
    actor_id: OpaqueId
    roles: tuple[Role, ...] = Field(min_length=1, max_length=16)
    issuer_dids: tuple[str, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def canonical_scopes(self):
        if len(set(self.roles)) != len(self.roles) or len(set(self.issuer_dids)) != len(self.issuer_dids):
            raise ValueError("Duplicate authorization scope")
        for did in self.issuer_dids:
            if parse_target(did).did != did:
                raise ValueError("Issuer scope requires canonical did:web")
        return self

    def require(self, role: Role) -> None:
        # No implicit wildcard or administrator override.
        if role not in self.roles:
            raise HTTPException(status_code=403, detail="Required role is not granted")

    def require_issuer(
        self, did: str, operation: Literal["credential:issue", "credential:revoke"] = "credential:issue"
    ) -> None:
        self.require(operation)
        if did not in self.issuer_dids:
            raise HTTPException(status_code=403, detail="Issuer is outside the authorized scope")


def principal_from_claims(claims: dict) -> Principal:
    """Only call with claims verified by the configured authentication provider.

    The issuer must assign opaque actor IDs; wallets/names/emails are not used as
    tenant selectors. Roles authorize operations, not factual credential validity.
    """
    roles, issuers = claims.get("roles"), claims.get("issuer_dids", [])
    if type(roles) is not list or type(issuers) is not list:
        raise HTTPException(status_code=403, detail="Tenant-scoped authorization is required")
    try:
        return Principal(
            tenant_id=claims.get("tenant_id"),
            actor_id=claims.get("actor_id"),
            roles=tuple(roles),
            issuer_dids=tuple(issuers),
        )
    except (ValidationError, ValueError, DiscoveryError) as exc:
        raise HTTPException(status_code=403, detail="Invalid tenant-scoped authorization") from exc


async def TenantPrincipalDependency(claims: dict = Depends(JWTAuthDependency)) -> Principal:  # noqa: N802
    from src.api.middleware import auth

    if auth.AUTH_MODE.lower() == "api-key":
        # A static development key maps to exactly one operator-selected tenant.
        # Header/body/query parameters cannot supply these scopes.
        claims = {
            "tenant_id": os.getenv("API_KEY_TENANT_ID"),
            "actor_id": os.getenv("API_KEY_ACTOR_ID"),
            "roles": [r for r in os.getenv("API_KEY_ROLES", "").split(",") if r],
            "issuer_dids": [d for d in os.getenv("API_KEY_ISSUER_DIDS", "").split(",") if d],
        }
    return principal_from_claims(claims)
