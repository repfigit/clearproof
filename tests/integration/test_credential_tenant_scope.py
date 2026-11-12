"""Legacy /credential/* routes are bound to the caller's tenant and issuer scope."""

import httpx
import pytest
from fastapi import FastAPI

from src.api.dependencies import get_credential_registry
from src.api.middleware.auth import JWTAuthDependency
from src.api.routes import credential as routes
from src.auth.principal import Principal, TenantPrincipalDependency
from src.registry.credential_registry import CredentialRegistry

ISSUER_A = "did:web:issuer-a.example"
ISSUER_B = "did:web:issuer-b.example"
ALL_ROLES = ("credential:issue", "credential:revoke")
ISSUE_BODY = {"subject_wallet": "0x" + "11" * 20, "jurisdiction": "US", "kyc_tier": "retail"}


def principal(tenant: str, issuers: tuple[str, ...], roles: tuple[str, ...] = ALL_ROLES) -> Principal:
    return Principal(tenant_id=tenant, actor_id="actor-" + tenant, roles=roles, issuer_dids=issuers)


TENANT_A = principal("tenant-a", (ISSUER_A,))
TENANT_B = principal("tenant-b", (ISSUER_B,))


@pytest.fixture
async def api():
    registry = CredentialRegistry()
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[JWTAuthDependency] = lambda: {"sub": "test"}
    app.dependency_overrides[get_credential_registry] = lambda: registry
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:

        async def call(who: Principal, method: str, path: str, **kwargs):
            app.dependency_overrides[TenantPrincipalDependency] = lambda: who
            return await client.request(method, path, **kwargs)

        yield call, registry


async def issue(call, who: Principal, issuer: str) -> httpx.Response:
    return await call(who, "POST", "/credential/issue", json={**ISSUE_BODY, "issuer_did": issuer})


async def test_issue_requires_role_and_exact_issuer_scope(api):
    call, registry = api
    assert (await issue(call, TENANT_A, ISSUER_B)).status_code == 403
    revoke_only = principal("tenant-a", (ISSUER_A,), ("credential:revoke",))
    assert (await issue(call, revoke_only, ISSUER_A)).status_code == 403
    assert registry._credentials == {}

    issued = await issue(call, TENANT_A, ISSUER_A)
    assert issued.status_code == 200
    assert registry.tenant_of(issued.json()["credential_id"]) == "tenant-a"


async def test_other_tenant_cannot_read_or_revoke(api):
    call, registry = api
    credential_id = (await issue(call, TENANT_A, ISSUER_A)).json()["credential_id"]

    # A foreign credential is indistinguishable from a missing one.
    assert (await call(TENANT_B, "GET", f"/credential/{credential_id}")).status_code == 404
    denied = await call(TENANT_B, "POST", "/credential/revoke", json={"credential_id": credential_id})
    assert denied.status_code == 404
    assert registry.is_revoked(credential_id) is False

    assert (await call(TENANT_A, "GET", f"/credential/{credential_id}")).json()["status"] == "active"


async def test_revoke_requires_role_and_issuer_scope_within_tenant(api):
    call, registry = api
    credential_id = (await issue(call, TENANT_A, ISSUER_A)).json()["credential_id"]
    body = {"credential_id": credential_id}

    issue_only = principal("tenant-a", (ISSUER_A,), ("credential:issue",))
    assert (await call(issue_only, "POST", "/credential/revoke", json=body)).status_code == 403
    other_issuer = principal("tenant-a", (ISSUER_B,))
    assert (await call(other_issuer, "POST", "/credential/revoke", json=body)).status_code == 403
    assert registry.is_revoked(credential_id) is False

    assert (await call(TENANT_A, "POST", "/credential/revoke", json=body)).status_code == 200
    assert registry.is_revoked(credential_id) is True


async def test_credential_without_recorded_tenant_is_not_served(api):
    """Credentials registered outside the route have no owner and fail closed."""
    from src.registry.credential_registry import zkKYCCredential

    call, registry = api
    orphan = zkKYCCredential(
        issuer_did=ISSUER_A,
        subject_wallet="0x" + "22" * 20,
        jurisdiction="US",
        kyc_tier="retail",
        sanctions_clear=True,
        issued_at=1,
        expires_at=2,
    )
    await registry.issue(orphan)
    assert registry.tenant_of(orphan.credential_id) is None
    assert (await call(TENANT_A, "GET", f"/credential/{orphan.credential_id}")).status_code == 404
    body = {"credential_id": orphan.credential_id}
    assert (await call(TENANT_A, "POST", "/credential/revoke", json=body)).status_code == 404
