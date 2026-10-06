# SPDX-License-Identifier: Apache-2.0
"""Bounded private selectors, explicit issuer permissions and redacted failures."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from src.api.routes import enrollment as routes
from src.auth.principal import Principal, TenantPrincipalDependency
from src.services.enrollment_inventory import EnrollmentInventoryPage, EnrollmentPageRequest, InventoryAudience


@pytest.fixture
async def api(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.delenv("PII_ROTATED_KEYS", raising=False)
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "1" * 40)
    who = Principal(
        tenant_id="tenant-a",
        actor_id="issuer",
        roles=("credential:issue", "evidence:decrypt"),
        issuer_dids=("did:web:issuer.example",),
    )
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: who
    app.state.db = SimpleNamespace(is_ready=True)
    page = AsyncMock(return_value=EnrollmentInventoryPage(checked_at=120, entries=(), next_cursor=None))
    monkeypatch.setattr(routes.EnrollmentInventoryService, "page", page)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://synthetic.local") as client:
        yield SimpleNamespace(client=client, app=app, who=who, page=page)


async def test_list_is_typed_minimized_and_uses_only_operator_audience(api):
    response = await api.client.post("/pilot/credential/list", json={"issuer_did": "did:web:issuer.example"})
    assert response.headers["Cache-Control"] == "no-store"
    assert response.status_code == 200
    assert response.json()["scope"] == "live-enrollment-inventory"
    assert response.json()["authorization_consumed"] is False
    assert api.who.tenant_id not in response.text
    api.page.assert_awaited_once()
    assert isinstance(api.page.call_args.args[0], EnrollmentPageRequest)
    assert type(api.page.call_args.kwargs["now"]) is int
    schema = api.app.openapi()["paths"]["/pilot/credential/list"]["post"]
    assert schema["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "EnrollmentInventoryPage"
    )


@pytest.mark.parametrize(
    "body",
    [
        b"{",
        b'{"issuer_did":"did:web:ISSUER.example"}',
        b'{"issuer_did":"issuer.example"}',
        b'{"issuer_did":"did:web:issuer.example","limit":65}',
        b'{"issuer_did":"did:web:issuer.example","tenant_id":"other"}',
        b'{"issuer_did":"did:web:issuer.example","issuer_did":"did:web:other.example"}',
    ],
)
async def test_bad_private_body_rejected_before_service(api, body):
    response = await api.client.post("/pilot/credential/list", content=body)
    assert response.status_code == 422 and response.json() == {"detail": "Invalid enrollment inventory page"}
    api.page.assert_not_called()


async def test_query_selectors_and_oversized_body_are_rejected(api):
    assert (await api.client.post("/pilot/credential/list?after=other", json={})).status_code == 422
    assert (await api.client.post("/pilot/credential/list", content=b"x" * 1025)).status_code == 413
    api.page.assert_not_called()


async def test_unauthenticated_or_unscoped_access_is_rejected(api):
    api.app.dependency_overrides.clear()
    assert (await api.client.post("/pilot/credential/list", json={})).status_code == 401
    api.app.dependency_overrides[TenantPrincipalDependency] = lambda: api.who
    response = await api.client.post("/pilot/credential/list", json={"issuer_did": "did:web:other.example"})
    assert response.status_code == 403
    api.page.assert_not_called()


@pytest.mark.parametrize("failure", ["absent-db", "closed-db", "missing-key", "bad-chain", "bad-registry", "source"])
async def test_unavailable_or_inconsistent_inventory_is_redacted(api, monkeypatch, failure):
    if failure == "absent-db":
        api.app.state.db = None
    elif failure == "closed-db":
        api.app.state.db.is_ready = False
    elif failure == "missing-key":
        monkeypatch.delenv("PII_MASTER_KEY")
    elif failure == "bad-chain":
        monkeypatch.setenv("PILOT_CHAIN_ID", "SYNTHETIC-PRIVATE-DETAIL")
    elif failure == "bad-registry":
        monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "SYNTHETIC-PRIVATE-DETAIL")
    else:
        api.page.side_effect = ValueError("SYNTHETIC-PRIVATE-DETAIL")
    response = await api.client.post("/pilot/credential/list", json={"issuer_did": "did:web:issuer.example"})
    assert response.status_code == 503 and "PRIVATE" not in response.text


@pytest.mark.parametrize(
    "change",
    [
        dict(limit=0),
        dict(limit=True),
        dict(after="A" * 64),
        dict(issuer_did="did:web:ISSUER.example"),
        dict(issuer_did="issuer.example"),
    ],
)
def test_inventory_request_is_canonical_and_bounded(change):
    with pytest.raises(ValueError):
        EnrollmentPageRequest(**{**dict(issuer_did="did:web:issuer.example"), **change})


def test_zero_inventory_registry_is_not_a_usable_operator_target():
    with pytest.raises(ValueError, match="Invalid inventory audience"):
        InventoryAudience(chain_id=31337, registry_address="0x" + "0" * 40)


async def test_backfill_is_explicit_admin_mutation_with_bounded_private_pages(api, monkeypatch):
    who = api.who.model_copy(update={"roles": (*api.who.roles, "tenant:admin")})
    api.app.dependency_overrides[TenantPrincipalDependency] = lambda: who
    backfill = AsyncMock(return_value=dict(validated_records=1, next_cursor="a" * 64, inventory_complete=False))
    monkeypatch.setattr(routes.EnrollmentInventoryService, "backfill_page", backfill)
    response = await api.client.post("/pilot/credential/backfill", json={"limit": 1})
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert response.json() == dict(validated_records=1, next_cursor="a" * 64, inventory_complete=False)
    backfill.assert_awaited_once_with(after=None, limit=1)
    api.page.assert_not_called()


@pytest.mark.parametrize("roles", [("tenant:admin",), ("credential:issue", "evidence:decrypt")])
async def test_backfill_requires_each_explicit_role(api, roles):
    who = api.who.model_copy(update={"roles": roles})
    api.app.dependency_overrides[TenantPrincipalDependency] = lambda: who
    assert (await api.client.post("/pilot/credential/backfill", json={})).status_code == 403


@pytest.mark.parametrize("failure", ["query", "body", "limit", "database", "configuration", "source"])
async def test_backfill_rejects_ambiguous_selectors_and_redacts_failures(api, monkeypatch, failure):
    who = api.who.model_copy(update={"roles": (*api.who.roles, "tenant:admin")})
    api.app.dependency_overrides[TenantPrincipalDependency] = lambda: who
    backfill = AsyncMock(side_effect=ValueError("SYNTHETIC-PRIVATE-EVIDENCE"))
    monkeypatch.setattr(routes.EnrollmentInventoryService, "backfill_page", backfill)
    url, kwargs, code = "/pilot/credential/backfill", {"json": {}}, 503
    if failure == "query":
        url += "?tenant=other"
        code = 422
    elif failure == "body":
        kwargs, code = {"content": b"{"}, 422
    elif failure == "limit":
        kwargs, code = {"json": {"limit": 65}}, 422
    elif failure == "database":
        api.app.state.db = None
    elif failure == "configuration":
        monkeypatch.delenv("PII_MASTER_KEY")
    response = await api.client.post(url, **kwargs)
    assert response.status_code == code and "SYNTHETIC-PRIVATE-EVIDENCE" not in response.text
    if failure != "source":
        backfill.assert_not_called()
