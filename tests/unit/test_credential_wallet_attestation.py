"""Credential issue path when linking an active wallet-ownership attestation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI

from src.api.dependencies import get_credential_registry
from src.api.middleware.auth import JWTAuthDependency
from src.api.routes import credential as routes
from src.auth.principal import Principal, TenantPrincipalDependency
from src.registry.credential_registry import CredentialRegistry
from src.services.enrollment import EnrollmentNotFound
from src.services.wallet_ownership import WalletOwnershipError


@pytest.fixture
async def api(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "1" * 40)
    principal = Principal(
        tenant_id="tenant-a",
        actor_id="actor-a",
        roles=("credential:issue",),
        issuer_dids=("did:web:issuer.example",),
    )
    registry = MagicMock(spec=CredentialRegistry)
    registry.issue = AsyncMock(return_value="0xdeadbeef")
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    app.dependency_overrides[JWTAuthDependency] = lambda: {"sub": "test"}
    app.dependency_overrides[get_credential_registry] = lambda: registry
    app.state.db = SimpleNamespace(is_ready=True)
    ownership = MagicMock()
    ownership.assert_active = AsyncMock()
    with patch.object(routes, "load_keyring", return_value=None):
        with patch.object(routes, "RecordCipher", return_value=MagicMock()):
            with patch.object(routes, "WalletOwnershipService", return_value=ownership):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                    yield SimpleNamespace(client=client, ownership=ownership, registry=registry, app=app)


async def test_issue_with_wallet_attestation_marks_credential(api):
    body = {
        "issuer_did": "did:web:issuer.example",
        "subject_wallet": "0x" + "11" * 20,
        "jurisdiction": "US",
        "kyc_tier": "retail",
        "wallet_ownership_attestation_id": "cd" * 32,
    }
    response = await api.client.post("/credential/issue", json=body, headers={"X-API-Key": "unused"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["wallet_ownership_verified"] is True
    assert payload["wallet_ownership_attestation_id"] == "cd" * 32
    api.ownership.assert_active.assert_awaited_once()


@pytest.mark.parametrize(
    "error,status",
    [
        (WalletOwnershipError("inactive"), 422),
        (EnrollmentNotFound("missing"), 422),
    ],
)
async def test_issue_rejects_ineligible_attestation(api, error, status):
    api.ownership.assert_active = AsyncMock(side_effect=error)
    response = await api.client.post(
        "/credential/issue",
        json={
            "issuer_did": "did:web:issuer.example",
            "subject_wallet": "0x" + "11" * 20,
            "jurisdiction": "US",
            "kyc_tier": "retail",
            "wallet_ownership_attestation_id": "cd" * 32,
        },
    )
    assert response.status_code == status


async def test_wallet_service_unavailable_when_database_missing(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "1" * 40)
    principal = Principal(tenant_id="t", actor_id="a", roles=("credential:issue",), issuer_dids=())
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    app.dependency_overrides[JWTAuthDependency] = lambda: {"sub": "test"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/credential/issue",
            json={
                "issuer_did": "did:web:issuer.example",
                "subject_wallet": "0x" + "11" * 20,
                "jurisdiction": "US",
                "kyc_tier": "retail",
                "wallet_ownership_attestation_id": "cd" * 32,
            },
        )
        assert response.status_code == 503


async def test_wallet_service_config_unavailable(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.delenv("PILOT_CHAIN_ID", raising=False)
    principal = Principal(tenant_id="t", actor_id="a", roles=("credential:issue",), issuer_dids=())
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    app.dependency_overrides[JWTAuthDependency] = lambda: {"sub": "test"}
    app.state.db = SimpleNamespace(is_ready=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/credential/issue",
            json={
                "issuer_did": "did:web:issuer.example",
                "subject_wallet": "0x" + "11" * 20,
                "jurisdiction": "US",
                "kyc_tier": "retail",
                "wallet_ownership_attestation_id": "cd" * 32,
            },
        )
        assert response.status_code == 503
