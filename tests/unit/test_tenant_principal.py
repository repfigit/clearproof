"""Signed claims, rather than client-selected headers, determine tenant scope."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from src.auth.principal import Principal, TenantPrincipalDependency, principal_from_claims

CLAIMS = {"tenant_id": "tenant-a", "actor_id": "actor-a", "roles": ["proof:inspect"], "issuer_dids": []}


@pytest.mark.parametrize(
    "replacement",
    [
        {"tenant_id": None},
        {"actor_id": None},
        {"roles": []},
        {"roles": "proof:inspect"},
        {"roles": ["*"]},
        {"roles": ["proof:inspect", "proof:inspect"]},
        {"issuer_dids": ["did:web:127.0.0.1"]},
        {"issuer_dids": ["did:web:issuer.example", "did:web:issuer.example"]},
        {"issuer_dids": ["issuer.example"]},
    ],
)
def test_missing_or_malformed_scopes_fail_closed(replacement):
    with pytest.raises(HTTPException) as error:
        principal_from_claims({**CLAIMS, **replacement})
    assert error.value.status_code == 403


def test_roles_and_issuer_scopes_are_both_required():
    principal = principal_from_claims(
        {**CLAIMS, "roles": ["credential:issue"], "issuer_dids": ["did:web:issuer.example"]}
    )
    principal.require_issuer("did:web:issuer.example")
    with pytest.raises(HTTPException):
        principal.require_issuer("did:web:other.example")
    with pytest.raises(HTTPException):
        principal.require_issuer("did:web:issuer.example", "credential:revoke")
    with pytest.raises(HTTPException):
        principal.require("proof:consume")
    admin = principal_from_claims({**CLAIMS, "roles": ["tenant:admin"]})
    with pytest.raises(HTTPException):
        admin.require("evidence:decrypt")


@pytest.fixture
def probe():
    app = FastAPI()

    @app.get("/probe")
    async def probe(principal: Principal = Depends(TenantPrincipalDependency)):
        principal.require("proof:inspect")
        return {"tenant_id": principal.tenant_id, "actor_id": principal.actor_id}

    return app


async def test_real_jwt_signature_binds_tenant_and_ignores_spoofed_headers(probe, monkeypatch):
    from src.api.middleware import auth

    private = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    # SIWE scope is configured but must not override token claims in jwt mode.
    _set_siwe_scope(monkeypatch)
    monkeypatch.setattr(
        auth,
        "JWT_PUBLIC_KEY",
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    now = int(time.time())
    claims = {
        **CLAIMS,
        "iss": auth.JWT_ISSUER,
        "aud": auth.JWT_AUDIENCE,
        "sub": "opaque-subject",
        "iat": now,
        "exp": now + 60,
    }
    token = jwt.encode(claims, private, algorithm="ES256")
    async with AsyncClient(transport=ASGITransport(app=probe), base_url="http://test") as client:
        response = await client.get(
            "/probe?tenant_id=tenant-b", headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": "tenant-b"}
        )
        assert response.status_code == 200
        assert response.json() == {"tenant_id": "tenant-a", "actor_id": "actor-a"}
        forged = jwt.encode(
            {**claims, "tenant_id": "tenant-b"}, ec.generate_private_key(ec.SECP256R1()), algorithm="ES256"
        )
        assert (await client.get("/probe", headers={"Authorization": f"Bearer {forged}"})).status_code == 401
        no_tenant = jwt.encode(
            {key: value for key, value in claims.items() if key != "tenant_id"}, private, algorithm="ES256"
        )
        assert (await client.get("/probe", headers={"Authorization": f"Bearer {no_tenant}"})).status_code == 403


async def test_api_key_requires_operator_scopes(probe, monkeypatch):
    from src.api.middleware import auth

    monkeypatch.setattr(auth, "AUTH_MODE", "api-key")
    monkeypatch.setattr(auth, "API_KEY", "synthetic-key")
    # SIWE scope is configured but must not override the static key scope in api-key mode.
    _set_siwe_scope(monkeypatch)
    for name in ("API_KEY_TENANT_ID", "API_KEY_ACTOR_ID", "API_KEY_ROLES", "API_KEY_ISSUER_DIDS"):
        monkeypatch.delenv(name, raising=False)
    async with AsyncClient(transport=ASGITransport(app=probe), base_url="http://test") as client:
        assert (
            await client.get("/probe", headers={"X-API-Key": "synthetic-key", "X-Tenant-ID": "tenant-a"})
        ).status_code == 403
        monkeypatch.setenv("API_KEY_TENANT_ID", "tenant-a")
        monkeypatch.setenv("API_KEY_ACTOR_ID", "actor-a")
        monkeypatch.setenv("API_KEY_ROLES", "proof:inspect")
        response = await client.get("/probe", headers={"X-API-Key": "synthetic-key", "X-Tenant-ID": "tenant-b"})
        assert response.status_code == 200
        assert response.json()["tenant_id"] == "tenant-a"


def _set_siwe_scope(monkeypatch, **overrides):
    """Set a SIWE scope whose roles deliberately exclude ``proof:inspect``."""
    values = {"SIWE_TENANT_ID": "tenant-siwe", "SIWE_ROLES": "usage:read"}
    values.update(overrides)
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def _install_siwe_session(app: FastAPI, token: str, address: str) -> None:
    from datetime import datetime, timedelta, timezone

    from src.auth.siwe_auth import SIWEAuth

    siwe_auth = SIWEAuth(domain="test.example")
    now = datetime.now(timezone.utc)
    siwe_auth._sessions.set(
        token,
        {
            "address": address,
            "chain_id": 1,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    app.state.siwe_auth = siwe_auth


async def test_siwe_scope_unset_fails_closed_403(probe):
    from src.api.config import AuthConfig

    _install_siwe_session(probe, "siwe-tok", "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B")
    probe.state.auth_config = AuthConfig(auth_mode="siwe", siwe_domain="test.example")
    async with AsyncClient(transport=ASGITransport(app=probe), base_url="http://test") as client:
        resp = await client.get("/probe", headers={"Authorization": "Bearer siwe-tok"})
        assert resp.status_code == 403
        assert "SIWE_TENANT_ID" in resp.json()["detail"]

        # Tenant set but roles unset still fails closed 403
        probe.state.auth_config = AuthConfig(auth_mode="siwe", siwe_domain="test.example", siwe_tenant_id="tenant-siwe")
        resp2 = await client.get("/probe", headers={"Authorization": "Bearer siwe-tok"})
        assert resp2.status_code == 403
        assert "SIWE_ROLES" in resp2.json()["detail"]


async def test_siwe_actor_defaults_to_session_address_and_respects_override(probe):
    from src.api.config import AuthConfig

    address = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
    _install_siwe_session(probe, "siwe-tok", address)
    probe.state.auth_config = AuthConfig.from_env(
        {
            "AUTH_MODE": "siwe",
            "SIWE_DOMAIN": "test.example",
            "SIWE_TENANT_ID": "tenant-siwe",
            "SIWE_ROLES": "proof:inspect, usage:read",
            "SIWE_ISSUER_DIDS": "did:web:issuer.example",
        }
    )
    async with AsyncClient(transport=ASGITransport(app=probe), base_url="http://test") as client:
        resp = await client.get(
            "/probe?tenant_id=tenant-other",
            headers={"Authorization": "Bearer siwe-tok", "X-Tenant-ID": "tenant-other"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"tenant_id": "tenant-siwe", "actor_id": address.lower()}

        # Explicit SIWE_ACTOR_ID overrides the session address
        probe.state.auth_config = AuthConfig.from_env(
            {
                "AUTH_MODE": "siwe",
                "SIWE_DOMAIN": "test.example",
                "SIWE_TENANT_ID": "tenant-siwe",
                "SIWE_ACTOR_ID": "operator-siwe",
                "SIWE_ROLES": "proof:inspect",
            }
        )
        resp2 = await client.get("/probe", headers={"Authorization": "Bearer siwe-tok"})
        assert resp2.status_code == 200
        assert resp2.json() == {"tenant_id": "tenant-siwe", "actor_id": "operator-siwe"}


async def test_siwe_principal_reaches_pilot_readiness_and_wallet_ownership_status():
    from src.api.config import AuthConfig
    from src.api.routes.readiness import router as readiness_router
    from src.api.routes.wallet_ownership import router as wallet_ownership_router

    app = FastAPI()
    app.include_router(readiness_router)
    app.include_router(wallet_ownership_router)
    _install_siwe_session(app, "siwe-pilot-tok", "0x1111111111111111111111111111111111111111")
    app.state.auth_config = AuthConfig.from_env(
        {
            "AUTH_MODE": "siwe",
            "SIWE_DOMAIN": "test.example",
            "SIWE_TENANT_ID": "tenant-siwe",
            "SIWE_ROLES": "usage:read,evidence:read",
        }
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # /pilot/readiness: passes auth + role check; returns 503 (not 403) without DB/cipher
        readiness_resp = await client.get(
            "/pilot/readiness/proving/target-1",
            headers={"Authorization": "Bearer siwe-pilot-tok"},
        )
        assert readiness_resp.status_code == 503
        assert readiness_resp.json()["status"] == "not_ready"

        # /wallet/ownership/attestations/{id} (status): passes auth; returns 503 (not 403) without DB
        wallet_resp = await client.get(
            f"/wallet/ownership/attestations/{'0x' + 'ab' * 32}",
            headers={"Authorization": "Bearer siwe-pilot-tok"},
        )
        assert wallet_resp.status_code == 503
        assert wallet_resp.json()["detail"] == "Wallet evidence database unavailable"
