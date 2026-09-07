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
