"""Exercise nonce issuance, real wallet signing and protected HTTP access."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import Depends, FastAPI

from src.api.middleware import auth as middleware
from src.api.routes import auth as routes
from src.auth import siwe_auth
from tests.unit.test_siwe_auth import signed


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setattr(siwe_auth, "_nonce_store", {})
    monkeypatch.setattr(siwe_auth, "_session_store", {})
    monkeypatch.setattr(routes, "_siwe", None)
    monkeypatch.setattr(routes._nonce_limiter, "_requests", routes._nonce_limiter._requests.copy())
    routes._nonce_limiter._requests.clear()
    monkeypatch.setattr(middleware, "AUTH_MODE", "siwe")
    monkeypatch.setenv("SIWE_DOMAIN", "wallet.example")
    app = FastAPI()
    app.include_router(routes.router)

    @app.get("/protected")
    async def protected(claims=Depends(middleware.JWTAuthDependency)):
        return claims

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as value:
        yield value


async def test_nonce_sign_verify_protected_request_replay_and_expiry(client):
    response = await client.get("/auth/nonce")
    assert response.status_code == 200
    message, signature, address = signed(response.json()["nonce"])
    payload = {"message": message, "signature": signature}
    response = await client.post("/auth/verify", json=payload)
    assert response.status_code == 200
    session = response.json()
    assert session["address"] == address
    assert session["chain_id"] == 1
    headers = {"Authorization": f"Bearer {session['session_token']}"}
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 200
    assert response.json()["sub"] == address
    assert response.json()["auth_mode"] == "siwe"
    assert (await client.post("/auth/verify", json=payload)).status_code == 401
    assert (await client.get("/protected")).status_code == 401
    assert (await client.get("/protected", headers={"Authorization": "Bearer unknown"})).status_code == 401
    siwe_auth._session_store[session["session_token"]]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    assert (await client.get("/protected", headers=headers)).status_code == 401


async def test_malformed_input_and_nonce_rate_limit(client, monkeypatch):
    response = await client.post("/auth/verify", json={"message": "invalid", "signature": "0x00"})
    assert response.status_code == 401
    assert (await client.post("/auth/verify", json={})).status_code == 422
    monkeypatch.setattr(routes._nonce_limiter, "max_requests", 1)
    assert (await client.get("/auth/nonce")).status_code == 200
    limited = await client.get("/auth/nonce")
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
