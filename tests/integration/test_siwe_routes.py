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
        yield value, app


async def test_nonce_sign_verify_protected_request_replay_and_expiry(client):
    http_client, app = client
    response = await http_client.get("/auth/nonce")
    assert response.status_code == 200
    siwe_after_nonce = app.state.siwe_auth
    message, signature, address = signed(response.json()["nonce"])
    payload = {"message": message, "signature": signature}
    response = await http_client.post("/auth/verify", json=payload)
    assert response.status_code == 200
    # /auth/nonce, /auth/verify, and JWTAuthDependency all share the exact app.state.siwe_auth instance.
    assert app.state.siwe_auth is siwe_after_nonce
    assert siwe_after_nonce.session_count() == 1
    session = response.json()
    assert session["address"] == address
    assert session["chain_id"] == 1
    headers = {"Authorization": f"Bearer {session['session_token']}"}
    response = await http_client.get("/protected", headers=headers)
    assert response.status_code == 200
    assert app.state.siwe_auth is siwe_after_nonce
    assert response.json()["sub"] == address
    assert response.json()["auth_mode"] == "siwe"
    assert (await http_client.post("/auth/verify", json=payload)).status_code == 401
    assert (await http_client.get("/protected")).status_code == 401
    assert (await http_client.get("/protected", headers={"Authorization": "Bearer unknown"})).status_code == 401
    app.state.siwe_auth._sessions[session["session_token"]]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    assert (await http_client.get("/protected", headers=headers)).status_code == 401
    assert app.state.siwe_auth.session_count() == 0


async def test_malformed_input_and_nonce_rate_limit(client, monkeypatch):
    http_client, _ = client
    response = await http_client.post("/auth/verify", json={"message": "invalid", "signature": "0x00"})
    assert response.status_code == 401
    assert (await http_client.post("/auth/verify", json={})).status_code == 422
    monkeypatch.setattr(routes._nonce_limiter, "max_requests", 1)
    assert (await http_client.get("/auth/nonce")).status_code == 200
    limited = await http_client.get("/auth/nonce")
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
