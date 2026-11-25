"""Unit tests for startup-loaded runtime config accessors and fallback paths."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request

from src.api.config import (
    AuthConfig,
    _request_app_state,
    get_auth_config,
    get_event_config,
    get_fireblocks_config,
    get_record_cipher,
    get_siwe_auth,
    require_record_cipher,
)
from src.api.middleware import auth as auth_middleware
from src.api.routes import auth as auth_routes
from src.api.routes import fireblocks as fireblocks_routes
from src.auth.principal import Principal, TenantPrincipalDependency
from src.auth.siwe_auth import SIWEAuth


def test_request_app_state_handles_none_and_keyerror():
    assert _request_app_state(None) is None
    # Starlette Request without "app" in scope raises KeyError on request.app.
    bare_request = Request({"type": "http", "headers": []})
    assert _request_app_state(bare_request) is None
    assert _request_app_state(SimpleNamespace(app=None)) is None


def test_get_auth_config_handles_none_request_and_non_auth_config_state(monkeypatch):
    monkeypatch.setenv("SIWE_DOMAIN", "fallback.example")
    cfg = get_auth_config(None)
    assert isinstance(cfg, AuthConfig)
    assert cfg.siwe_domain == "fallback.example"

    # Explicit non-AuthConfig value on state falls back to module/env defaults.
    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(auth_config="invalid")))
    cfg2 = get_auth_config(req)
    assert isinstance(cfg2, AuthConfig)
    assert cfg2.siwe_domain == "fallback.example"


def test_get_siwe_auth_handles_non_siwe_existing_attr_and_missing_state(monkeypatch):
    monkeypatch.setenv("SIWE_DOMAIN", "siwe-fallback.example")

    # Request without state (e.g. request=None) still constructs SIWEAuth without caching.
    no_state_siwe = get_siwe_auth(None)
    assert isinstance(no_state_siwe, SIWEAuth)
    assert no_state_siwe.domain == "siwe-fallback.example"

    # Existing non-SIWEAuth attribute on app.state is not returned and not overwritten.
    app = FastAPI()
    app.state.siwe_auth = "not-a-siwe-instance"
    req = Request({"type": "http", "app": app, "headers": []})
    fallback_siwe = get_siwe_auth(req)
    assert isinstance(fallback_siwe, SIWEAuth)
    assert fallback_siwe.domain == "siwe-fallback.example"
    assert app.state.siwe_auth == "not-a-siwe-instance"


def test_event_and_fireblocks_config_accessors_return_none_when_state_missing():
    bare_request = Request({"type": "http", "headers": []})
    assert get_event_config(None) is None
    assert get_event_config(bare_request) is None
    assert get_fireblocks_config(None) is None
    assert get_fireblocks_config(bare_request) is None


def test_get_record_cipher_returns_cipher_or_raises_503():
    sentinel = object()
    req_with_cipher = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(record_cipher=sentinel)))
    assert get_record_cipher(req_with_cipher) is sentinel
    assert require_record_cipher(req_with_cipher) is sentinel

    for bad_req in (
        None,
        Request({"type": "http", "headers": []}),
        SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(record_cipher=None))),
    ):
        with pytest.raises(HTTPException) as exc_info:
            get_record_cipher(bad_req, detail="Custom unavailable detail")
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == "Custom unavailable detail"


def test_auth_route_get_siwe_without_request_caches_module_fallback(monkeypatch):
    monkeypatch.setattr(auth_routes, "_siwe", None)
    monkeypatch.setenv("SIWE_DOMAIN", "module-fallback.example")
    first = auth_routes._get_siwe(None)
    assert isinstance(first, SIWEAuth)
    assert first.domain == "module-fallback.example"
    # Second call reuses the cached module-level _siwe instance.
    assert auth_routes._get_siwe(None) is first


async def test_verify_siwe_session_constructs_siwe_auth_when_not_passed(monkeypatch):
    monkeypatch.setenv("SIWE_DOMAIN", "direct.example")
    with pytest.raises(HTTPException) as exc_info:
        await auth_middleware._verify_siwe_session("unknown-session-token")
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired SIWE session"

    cfg = AuthConfig(siwe_domain="configured.example")
    with pytest.raises(HTTPException) as exc_info2:
        await auth_middleware._verify_siwe_session("unknown-session-token", config=cfg)
    assert exc_info2.value.status_code == 401


async def test_fireblocks_route_returns_503_when_get_fireblocks_config_raises(monkeypatch):
    principal = Principal(
        tenant_id="tenant-a",
        actor_id="actor-a",
        roles=("events:ingest", "evidence:decrypt"),
    )
    app = FastAPI()
    app.include_router(fireblocks_routes.router)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal

    def broken_config(_request):
        raise ValueError("SYNTHETIC-PRIVATE-PARSE-DETAIL")

    monkeypatch.setattr(fireblocks_routes, "get_fireblocks_config", broken_config)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/pilot/fireblocks/simulator-a", content=b"{}")
    assert response.status_code == 503
    assert response.json() == {"detail": "Fireblocks relay configuration is unavailable"}
    assert "SYNTHETIC-PRIVATE-PARSE-DETAIL" not in response.text
