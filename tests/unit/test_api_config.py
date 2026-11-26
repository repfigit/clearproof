"""Unit tests for startup-loaded runtime config accessors and fallback paths."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request

from src.api.config import (
    AuthConfig,
    WalletOwnershipConfig,
    _request_app_state,
    build_wallet_web3,
    close_wallet_web3,
    get_auth_config,
    get_event_config,
    get_fireblocks_config,
    get_record_cipher,
    get_siwe_auth,
    get_wallet_ownership_config,
    get_wallet_web3,
    legacy_api_enabled,
    require_record_cipher,
    wallet_rpc_timeout_seconds,
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


def test_auth_route_get_siwe_delegates_to_app_state_accessor(monkeypatch):
    monkeypatch.setenv("SIWE_DOMAIN", "module-fallback.example")
    first = auth_routes._get_siwe(None)
    assert isinstance(first, SIWEAuth)
    assert first.domain == "module-fallback.example"

    app = FastAPI()
    req = Request({"type": "http", "app": app, "headers": []})
    from_req = auth_routes._get_siwe(req)
    assert app.state.siwe_auth is from_req
    assert auth_routes._get_siwe(req) is from_req


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


def test_wallet_ownership_config_from_env_defaults_and_validation(monkeypatch):
    valid = {"PILOT_CHAIN_ID": "31337", "PILOT_REGISTRY_ADDRESS": "0x" + "1" * 40}
    config = WalletOwnershipConfig.from_env(valid)
    assert (config.chain_id, config.registry_address) == (31337, "0x" + "1" * 40)
    assert config.delegation_recheck_seconds == 3600
    assert config.siwe_domain is None

    config = WalletOwnershipConfig.from_env(
        {
            **valid,
            "WALLET_OWNERSHIP_DELEGATION_RECHECK_SECONDS": " 45 ",
            "PILOT_SIWE_DOMAIN": "  delegation.example  ",
        }
    )
    assert config.delegation_recheck_seconds == 45
    assert config.siwe_domain == "delegation.example"
    assert WalletOwnershipConfig.from_env({**valid, "PILOT_SIWE_DOMAIN": " "}).siwe_domain is None
    assert (
        WalletOwnershipConfig.from_env(
            {**valid, "WALLET_OWNERSHIP_DELEGATION_RECHECK_SECONDS": "  "}
        ).delegation_recheck_seconds
        == 3600
    )

    invalid = [
        ({}, "PILOT_CHAIN_ID"),
        ({**valid, "PILOT_CHAIN_ID": "synthetic-invalid-chain"}, "integer"),
        ({**valid, "PILOT_CHAIN_ID": "0"}, "positive"),
        ({**valid, "PILOT_REGISTRY_ADDRESS": "0x1234"}, "PILOT_REGISTRY_ADDRESS"),
        ({**valid, "WALLET_OWNERSHIP_DELEGATION_RECHECK_SECONDS": "later"}, "integer"),
        ({**valid, "WALLET_OWNERSHIP_DELEGATION_RECHECK_SECONDS": "0"}, "positive"),
    ]
    for env, pattern in invalid:
        with pytest.raises(ValueError, match=pattern):
            WalletOwnershipConfig.from_env(env)


def test_get_wallet_ownership_config_prefers_state_and_lazily_falls_back(monkeypatch):
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "1" * 40)
    config = WalletOwnershipConfig(chain_id=31337, registry_address="0x" + "1" * 40)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(wallet_ownership_config=config)))
    assert get_wallet_ownership_config(request) is config

    # A bare app or a stale value falls back to the environment and caches once.
    state = SimpleNamespace(wallet_ownership_config="invalid")
    fallback = get_wallet_ownership_config(SimpleNamespace(app=SimpleNamespace(state=state)))
    assert fallback.chain_id == 31337
    assert state.wallet_ownership_config is fallback
    assert get_wallet_ownership_config(None).chain_id == 31337
    assert get_wallet_ownership_config(Request({"type": "http", "headers": []})).chain_id == 31337
    assert get_wallet_ownership_config(SimpleNamespace(app=SimpleNamespace())).chain_id == 31337

    monkeypatch.delenv("PILOT_CHAIN_ID")
    with pytest.raises(ValueError, match="PILOT_CHAIN_ID"):
        get_wallet_ownership_config(None)


def test_wallet_rpc_timeout_seconds_parsing_and_validation(monkeypatch):
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS", raising=False)
    assert wallet_rpc_timeout_seconds() == 10.0

    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS", "   ")
    assert wallet_rpc_timeout_seconds() == 10.0

    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS", "2.5")
    assert wallet_rpc_timeout_seconds() == 2.5

    for invalid in ("0", "-1", "nan", "inf", "-inf", "not-a-float"):
        with pytest.raises(ValueError):
            wallet_rpc_timeout_seconds({"WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS": invalid})


def test_build_and_get_wallet_web3_lazy_caching_and_timeout(monkeypatch):
    from web3 import AsyncHTTPProvider, AsyncWeb3

    # Unset URL returns None without constructing a client.
    assert build_wallet_web3({}) is None

    # Default web3 branch constructs a real AsyncWeb3 with AsyncHTTPProvider + explicit timeout.
    real_client = build_wallet_web3(
        {"WALLET_OWNERSHIP_RPC_URL": "http://127.0.0.1:8545", "WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS": "7.5"}
    )
    assert isinstance(real_client, AsyncWeb3)
    assert isinstance(real_client.provider, AsyncHTTPProvider)
    assert real_client.provider._request_kwargs == {"timeout": 7.5}

    # get_wallet_web3 with request=None or missing app falls back to build_wallet_web3().
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS", "4")
    sentinel = SimpleNamespace(provider=SimpleNamespace())
    calls = []

    def fake_build():
        calls.append(True)
        return sentinel

    monkeypatch.setattr("src.api.config.build_wallet_web3", fake_build)
    assert get_wallet_web3(None) is sentinel
    assert get_wallet_web3(Request({"type": "http", "headers": []})) is sentinel
    assert len(calls) == 2

    # Bare FastAPI app without lifespan lazily constructs once and caches on app.state.wallet_web3.
    app = FastAPI()
    req = Request({"type": "http", "app": app, "headers": []})
    first = get_wallet_web3(req)
    assert first is sentinel
    assert app.state.wallet_web3 is sentinel
    assert get_wallet_web3(req) is sentinel
    assert len(calls) == 3

    # Explicit None on app.state is respected without rebuilding.
    app.state.wallet_web3 = None
    assert get_wallet_web3(req) is None
    assert len(calls) == 3


async def test_close_wallet_web3_handles_none_non_disconnect_and_disconnect():
    from unittest.mock import AsyncMock

    await close_wallet_web3(None)
    await close_wallet_web3(SimpleNamespace(provider=SimpleNamespace()))

    disconnect = AsyncMock()
    await close_wallet_web3(SimpleNamespace(provider=SimpleNamespace(disconnect=disconnect)))
    disconnect.assert_awaited_once()


def test_legacy_api_enabled_parsing_and_profile_defaults():
    # Unset flag: enabled by default unless CLEARPROOF_PROFILE is pilot or production.
    assert legacy_api_enabled({}) is True
    assert legacy_api_enabled({"CLEARPROOF_ENABLE_LEGACY_API": "   "}) is True
    assert legacy_api_enabled({"CLEARPROOF_PROFILE": "development"}) is True
    assert legacy_api_enabled({"CLEARPROOF_PROFILE": "pilot"}) is False
    assert legacy_api_enabled({"CLEARPROOF_PROFILE": "PRODUCTION"}) is False

    # Explicit flag overrides profile default in both directions.
    for truthy in ("1", "true", "TRUE", "yes", "on"):
        assert legacy_api_enabled({"CLEARPROOF_PROFILE": "production", "CLEARPROOF_ENABLE_LEGACY_API": truthy}) is True
    for falsy in ("0", "false", "FALSE", "no", "off"):
        assert legacy_api_enabled({"CLEARPROOF_PROFILE": "development", "CLEARPROOF_ENABLE_LEGACY_API": falsy}) is False

    # Invalid flag fails closed.
    with pytest.raises(ValueError, match="CLEARPROOF_ENABLE_LEGACY_API"):
        legacy_api_enabled({"CLEARPROOF_ENABLE_LEGACY_API": "maybe"})


async def test_legacy_routers_gated_by_clearproof_enable_legacy_api(monkeypatch):
    from src.api.main import create_app

    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "legacy-gate-key")
    monkeypatch.delenv("CLEARPROOF_PROFILE", raising=False)

    # Flag=0 disables /proof/*, /credential/*, and /metrics while keeping /health and /pilot/*.
    monkeypatch.setenv("CLEARPROOF_ENABLE_LEGACY_API", "0")
    disabled_app = create_app()
    disabled_app.state.auth_config = AuthConfig(auth_mode="api-key", api_key="legacy-gate-key")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=disabled_app), base_url="http://test") as client:
        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/metrics", headers={"X-API-Key": "legacy-gate-key"})).status_code == 404
        assert (
            await client.post("/proof/generate", json={}, headers={"X-API-Key": "legacy-gate-key"})
        ).status_code == 404
        assert (
            await client.post("/proof/verify", json={}, headers={"X-API-Key": "legacy-gate-key"})
        ).status_code == 404
        assert (
            await client.post("/credential/issue", json={}, headers={"X-API-Key": "legacy-gate-key"})
        ).status_code == 404
        # Pilot proof jobs remain mounted even when legacy API is disabled.
        assert (await client.get("/pilot/proof/jobs/" + "a" * 64)).status_code == 401

    # Flag=1 mounts legacy routers (/metrics returns 200; /proof/* and /credential/* are reachable).
    monkeypatch.setenv("CLEARPROOF_ENABLE_LEGACY_API", "1")
    enabled_app = create_app()
    enabled_app.state.auth_config = AuthConfig(
        auth_mode="api-key",
        api_key="legacy-gate-key",
        api_key_tenant_id="tenant-a",
        api_key_actor_id="actor-a",
        api_key_roles=("credential:issue", "proof:generate"),
        api_key_issuer_dids=("did:web:issuer.example",),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=enabled_app), base_url="http://test") as client:
        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/metrics", headers={"X-API-Key": "legacy-gate-key"})).status_code == 200
        assert (
            await client.post("/proof/generate", json={}, headers={"X-API-Key": "legacy-gate-key"})
        ).status_code == 422
        assert (
            await client.post("/credential/issue", json={}, headers={"X-API-Key": "legacy-gate-key"})
        ).status_code == 422
