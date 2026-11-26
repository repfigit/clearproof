"""Exercise the real app lifespan with a controlled database boundary."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def module(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "synthetic-api-key")
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "1" * 40)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from src.api import main

    return main


@pytest.mark.parametrize("key", ["", "short"])
async def test_invalid_key_blocks_startup(module, monkeypatch, key):
    monkeypatch.setenv("PII_MASTER_KEY", key)
    database = Mock()
    monkeypatch.setattr(module, "Database", database)
    with pytest.raises(RuntimeError, match="PII_MASTER_KEY"):
        async with module.lifespan(module.create_app()):
            pytest.fail("invalid key reached serving state")
    database.assert_not_called()


@pytest.mark.parametrize("key", ["a" * 64, "z" * 64, "é" * 16])
async def test_valid_keys_support_in_memory_lifecycle(module, monkeypatch, key, caplog):
    monkeypatch.setenv("PII_MASTER_KEY", key)
    app = module.create_app()
    async with module.lifespan(app):
        assert app.state.db is None
    assert key not in caplog.text


@pytest.mark.parametrize("salt", [None, "", "  "])
async def test_missing_salt_blocks_startup_before_database_connection(module, monkeypatch, salt):
    if salt is None:
        monkeypatch.delenv("HKDF_SALT", raising=False)
    else:
        monkeypatch.setenv("HKDF_SALT", salt)
    monkeypatch.delenv("ALLOW_INSECURE_HKDF_SALT", raising=False)
    monkeypatch.setenv("DATABASE_URL", "configured")
    factory = Mock()
    monkeypatch.setattr(module, "Database", factory)
    with pytest.raises(RuntimeError, match="HKDF_SALT is required"):
        async with module.lifespan(module.create_app()):
            pytest.fail("missing salt reached serving state")
    factory.assert_not_called()


async def test_explicit_local_demo_opt_in_allows_startup_without_salt(module, monkeypatch):
    monkeypatch.delenv("HKDF_SALT", raising=False)
    monkeypatch.setenv("ALLOW_INSECURE_HKDF_SALT", "1")
    app = module.create_app()
    async with module.lifespan(app):
        assert app.state.db is None


@pytest.mark.parametrize("failure", ["none", "serving", "connecting"])
async def test_database_closed_on_every_lifecycle_exit(module, monkeypatch, failure):
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setenv("DB_POOL_MIN", "1")
    monkeypatch.setenv("DB_POOL_MAX", "3")
    database = SimpleNamespace(connect=AsyncMock(), close=AsyncMock())
    factory = Mock(return_value=database)
    monkeypatch.setattr(module, "Database", factory)
    if failure == "connecting":
        database.connect.side_effect = RuntimeError("connection failed")
    app = module.create_app()

    async def run():
        async with module.lifespan(app):
            assert app.state.db is database
            if failure == "serving":
                raise RuntimeError("serving failed")

    if failure == "none":
        await run()
    else:
        with pytest.raises(RuntimeError, match="failed"):
            await run()
    factory.assert_called_once_with(pool_min=1, pool_max=3)
    database.close.assert_awaited_once()
    assert app.state.db is None


@pytest.mark.parametrize(
    "origins,allowed",
    [
        ("*", "http://localhost:3000"),
        ("*,https://operator.example", "https://operator.example"),
        ("https://operator.example", "https://operator.example"),
    ],
)
async def test_cors_credentials_require_explicit_origin(module, monkeypatch, origins, allowed):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", origins)
    app = module.create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://local") as client:
        for origin, status in [(allowed, 200), ("https://untrusted.example", 400)]:
            response = await client.options(
                "/health",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization",
                },
            )
            assert response.status_code == status
            assert response.headers.get("access-control-allow-origin") == (allowed if status == 200 else None)


async def test_cancelled_lifespan_closes_database(module, monkeypatch):
    import asyncio

    monkeypatch.setenv("DATABASE_URL", "configured")
    database = SimpleNamespace(connect=AsyncMock(), close=AsyncMock())
    monkeypatch.setattr(module, "Database", Mock(return_value=database))
    app = module.create_app()
    entered = asyncio.Event()

    async def serve():
        async with module.lifespan(app):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(serve())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    database.close.assert_awaited_once()
    assert app.state.db is None


@pytest.mark.parametrize("failure", [False, True])
async def test_operator_proving_factory_loads_before_serving_and_closes_on_failure(module, monkeypatch, failure):
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setenv("PILOT_PROVING_FACTORY", "synthetic_operator:configure")
    database = SimpleNamespace(connect=AsyncMock(), close=AsyncMock())
    monkeypatch.setattr(module, "Database", Mock(return_value=database))
    targets = {("synthetic-tenant", "synthetic-target"): object()}
    loader = AsyncMock(return_value=targets)
    if failure:
        loader.side_effect = RuntimeError("Operator proving configuration could not be loaded")
    monkeypatch.setattr(module, "load_proving_targets", loader)
    app = module.create_app()

    async def serve():
        async with module.lifespan(app):
            assert app.state.db is database and app.state.pilot_proving_targets is targets

    if failure:
        with pytest.raises(RuntimeError, match="could not be loaded"):
            await serve()
    else:
        await serve()
    loader.assert_awaited_once()
    assert loader.call_args.args[0] is database
    database.close.assert_awaited_once()
    assert app.state.db is None


@pytest.mark.parametrize(
    "variable,loader_name,attribute",
    [
        ("PILOT_INSPECTION_FACTORY", "load_inspection_targets", "pilot_inspection_targets"),
        ("PILOT_AUTHORIZATION_FACTORY", "load_authorization_targets", "pilot_authorization_targets"),
    ],
)
@pytest.mark.parametrize("failure", [False, True])
async def test_operator_target_factories_load_before_serving_and_close_on_failure(
    module, monkeypatch, variable, loader_name, attribute, failure
):
    monkeypatch.setenv("DATABASE_URL", "configured")
    for name in ("PILOT_PROVING_FACTORY", "PILOT_INSPECTION_FACTORY", "PILOT_AUTHORIZATION_FACTORY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(variable, "synthetic_operator:configure")
    database = SimpleNamespace(connect=AsyncMock(), close=AsyncMock())
    monkeypatch.setattr(module, "Database", Mock(return_value=database))
    targets = {("synthetic-tenant", "synthetic-target"): object()}
    loader = AsyncMock(return_value=targets)
    if failure:
        loader.side_effect = RuntimeError("Operator configuration could not be loaded")
    monkeypatch.setattr(module, loader_name, loader)
    other = "load_authorization_targets" if loader_name == "load_inspection_targets" else "load_inspection_targets"
    unused = AsyncMock(side_effect=AssertionError("An unset factory must not be loaded"))
    monkeypatch.setattr(module, other, unused)
    app = module.create_app()

    async def serve():
        async with module.lifespan(app):
            assert app.state.db is database and getattr(app.state, attribute) is targets

    if failure:
        with pytest.raises(RuntimeError, match="could not be loaded"):
            await serve()
    else:
        await serve()
    loader.assert_awaited_once()
    assert loader.call_args.args[0] is database
    unused.assert_not_awaited()
    database.close.assert_awaited_once()


async def test_lifespan_populates_shared_cipher_and_runtime_configs_and_clears_on_shutdown(module, monkeypatch):
    import json

    from src.api.config import AuthConfig, EventConfig, FireblocksConfig, WalletOwnershipConfig
    from src.storage.pilot_cipher import RecordCipher

    monkeypatch.setenv("AUTH_MODE", "jwt")
    monkeypatch.setenv("JWT_ISSUER", "custom-issuer")
    monkeypatch.setenv("JWT_AUDIENCE", "custom-audience")
    monkeypatch.setenv("SIWE_DOMAIN", "custom.example")
    monkeypatch.setenv("PILOT_EVENT_AUTHORITIES", json.dumps({"authorities": []}))
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setenv("PILOT_PROVING_FACTORY", "synthetic_operator:proving")
    monkeypatch.setenv("PILOT_INSPECTION_FACTORY", "synthetic_operator:inspection")
    monkeypatch.setenv("PILOT_AUTHORIZATION_FACTORY", "synthetic_operator:authorization")

    database = SimpleNamespace(connect=AsyncMock(), close=AsyncMock())
    monkeypatch.setattr(module, "Database", Mock(return_value=database))
    proving_loader = AsyncMock(return_value={})
    inspection_loader = AsyncMock(return_value={})
    authorization_loader = AsyncMock(return_value={})
    monkeypatch.setattr(module, "load_proving_targets", proving_loader)
    monkeypatch.setattr(module, "load_inspection_targets", inspection_loader)
    monkeypatch.setattr(module, "load_authorization_targets", authorization_loader)

    app = module.create_app()
    async with module.lifespan(app):
        assert isinstance(app.state.record_cipher, RecordCipher)
        # All three operator target loaders receive the same lifespan-constructed RecordCipher.
        assert proving_loader.call_args.args[1] is app.state.record_cipher
        assert inspection_loader.call_args.args[1] is app.state.record_cipher
        assert authorization_loader.call_args.args[1] is app.state.record_cipher
        assert isinstance(app.state.auth_config, AuthConfig)
        assert app.state.auth_config.auth_mode == "jwt"
        assert app.state.auth_config.jwt_issuer == "custom-issuer"
        assert app.state.auth_config.jwt_audience == "custom-audience"
        assert app.state.auth_config.siwe_domain == "custom.example"
        assert app.state.siwe_auth.domain == "custom.example"
        assert isinstance(app.state.event_config, EventConfig)
        assert app.state.event_config.authorities == ()
        assert app.state.event_config.links == ()
        assert app.state.fireblocks_config is None
        assert isinstance(app.state.wallet_ownership_config, WalletOwnershipConfig)
        assert app.state.wallet_ownership_config.chain_id == 31337

    assert app.state.record_cipher is None
    assert app.state.auth_config is None
    assert app.state.siwe_auth is None
    assert app.state.event_config is None
    assert app.state.fireblocks_config is None
    assert app.state.wallet_ownership_config is None
    assert isinstance(FireblocksConfig(), FireblocksConfig)


@pytest.mark.parametrize(
    "variable,value,pattern",
    [
        ("PILOT_EVENT_AUTHORITIES", "{invalid", "Invalid pilot event configuration"),
        ("PILOT_INVESTIGATION_LINKS", '{"links":[{"url":"javascript:bad"}]}', "Invalid pilot event configuration"),
        ("PILOT_FIREBLOCKS_INTEGRATIONS", "{invalid", "Invalid Fireblocks relay configuration"),
    ],
)
async def test_invalid_event_or_fireblocks_config_blocks_startup_before_db(
    module, monkeypatch, variable, value, pattern
):
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setenv(variable, value)
    database = Mock()
    monkeypatch.setattr(module, "Database", database)
    with pytest.raises(RuntimeError, match=pattern):
        async with module.lifespan(module.create_app()):
            pytest.fail("invalid event/fireblocks config reached serving state")
    database.assert_not_called()


async def test_auth_dependency_reads_app_state_auth_config_over_module_globals(module, monkeypatch):
    from fastapi import Depends

    from src.api.config import AuthConfig
    from src.api.middleware import auth as auth_middleware

    # Set conflicting module-level globals to prove app.state.auth_config wins.
    monkeypatch.setattr(auth_middleware, "AUTH_MODE", "jwt")
    monkeypatch.setattr(auth_middleware, "API_KEY", "stale-module-key")
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "lifespan-api-key")
    monkeypatch.delenv("PILOT_EVENT_AUTHORITIES", raising=False)
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)

    app = module.create_app()

    @app.get("/_lifespan_auth_probe")
    async def probe(claims: dict = Depends(auth_middleware.JWTAuthDependency)):
        return claims

    async with module.lifespan(app):
        assert isinstance(app.state.auth_config, AuthConfig)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://local") as client:
            ok = await client.get("/_lifespan_auth_probe", headers={"X-API-Key": "lifespan-api-key"})
            assert ok.status_code == 200
            bad = await client.get("/_lifespan_auth_probe", headers={"X-API-Key": "stale-module-key"})
            assert bad.status_code == 401


def test_lazy_config_accessors_construct_and_cache_on_bare_app_state(monkeypatch):
    import json

    from fastapi import FastAPI
    from starlette.requests import Request

    from src.api.config import (
        EventConfig,
        FireblocksConfig,
        get_auth_config,
        get_event_config,
        get_fireblocks_config,
        get_siwe_auth,
    )

    monkeypatch.setenv("PILOT_EVENT_AUTHORITIES", json.dumps({"authorities": []}))
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)
    monkeypatch.setenv("SIWE_DOMAIN", "bare.example")

    app = FastAPI()
    req = Request({"type": "http", "app": app, "headers": []})

    # Bare app.state without lifespan lazily constructs and caches event/Fireblocks/SIWE config.
    ev1 = get_event_config(req)
    assert isinstance(ev1, EventConfig) and ev1.authorities == ()
    assert app.state.event_config is ev1
    monkeypatch.delenv("PILOT_EVENT_AUTHORITIES", raising=False)
    assert get_event_config(req) is ev1

    fb1 = get_fireblocks_config(req)
    assert fb1 is None
    assert app.state.fireblocks_config is None
    assert get_fireblocks_config(req) is None
    # Explicit override on app.state is respected without AttributeError.
    custom_fb = FireblocksConfig()
    app.state.fireblocks_config = custom_fb
    assert get_fireblocks_config(req) is custom_fb

    siwe1 = get_siwe_auth(req)
    assert siwe1.domain == "bare.example"
    assert app.state.siwe_auth is siwe1
    assert get_siwe_auth(req) is siwe1

    auth_cfg = get_auth_config(req)
    assert auth_cfg.siwe_domain == "bare.example"


@pytest.mark.parametrize("failure", ["none", "serving", "connecting"])
async def test_lifespan_constructs_and_disconnects_wallet_web3_on_every_exit(module, monkeypatch, failure):
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS", "5")
    monkeypatch.delenv("PILOT_EVENT_AUTHORITIES", raising=False)
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)

    disconnect = AsyncMock()
    managed_w3 = SimpleNamespace(provider=SimpleNamespace(disconnect=disconnect))
    builder = Mock(return_value=managed_w3)
    monkeypatch.setattr(module, "build_wallet_web3", builder)

    if failure == "connecting":
        monkeypatch.setenv("DATABASE_URL", "configured")
        database = SimpleNamespace(connect=AsyncMock(side_effect=RuntimeError("db connect failed")), close=AsyncMock())
        monkeypatch.setattr(module, "Database", Mock(return_value=database))
    else:
        monkeypatch.delenv("DATABASE_URL", raising=False)

    app = module.create_app()

    async def run():
        async with module.lifespan(app):
            assert app.state.wallet_web3 is managed_w3
            if failure == "serving":
                raise RuntimeError("serving failed")

    if failure == "none":
        await run()
    else:
        with pytest.raises(RuntimeError, match="failed"):
            await run()

    builder.assert_called_once_with()
    disconnect.assert_awaited_once()
    assert app.state.wallet_web3 is None


async def test_invalid_wallet_chain_id_blocks_startup_before_db(module, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setenv("PILOT_CHAIN_ID", "synthetic-invalid-chain")
    database = Mock()
    monkeypatch.setattr(module, "Database", database)
    with pytest.raises(RuntimeError, match="Invalid wallet ownership configuration"):
        async with module.lifespan(module.create_app()):
            pytest.fail("invalid wallet chain ID reached serving state")
    database.assert_not_called()


async def test_invalid_wallet_rpc_timeout_blocks_startup_before_db(module, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS", "0")
    monkeypatch.delenv("PILOT_EVENT_AUTHORITIES", raising=False)
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)
    database = Mock()
    monkeypatch.setattr(module, "Database", database)
    with pytest.raises(RuntimeError, match="Invalid wallet ownership RPC configuration"):
        async with module.lifespan(module.create_app()):
            pytest.fail("invalid wallet RPC timeout reached serving state")
    database.assert_not_called()


async def test_invalid_siwe_max_sessions_blocks_startup_before_db(module, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "configured")
    monkeypatch.setenv("SIWE_MAX_SESSIONS", "0")
    monkeypatch.delenv("PILOT_EVENT_AUTHORITIES", raising=False)
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_URL", raising=False)
    database = Mock()
    monkeypatch.setattr(module, "Database", database)
    with pytest.raises(RuntimeError, match="Invalid SIWE session configuration"):
        async with module.lifespan(module.create_app()):
            pytest.fail("invalid SIWE_MAX_SESSIONS reached serving state")
    database.assert_not_called()


async def test_lifespan_shares_single_siwe_auth_across_routes_and_middleware(module, monkeypatch):
    from fastapi import Depends

    from src.api.config import get_siwe_auth
    from src.api.middleware import auth as auth_middleware
    from src.auth import siwe_auth
    from tests.unit.test_siwe_auth import signed

    monkeypatch.setattr(siwe_auth, "_nonce_store", {})
    monkeypatch.setenv("AUTH_MODE", "siwe")
    monkeypatch.setenv("SIWE_DOMAIN", "wallet.example")
    monkeypatch.setenv("SIWE_MAX_SESSIONS", "4")
    monkeypatch.delenv("PILOT_EVENT_AUTHORITIES", raising=False)
    monkeypatch.delenv("PILOT_INVESTIGATION_LINKS", raising=False)
    monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS", raising=False)
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_URL", raising=False)

    app = module.create_app()

    @app.get("/_siwe_identity_probe")
    async def probe(claims: dict = Depends(auth_middleware.JWTAuthDependency)):
        return claims

    async with module.lifespan(app):
        lifespan_siwe = app.state.siwe_auth
        assert lifespan_siwe._sessions.max_entries == 4
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://local") as client:
            nonce = (await client.get("/auth/nonce")).json()["nonce"]
            message, signature, address = signed(nonce, domain="wallet.example")
            verify_resp = await client.post("/auth/verify", json={"message": message, "signature": signature})
            assert verify_resp.status_code == 200
            token = verify_resp.json()["session_token"]
            assert app.state.siwe_auth is lifespan_siwe
            assert lifespan_siwe.session_count() == 1
            protected = await client.get("/_siwe_identity_probe", headers={"Authorization": f"Bearer {token}"})
            assert protected.status_code == 200
            assert protected.json()["sub"] == address
            assert get_siwe_auth(SimpleNamespace(app=app)) is lifespan_siwe
