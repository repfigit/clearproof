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
