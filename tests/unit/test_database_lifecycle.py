"""Disconnected database operations fail before any connection-pool work."""

from unittest.mock import Mock

import pytest

from src.storage import database as database_module
from src.storage.database import Database


@pytest.mark.parametrize("configured", [None, ""])
async def test_missing_database_url_does_not_allocate_pool(monkeypatch, configured):
    if configured is None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("DATABASE_URL", configured)
    factory = Mock()
    monkeypatch.setattr(database_module, "AsyncConnectionPool", factory)
    database = Database()
    with pytest.raises(RuntimeError, match="DATABASE_URL environment variable is required"):
        await database.connect()
    assert not database.is_ready
    factory.assert_not_called()
    await database.close()
    assert not database.is_ready


@pytest.mark.parametrize("operation", ["connection", "transaction"])
async def test_disconnected_database_rejects_context_entry(operation):
    database = Database()
    for _ in range(2):
        with pytest.raises(RuntimeError, match="Database not connected"):
            async with getattr(database, operation)():
                pytest.fail("Disconnected context must never yield")
        await database.close()
        assert not database.is_ready
