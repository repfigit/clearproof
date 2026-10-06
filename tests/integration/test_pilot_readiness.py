# SPDX-License-Identifier: Apache-2.0
"""Real PostgreSQL probe: no retained rows, nullifiers or migrations are written."""

import os
from unittest.mock import AsyncMock

import pytest

from src.storage.database import SCHEMA_VERSION
from tests.integration.test_pilot_storage import db as db  # noqa: F401
from tests.unit.test_pilot_current import current_case as current_case  # noqa: F401
from tests.unit.test_readiness_api import api as api  # noqa: F401

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")


async def snapshot(database):
    async with database.connection() as conn:
        rows = await conn.execute("SELECT version, applied_at FROM schema_migrations ORDER BY version")
        versions = await rows.fetchall()
        rows = await conn.execute("SELECT count(*) FROM pilot_records")
        records = await rows.fetchone()
        rows = await conn.execute("SELECT count(*) FROM pilot_consumptions")
        nullifiers = await rows.fetchone()
        return versions, records, nullifiers


async def test_real_database_preflight_is_readonly_and_does_not_migrate(api, db, monkeypatch):
    api.app.state.db = db
    before = await snapshot(db)
    migrate = AsyncMock(side_effect=AssertionError("Readiness must never migrate"))
    monkeypatch.setattr(db, "_migrate", migrate)
    for capability in ("inspection", "proving"):
        response = await api.client.get(f"/pilot/readiness/{capability}/target-a")
        assert response.status_code == 200
        assert response.json()["checks"]["database"] is response.json()["checks"]["migration_history"] is True
        assert response.json()["authorization_consumed"] is False
    assert await snapshot(db) == before
    migrate.assert_not_called()


async def test_real_schema_drift_fails_without_repair_and_connection_remains_usable(api, db):
    api.app.state.db = db
    async with db.connection() as conn:
        await conn.execute("DELETE FROM schema_migrations WHERE version = %s", (SCHEMA_VERSION,))
    before = await snapshot(db)
    response = await api.client.get("/pilot/readiness/inspection/target-a")
    assert response.status_code == 503
    assert response.json()["checks"]["database"] is True
    assert response.json()["checks"]["migration_history"] is False
    assert await snapshot(db) == before


async def test_real_closed_pool_does_not_change_public_liveness(api, db):
    from src.api.routes.health import router as health

    api.app.include_router(health)
    api.app.state.db = db
    await db.close()
    assert (await api.client.get("/pilot/readiness/inspection/target-a")).status_code == 503
    assert (await api.client.get("/health")).status_code == 200
