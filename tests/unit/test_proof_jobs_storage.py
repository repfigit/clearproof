"""Proof job queue storage helpers without PostgreSQL."""

from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest

from src.storage.proof_jobs import ProofJobQueue


@pytest.mark.asyncio
async def test_proof_job_queue_transaction_yields_cursor():
    cursor = object()

    class CursorContext:
        async def __aenter__(self):
            return cursor

        async def __aexit__(self, *_args):
            return False

    class TransactionContext:
        async def __aenter__(self):
            return None

        async def __aexit__(self, *_args):
            return False

    conn = MagicMock()
    conn.transaction = MagicMock(return_value=TransactionContext())
    conn.cursor = MagicMock(return_value=CursorContext())

    @asynccontextmanager
    async def connection():
        yield conn

    db = MagicMock()
    db.connection = connection
    queue = ProofJobQueue(db, MagicMock())

    async with queue._transaction() as cur:
        assert cur is cursor
