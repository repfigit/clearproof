"""Bounded ASGI upload handling without retaining or returning partial payloads."""

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import ClientDisconnect, Request

from src.api.request_body import read_private_body


def request_from_messages(messages):
    pending = iter(messages)

    async def receive():
        return next(pending)

    return Request({"type": "http", "method": "POST", "path": "/synthetic", "headers": []}, receive)


async def test_chunked_upload_accepts_exact_limit():
    request = request_from_messages(
        [
            {"type": "http.request", "body": b"syn", "more_body": True},
            {"type": "http.request", "body": b"", "more_body": True},
            {"type": "http.request", "body": b"thetic", "more_body": False},
        ]
    )
    assert await read_private_body(request, limit=9) == b"synthetic"


async def test_empty_upload_is_left_for_caller_validation():
    request = request_from_messages([{"type": "http.request", "body": b"", "more_body": False}])
    assert await read_private_body(request) == b""


async def test_oversized_upload_stops_without_reading_remaining_chunks():
    reads = 0

    async def receive():
        nonlocal reads
        reads += 1
        assert reads <= 2, "Oversized request must not be drained"
        return {"type": "http.request", "body": b"synthetic", "more_body": True}

    request = Request({"type": "http", "method": "POST", "path": "/synthetic", "headers": []}, receive)
    with pytest.raises(HTTPException) as error:
        await read_private_body(request, limit=10)
    assert error.value.status_code == 413
    assert error.value.detail == "Request exceeds the input limit"
    assert reads == 2


async def test_upload_deadline_cancels_pending_receive(monkeypatch):
    from src.api import request_body

    timeout = asyncio.timeout
    cancelled = asyncio.Event()

    def short_deadline(seconds):
        assert seconds == 10
        return timeout(0.01)

    async def receive():
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(request_body.asyncio, "timeout", short_deadline)
    request = Request({"type": "http", "method": "POST", "path": "/synthetic", "headers": []}, receive)
    with pytest.raises(HTTPException) as error:
        await read_private_body(request)
    assert error.value.status_code == 408
    assert error.value.detail == "Request upload timed out"
    assert cancelled.is_set()


async def test_disconnected_client_does_not_return_partial_body():
    request = request_from_messages(
        [
            {"type": "http.request", "body": b"synthetic-partial", "more_body": True},
            {"type": "http.disconnect"},
        ]
    )
    with pytest.raises(ClientDisconnect):
        await read_private_body(request)


async def test_caller_cancellation_is_not_reported_as_upload_timeout():
    receiving = asyncio.Event()
    cancelled = asyncio.Event()

    async def receive():
        receiving.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    request = Request({"type": "http", "method": "POST", "path": "/synthetic", "headers": []}, receive)
    task = asyncio.create_task(read_private_body(request))
    try:
        async with asyncio.timeout(2):
            await receiving.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert cancelled.is_set()
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
