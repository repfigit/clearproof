"""Bounded private JSON upload transport; callers authenticate before reading."""

import asyncio

from fastapi import HTTPException, Request


async def read_private_body(request: Request, *, limit: int = 1024 * 1024) -> bytes:
    body = bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(body) + len(chunk) > limit:
                    raise HTTPException(status_code=413, detail="Request exceeds the input limit")
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(status_code=408, detail="Request upload timed out") from None
    return bytes(body)
