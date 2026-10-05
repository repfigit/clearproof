"""Rate limiter identity, key hygiene and bounded memory."""

import hashlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.api.middleware import auth, rate_limit
from src.api.middleware.rate_limit import PrincipalRateLimiter, RateLimiter

VALID_KEY = "synthetic-valid-api-key"


@pytest.fixture(autouse=True)
def api_key_mode(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", "api-key")
    monkeypatch.setattr(auth, "API_KEY", VALID_KEY)


def make_request(key=None, host="192.0.2.10"):
    headers = {} if key is None else {"X-API-Key": key}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=host) if host else None)


async def test_random_invalid_keys_share_the_ip_bucket():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    await limiter(make_request("random-1"))
    await limiter(make_request("random-2"))
    with pytest.raises(HTTPException) as error:
        await limiter(make_request("random-3"))
    assert error.value.status_code == 429
    assert error.value.headers["Retry-After"]


async def test_valid_key_is_hashed_with_client_ip_and_never_stored_raw():
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    await limiter(make_request(VALID_KEY, host="192.0.2.10"))
    await limiter(make_request(VALID_KEY, host="192.0.2.11"))
    assert len(limiter._requests) == 2
    for client_key in limiter._requests:
        assert VALID_KEY not in client_key
        assert client_key.startswith("key:")
    expected = hashlib.sha256(f"{VALID_KEY}\x00192.0.2.10".encode()).hexdigest()
    assert f"key:{expected}" in limiter._requests


@pytest.mark.parametrize("mode", ["jwt", "siwe"])
async def test_api_key_header_is_ignored_outside_api_key_mode(monkeypatch, mode):
    monkeypatch.setattr(auth, "AUTH_MODE", mode)
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    await limiter(make_request(VALID_KEY))
    with pytest.raises(HTTPException):
        await limiter(make_request("anything-else"))
    assert list(limiter._requests) == ["ip:192.0.2.10"]


async def test_missing_client_and_unconfigured_key_fall_back_to_ip(monkeypatch):
    monkeypatch.setattr(auth, "API_KEY", "")
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    await limiter(make_request("", host=None))
    await limiter(make_request("any", host=None))
    assert list(limiter._requests) == ["ip:unknown"]


async def test_principal_limiter_keys_on_hashed_principal():
    limiter = PrincipalRateLimiter(max_requests=1, window_seconds=60)
    await limiter(make_request("random-1", host="192.0.2.10"), claims={"sub": "tenant-a"})
    # Same principal from another address and header still shares the bucket.
    with pytest.raises(HTTPException):
        await limiter(make_request("random-2", host="198.51.100.1"), claims={"sub": "tenant-a"})
    # A different principal is independent.
    await limiter(make_request(host="192.0.2.10"), claims={"sub": "tenant-b"})
    assert all(key.startswith("principal:") and "tenant" not in key for key in limiter._requests)


@pytest.mark.parametrize("claims", [None, {}, {"sub": ""}, {"sub": 7}])
async def test_principal_limiter_without_subject_uses_request_identity(claims):
    limiter = PrincipalRateLimiter(max_requests=5, window_seconds=60)
    await limiter(make_request("random"), claims=claims)
    assert list(limiter._requests) == ["ip:192.0.2.10"]


async def test_expired_windows_are_evicted(monkeypatch):
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock.now)
    limiter = RateLimiter(max_requests=1, window_seconds=10)
    for index in range(50):
        await limiter(make_request(host=f"192.0.2.{index}"))
    assert len(limiter._requests) == 50
    clock.now += 11
    await limiter(make_request(host="203.0.113.1"))
    # Idle clients are swept once a full window has passed; only the live one remains.
    assert list(limiter._requests) == ["ip:203.0.113.1"]
    clock.now += 5
    await limiter(make_request(host="203.0.113.2"))
    # No sweep inside the window: both live clients remain.
    assert len(limiter._requests) == 2


async def test_window_slides_and_empty_current_bucket_is_reused(monkeypatch):
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock.now)
    limiter = RateLimiter(max_requests=1, window_seconds=10)
    await limiter(make_request())
    with pytest.raises(HTTPException) as error:
        await limiter(make_request())
    assert error.value.headers["Retry-After"] == "11"
    clock.now += 10.5
    await limiter(make_request())
    assert len(limiter._requests["ip:192.0.2.10"]) == 1


async def test_active_client_keeps_only_requests_inside_the_window(monkeypatch):
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock.now)
    limiter = RateLimiter(max_requests=2, window_seconds=10)
    await limiter(make_request())
    clock.now = 1006.0
    await limiter(make_request())
    clock.now = 1011.0
    # The 1000 request has expired, the 1006 one has not: one slot is free again.
    await limiter(make_request())
    assert list(limiter._requests["ip:192.0.2.10"]) == [1006.0, 1011.0]
    with pytest.raises(HTTPException):
        await limiter(make_request())
