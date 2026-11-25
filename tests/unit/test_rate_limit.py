"""Rate limiter identity, proxy trust, config overrides, bounded memory, and route wiring."""

import hashlib
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from src.api.main import create_app
from src.api.middleware import auth, rate_limit
from src.api.middleware.rate_limit import (
    PrincipalRateLimiter,
    RateLimiter,
    parse_trusted_proxies,
    trusted_client_ip,
)
from src.auth.principal import Principal, TenantPrincipalDependency

VALID_KEY = "synthetic-valid-api-key"


@pytest.fixture(autouse=True)
def api_key_mode(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", "api-key")
    monkeypatch.setattr(auth, "API_KEY", VALID_KEY)
    monkeypatch.delenv("RATE_LIMIT_TRUSTED_PROXIES", raising=False)
    monkeypatch.setattr(rate_limit, "_TRUSTED_PROXIES_CACHE", ("", ()))


def make_request(key=None, host="192.0.2.10", xff=None):
    headers = {}
    if key is not None:
        headers["X-API-Key"] = key
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=host) if host else None)


async def test_random_invalid_keys_share_the_ip_bucket():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    await limiter(make_request("random-1"))
    await limiter(make_request("random-2"))
    with pytest.raises(HTTPException) as error:
        await limiter(make_request("random-3"))
    assert error.value.status_code == 429
    assert error.value.detail == "Rate limit exceeded"
    assert int(error.value.headers["Retry-After"]) >= 1


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
    assert error.value.status_code == 429
    assert error.value.detail == "Rate limit exceeded"
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


# ---------------------------------------------------------------------------
# Trusted proxy / spoofed X-Forwarded-For protection
# ---------------------------------------------------------------------------


async def test_spoofed_x_forwarded_for_ignored_when_no_trusted_proxies():
    """Without RATE_LIMIT_TRUSTED_PROXIES, spoofed X-Forwarded-For cannot bypass limits."""
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    await limiter(make_request(host="198.51.100.5", xff="203.0.113.1"))
    await limiter(make_request(host="198.51.100.5", xff="203.0.113.2"))
    with pytest.raises(HTTPException) as error:
        await limiter(make_request(host="198.51.100.5", xff="203.0.113.3"))
    assert error.value.status_code == 429
    assert list(limiter._requests) == ["ip:198.51.100.5"]


async def test_spoofed_x_forwarded_for_ignored_from_untrusted_peer(monkeypatch):
    """Direct attacker connecting from an untrusted peer IP cannot spoof X-Forwarded-For."""
    monkeypatch.setenv("RATE_LIMIT_TRUSTED_PROXIES", "10.0.0.0/8, 127.0.0.1/32")
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    await limiter(make_request(host="198.51.100.9", xff="203.0.113.1"))
    with pytest.raises(HTTPException) as error:
        await limiter(make_request(host="198.51.100.9", xff="203.0.113.2"))
    assert error.value.status_code == 429
    assert list(limiter._requests) == ["ip:198.51.100.9"]


async def test_spoofed_left_xff_entry_defeated_behind_trusted_proxy(monkeypatch):
    """Behind a trusted proxy, right-to-left parsing picks the rightmost untrusted IP."""
    monkeypatch.setenv("RATE_LIMIT_TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.0/12")
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    # Attacker prepends varying spoofed IPs on the left; real client 198.51.100.77 is
    # appended by the edge proxy, followed by an internal proxy hop 172.16.0.5.
    await limiter(make_request(host="10.0.0.2", xff="1.1.1.1, 198.51.100.77, 172.16.0.5"))
    await limiter(make_request(host="10.0.0.2", xff="2.2.2.2, 198.51.100.77, 172.16.0.5"))
    with pytest.raises(HTTPException) as error:
        await limiter(make_request(host="10.0.0.2", xff="3.3.3.3, 198.51.100.77, 172.16.0.5"))
    assert error.value.status_code == 429
    assert list(limiter._requests) == ["ip:198.51.100.77"]
    # Different real client behind the same trusted proxy gets its own bucket.
    await limiter(make_request(host="10.0.0.2", xff="198.51.100.88, 172.16.0.5"))
    assert "ip:198.51.100.88" in limiter._requests


def test_trusted_client_ip_edge_cases(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_TRUSTED_PROXIES", "10.0.0.0/8, , 127.0.0.1")
    # Cached repeat call hits cache cleanly.
    proxies = parse_trusted_proxies()
    assert len(proxies) == 2
    assert parse_trusted_proxies() == proxies
    # Non-IP peer host (e.g. "testclient") is returned verbatim.
    assert trusted_client_ip(make_request(host="testclient", xff="203.0.113.1")) == "testclient"
    # Trusted proxy with no X-Forwarded-For falls back to peer IP.
    assert trusted_client_ip(make_request(host="10.1.2.3")) == "10.1.2.3"
    # Trusted proxy with malformed X-Forwarded-For fails closed to peer IP.
    assert trusted_client_ip(make_request(host="10.1.2.3", xff="not-an-ip")) == "10.1.2.3"
    assert trusted_client_ip(make_request(host="10.1.2.3", xff="203.0.113.1, ")) == "10.1.2.3"
    # Trusted proxy where every XFF entry is also trusted falls back to peer IP.
    assert trusted_client_ip(make_request(host="10.1.2.3", xff="127.0.0.1, 10.9.9.9")) == "10.1.2.3"
    # Explicit trusted_proxies argument bypasses env cache.
    explicit = parse_trusted_proxies("10.0.0.0/8")
    assert (
        trusted_client_ip(make_request(host="10.1.2.3", xff="203.0.113.9"), trusted_proxies=explicit) == "203.0.113.9"
    )
    # Invalid CIDR in RATE_LIMIT_TRUSTED_PROXIES fails closed with ValueError.
    with pytest.raises(ValueError):
        parse_trusted_proxies("not-a-cidr")


# ---------------------------------------------------------------------------
# Bounded in-memory store & configuration validation
# ---------------------------------------------------------------------------


async def test_in_memory_store_is_lru_bounded_and_evicts_expired_first(monkeypatch):
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock.now)
    limiter = RateLimiter(max_requests=2, window_seconds=10, max_clients=3)
    await limiter(make_request(host="192.0.2.1"))
    clock.now = 1001.0
    await limiter(make_request(host="192.0.2.2"))
    clock.now = 1002.0
    await limiter(make_request(host="192.0.2.3"))
    # Touch .1 so .2 becomes least recently used.
    clock.now = 1003.0
    await limiter(make_request(host="192.0.2.1"))
    # Adding a 4th live client evicts LRU (.2), keeping cardinality capped at max_clients=3.
    clock.now = 1004.0
    await limiter(make_request(host="192.0.2.4"))
    assert len(limiter._requests) == 3
    assert "ip:192.0.2.2" not in limiter._requests
    assert set(limiter._requests) == {"ip:192.0.2.1", "ip:192.0.2.3", "ip:192.0.2.4"}

    # Advance past expiry of .1/.3/.4 while avoiding the periodic sweep (reset _last_sweep).
    clock.now = 1020.0
    limiter._last_sweep = clock.now
    await limiter(make_request(host="192.0.2.5"))
    # _evict drops expired buckets first instead of keeping dead entries.
    assert list(limiter._requests) == ["ip:192.0.2.5"]


async def test_config_driven_env_overrides_and_validation(monkeypatch):
    with pytest.raises(ValueError):
        RateLimiter(max_requests=0)
    with pytest.raises(ValueError):
        RateLimiter(window_seconds=0)
    with pytest.raises(ValueError):
        RateLimiter(max_clients=0)

    limiter = RateLimiter(max_requests=10, window_seconds=60, env_prefix="RATE_LIMIT_TEST_TIER", max_clients=100)
    monkeypatch.setenv("RATE_LIMIT_TEST_TIER_MAX_REQUESTS", "2")
    monkeypatch.setenv("RATE_LIMIT_TEST_TIER_WINDOW_SECONDS", "5")
    monkeypatch.setenv("RATE_LIMIT_MAX_CLIENTS", "2")

    clock = SimpleNamespace(now=500.0)
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock.now)

    await limiter(make_request(host="198.51.100.1"))
    await limiter(make_request(host="198.51.100.1"))
    with pytest.raises(HTTPException) as err:
        await limiter(make_request(host="198.51.100.1"))
    assert err.value.status_code == 429
    assert int(err.value.headers["Retry-After"]) == 6

    # Window resets after 5 seconds (env override, not default 60s).
    clock.now = 505.5
    await limiter(make_request(host="198.51.100.1"))

    # Blank env values fall back to defaults.
    monkeypatch.setenv("RATE_LIMIT_TEST_TIER_MAX_REQUESTS", "   ")
    monkeypatch.setenv("RATE_LIMIT_TEST_TIER_WINDOW_SECONDS", "")
    monkeypatch.setenv("RATE_LIMIT_MAX_CLIENTS", "")
    assert limiter._effective_limits() == (10, 60, 100)

    # Invalid env overrides fail closed with ValueError.
    for bad in ("0", "-5", "abc"):
        monkeypatch.setenv("RATE_LIMIT_TEST_TIER_MAX_REQUESTS", bad)
        with pytest.raises(ValueError):
            await limiter(make_request(host="198.51.100.2"))
    monkeypatch.delenv("RATE_LIMIT_TEST_TIER_MAX_REQUESTS")

    for bad in ("0", "-1.5", "not-a-float"):
        monkeypatch.setenv("RATE_LIMIT_TEST_TIER_WINDOW_SECONDS", bad)
        with pytest.raises(ValueError):
            await limiter(make_request(host="198.51.100.2"))


# ---------------------------------------------------------------------------
# End-to-end HTTP route coverage: /auth/verify, all /pilot/*, /wallet/ownership/*
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,body,env_prefix",
    [
        ("POST", "/auth/verify", {"message": "invalid", "signature": "0x00"}, "RATE_LIMIT_AUTH_VERIFY"),
        ("POST", "/pilot/proof/inspect", {}, "RATE_LIMIT_PILOT_PROOF"),
        ("POST", "/pilot/proof/evaluate", {}, "RATE_LIMIT_PILOT_PROOF"),
        ("POST", "/pilot/proof/observe", {}, "RATE_LIMIT_PILOT_PROOF"),
        ("POST", "/pilot/proof/observations/read", {}, "RATE_LIMIT_PILOT_PROOF"),
        ("POST", "/pilot/proof/observations/report", {}, "RATE_LIMIT_PILOT_PROOF"),
        ("POST", "/pilot/proof/observations/list", {}, "RATE_LIMIT_PILOT_PROOF"),
        ("POST", "/pilot/proof/authorize", {}, "RATE_LIMIT_PILOT_AUTHORIZATION"),
        ("POST", "/pilot/proof/jobs", {}, "RATE_LIMIT_PILOT_PROOF_JOBS"),
        ("GET", "/pilot/proof/jobs/" + "a" * 64, None, "RATE_LIMIT_PILOT_PROOF_JOBS"),
        ("POST", "/pilot/proof/jobs/" + "a" * 64 + "/cancel", {}, "RATE_LIMIT_PILOT_PROOF_JOBS"),
        ("POST", "/pilot/proof/jobs/" + "a" * 64 + "/retry", {}, "RATE_LIMIT_PILOT_PROOF_JOBS"),
        ("POST", "/pilot/credential/list", {}, "RATE_LIMIT_PILOT_CREDENTIAL"),
        ("POST", "/pilot/credential/backfill", {}, "RATE_LIMIT_PILOT_CREDENTIAL"),
        ("POST", "/pilot/credential/enroll", {}, "RATE_LIMIT_PILOT_CREDENTIAL"),
        ("POST", "/pilot/credential/revoke", {}, "RATE_LIMIT_PILOT_CREDENTIAL"),
        ("POST", "/pilot/policy/diff", {}, "RATE_LIMIT_PILOT_POLICY"),
        ("POST", "/pilot/policy/approve", {}, "RATE_LIMIT_PILOT_POLICY"),
        ("POST", "/pilot/policy/diff/stored", {}, "RATE_LIMIT_PILOT_POLICY"),
        ("POST", "/pilot/events/ingest", {}, "RATE_LIMIT_PILOT_EVENTS"),
        ("POST", "/pilot/events/investigate", {}, "RATE_LIMIT_PILOT_EVENTS"),
        ("POST", "/pilot/events/queue", {}, "RATE_LIMIT_PILOT_EVENTS"),
        ("POST", "/pilot/fireblocks/int-1", {}, "RATE_LIMIT_PILOT_FIREBLOCKS"),
        ("GET", "/pilot/readiness/inspection/target-1", None, "RATE_LIMIT_PILOT_READINESS"),
        ("GET", "/pilot/usage", None, "RATE_LIMIT_PILOT_USAGE"),
        ("POST", "/wallet/ownership/challenge", {"credential_id": "a" * 64}, "RATE_LIMIT_WALLET_OWNERSHIP"),
        (
            "POST",
            "/wallet/ownership/verify",
            {"nonce": "a" * 64, "signature": "0x" + "11" * 65},
            "RATE_LIMIT_WALLET_OWNERSHIP",
        ),
        ("GET", "/wallet/ownership/attestations/" + "a" * 64, None, "RATE_LIMIT_WALLET_OWNERSHIP"),
        ("POST", "/wallet/ownership/revoke", {"attestation_id": "a" * 64}, "RATE_LIMIT_WALLET_OWNERSHIP"),
        ("POST", "/wallet/ownership/delegation-check", {"attestation_id": "a" * 64}, "RATE_LIMIT_WALLET_OWNERSHIP"),
        ("GET", "/wallet/ownership/evidence/" + "a" * 64, None, "RATE_LIMIT_WALLET_OWNERSHIP"),
        ("POST", "/wallet/ownership/credential", {"attestation_id": "a" * 64}, "RATE_LIMIT_WALLET_OWNERSHIP"),
    ],
)
async def test_route_rate_limit_allow_deny_window_reset_and_spoofed_xff(monkeypatch, method, path, body, env_prefix):
    clock = SimpleNamespace(now=2000.0)
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock.now)
    monkeypatch.setenv(f"{env_prefix}_MAX_REQUESTS", "2")
    monkeypatch.setenv(f"{env_prefix}_WINDOW_SECONDS", "15")

    app: FastAPI = create_app()
    principal = Principal(
        tenant_id="tenant-rl",
        actor_id="actor-rl",
        roles=(
            "credential:issue",
            "credential:revoke",
            "proof:generate",
            "proof:inspect",
            "proof:consume",
            "evidence:read",
            "evidence:decrypt",
            "evidence:export",
            "events:ingest",
            "observations:write",
            "usage:read",
            "policy:read",
            "policy:approve",
            "tenant:admin",
        ),
        issuer_dids=("did:web:issuer.example",),
    )
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    app.state.db = None

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        kwargs = {"json": body} if body is not None else {}
        # 1st and 2nd requests are allowed through rate limiting (not 429).
        r1 = await client.request(method, path, headers={"X-Forwarded-For": "203.0.113.10"}, **kwargs)
        assert r1.status_code != 429
        r2 = await client.request(method, path, headers={"X-Forwarded-For": "203.0.113.11"}, **kwargs)
        assert r2.status_code != 429

        # 3rd request with a different spoofed X-Forwarded-For still hits 429 with Retry-After.
        r3 = await client.request(method, path, headers={"X-Forwarded-For": "203.0.113.12"}, **kwargs)
        assert r3.status_code == 429
        assert r3.json() == {"detail": "Rate limit exceeded"}
        assert int(r3.headers["Retry-After"]) >= 1

        # Advancing past the 15s window resets the bucket and allows traffic again.
        clock.now += 16.0
        r4 = await client.request(method, path, headers={"X-Forwarded-For": "203.0.113.13"}, **kwargs)
        assert r4.status_code != 429


def _iter_app_routes(routes):
    for route in routes:
        if hasattr(route, "original_router"):
            yield from _iter_app_routes(route.original_router.routes)
        elif hasattr(route, "routes"):
            yield from _iter_app_routes(route.routes)
        else:
            yield route


def test_every_pilot_wallet_and_auth_route_has_rate_limit_dependency():
    """Guardrail: newly added /pilot/*, /wallet/ownership/*, or /auth/* routes cannot omit rate limiting."""
    app = create_app()
    protected_prefixes = ("/auth/", "/pilot/", "/wallet/ownership/")
    checked = 0
    for route in _iter_app_routes(app.routes):
        path = getattr(route, "path", "")
        if not path.startswith(protected_prefixes):
            continue
        dependant = getattr(route, "dependant", None)
        assert dependant is not None
        dep_calls = [dep.call for dep in dependant.dependencies]
        assert any(isinstance(call, RateLimiter) for call in dep_calls), f"Missing RateLimiter on {path}"
        checked += 1
    assert checked >= 33


def test_rate_limiter_resolve_pg_store_handles_starlette_request_without_app():
    from starlette.requests import Request as StarletteRequest

    from src.storage.api_state import PostgresRateLimitStore

    limiter = RateLimiter(max_requests=5, window_seconds=60)
    bare_request = StarletteRequest({"type": "http", "headers": []})
    assert limiter._resolve_pg_store(bare_request) is None

    # A stale PostgresRateLimitStore whose Database is closed is cleared and ignored.
    app = FastAPI()
    closed_db = SimpleNamespace(is_ready=False)
    app.state.rate_limit_store = PostgresRateLimitStore(closed_db)
    app.state.db = None
    req = StarletteRequest({"type": "http", "app": app, "headers": []})
    assert limiter._resolve_pg_store(req) is None
    assert app.state.rate_limit_store is None


def test_pg_store_validation_guards():
    from src.storage.api_state import PostgresRateLimitStore, PostgresSIWESessionStore

    sentinel_db = SimpleNamespace()
    with pytest.raises(ValueError, match="cleanup_interval_writes"):
        PostgresRateLimitStore(sentinel_db, cleanup_interval_writes=0)
    with pytest.raises(ValueError, match="cleanup_batch_size"):
        PostgresRateLimitStore(sentinel_db, cleanup_batch_size=0)
    with pytest.raises(ValueError, match="max_entries"):
        PostgresSIWESessionStore(sentinel_db, max_entries=0)
    with pytest.raises(ValueError, match="cleanup_batch_size"):
        PostgresSIWESessionStore(sentinel_db, max_entries=10, cleanup_batch_size=0)
