"""Real EIP-4361 signing plus nonce/session storage boundaries."""

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from siwe import SiweMessage

from src.auth import siwe_auth as module


@pytest.fixture(autouse=True)
def isolated_stores(monkeypatch):
    monkeypatch.setattr(module, "_nonce_store", {})
    monkeypatch.setattr(module, "_siwe_auth_instance", None)
    monkeypatch.delenv("SIWE_MAX_SESSIONS", raising=False)


def signed(nonce, domain="wallet.example", account=None):
    account = account or Account.from_key(b"\x11" * 32)
    message = SiweMessage(
        domain=domain,
        address=account.address,
        uri=f"https://{domain}",
        version="1",
        chain_id=1,
        nonce=nonce,
        issued_at=datetime.now(timezone.utc).isoformat(),
    ).prepare_message()
    return message, account.sign_message(encode_defunct(text=message)).signature.hex(), account.address


async def test_nonce_uses_eip4361_alphanumeric_alphabet_for_all_entropy(monkeypatch):
    # URL-safe base64 can produce '-' and '_', which EIP-4361 rejects.
    monkeypatch.setattr(module.secrets, "token_bytes", lambda count: b"\xfb" * count)
    nonce = await module.SIWEAuth("wallet.example").generate_nonce()
    assert re.fullmatch(r"[A-Za-z0-9]{8,}", nonce)
    signed(nonce)  # The installed SIWE parser must accept the actual issued value.


async def test_real_signature_session_and_single_use_nonce():
    auth = module.SIWEAuth("wallet.example")
    message, signature, address = signed(await auth.generate_nonce())
    result = await auth.verify(message, signature)
    assert result["address"] == address
    assert result["chain_id"] == 1
    assert datetime.fromisoformat(result["expires_at"]) > datetime.now(timezone.utc)
    assert await auth.validate_session(result["session_token"]) == result
    with pytest.raises(ValueError, match="Invalid or expired nonce"):
        await auth.verify(message, signature)
    assert await auth.validate_session("missing") is None


@pytest.mark.parametrize("age,valid", [(299, True), (300, False), (301, False)])
async def test_nonce_expiry_boundary(monkeypatch, age, valid):
    module._nonce_store["syntheticnonce"] = 1000
    monkeypatch.setattr(module.time, "time", lambda: 1000 + age)
    assert await module.SIWEAuth("wallet.example")._consume_nonce("syntheticnonce") is valid
    assert "syntheticnonce" not in module._nonce_store


async def test_nonce_purge_keeps_live_entries(monkeypatch):
    module._nonce_store.update(expired=1000, boundary=1001, live=1002)
    monkeypatch.setattr(module.time, "time", lambda: 1301)
    await module.SIWEAuth("wallet.example").generate_nonce()
    assert "expired" not in module._nonce_store
    assert "boundary" not in module._nonce_store
    assert module._nonce_store["live"] == 1002


async def test_malformed_domain_unknown_nonce_and_wrong_signer():
    auth = module.SIWEAuth("wallet.example")
    with pytest.raises(ValueError, match="Malformed SIWE message"):
        await auth.verify("invalid message", "0x00")
    nonce = await auth.generate_nonce()
    wrong_domain, signature, _ = signed(nonce, domain="other.example")
    with pytest.raises(ValueError, match="Domain mismatch"):
        await auth.verify(wrong_domain, signature)
    assert nonce in module._nonce_store
    message, _, _ = signed(nonce)
    wrong_signature = Account.from_key(b"\x22" * 32).sign_message(encode_defunct(text=message)).signature.hex()
    with pytest.raises(ValueError, match="Signature verification failed"):
        await auth.verify(message, wrong_signature)
    assert nonce not in module._nonce_store
    assert auth.session_count() == 0
    unknown, signature, _ = signed("unknownnonce")
    with pytest.raises(ValueError, match="Invalid or expired nonce"):
        await auth.verify(unknown, signature)


async def test_concurrent_verifications_issue_one_session():
    auth = module.SIWEAuth("wallet.example")
    message, signature, _ = signed(await auth.generate_nonce())
    results = await asyncio.gather(*(auth.verify(message, signature) for _ in range(4)), return_exceptions=True)
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 3
    assert auth.session_count() == 1


@pytest.mark.parametrize("delta,valid", [(-1, True), (0, False), (1, False)])
async def test_session_expiry_boundary(monkeypatch, delta, valid):
    expiry = datetime(2026, 1, 1, tzinfo=timezone.utc)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return expiry + timedelta(seconds=delta)

    monkeypatch.setattr(module, "datetime", Clock)
    auth = module.SIWEAuth("wallet.example")
    session = {"expires_at": expiry.isoformat()}
    auth._sessions._entries["token"] = session
    result = await auth.validate_session("token")
    assert result == (session if valid else None)
    assert ("token" in auth._sessions) is valid
    assert auth.session_count() == (1 if valid else 0)


async def test_redis_protocol_nonce_session_and_misses():
    redis = AsyncMock()
    redis.delete.side_effect = [1, 0]
    auth = module.SIWEAuth("wallet.example", redis_client=redis)
    nonce = await auth.generate_nonce()
    redis.setex.assert_awaited_once_with(f"siwe:nonce:{nonce}", 300, "1")
    message, signature, address = signed(nonce)
    session = await auth.verify(message, signature)
    assert session["address"] == address
    redis.setex.assert_awaited_with(f"siwe:session:{session['session_token']}", 86400, json.dumps(session))
    assert auth.session_count() == 0
    assert module._nonce_store == {}
    redis.get.return_value = json.dumps(session).encode()
    assert await auth.validate_session(session["session_token"]) == session
    redis.get.return_value = None
    assert await auth.validate_session("missing") is None
    assert await auth._consume_nonce(nonce) is False


async def test_redis_failure_does_not_create_local_fallback_session():
    redis = AsyncMock()
    redis.delete.side_effect = ConnectionError("redis unavailable")
    auth = module.SIWEAuth("wallet.example", redis_client=redis)
    message, signature, _ = signed("syntheticnonce")
    with pytest.raises(ConnectionError):
        await auth.verify(message, signature)
    assert auth.session_count() == 0
    redis.setex.assert_not_awaited()


async def test_module_convenience_configuration(monkeypatch):
    monkeypatch.setenv("SIWE_DOMAIN", "wallet.example")
    auth = module._get_siwe_auth()
    assert module._get_siwe_auth() is auth
    assert auth.domain == "wallet.example"
    message, signature, _ = signed(await auth.generate_nonce())
    assert (await module.verify_siwe(message, signature))["chain_id"] == 1
    monkeypatch.delenv("SIWE_DOMAIN")
    monkeypatch.setattr(module, "_siwe_auth_instance", None)
    assert module._get_siwe_auth().domain == "localhost"


def test_siwe_max_sessions_env_parsing_and_validation(monkeypatch):
    monkeypatch.delenv("SIWE_MAX_SESSIONS", raising=False)
    assert module.siwe_max_sessions() == module.DEFAULT_MAX_SESSIONS

    monkeypatch.setenv("SIWE_MAX_SESSIONS", "  ")
    assert module.siwe_max_sessions() == module.DEFAULT_MAX_SESSIONS

    monkeypatch.setenv("SIWE_MAX_SESSIONS", "25")
    assert module.siwe_max_sessions() == 25

    for invalid in ("0", "-5", "abc"):
        monkeypatch.setenv("SIWE_MAX_SESSIONS", invalid)
        with pytest.raises(ValueError):
            module.siwe_max_sessions()

    with pytest.raises(ValueError):
        module.BoundedSessionStore(max_entries=0)


async def test_bounded_session_store_lru_eviction_and_ttl_sweep(monkeypatch):
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    clock = [base]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0]

    monkeypatch.setattr(module, "datetime", Clock)

    auth = module.SIWEAuth("wallet.example", max_sessions=2)
    assert auth._sessions.max_entries == 2

    # Insert 2 sessions via verify()
    tokens = []
    for _ in range(2):
        msg, sig, _ = signed(await auth.generate_nonce())
        tokens.append((await auth.verify(msg, sig))["session_token"])
    assert auth.session_count() == 2
    assert len(auth._sessions) == 2

    # Touch token[0] so it becomes MRU; token[1] becomes LRU.
    assert await auth.validate_session(tokens[0]) is not None

    # Refreshing an existing token moves it to MRU without evicting.
    existing = auth._sessions[tokens[0]]
    auth._sessions.set(tokens[0], existing)
    assert auth.session_count() == 2

    # Inserting a 3rd session evicts LRU (token[1]), keeping token[0] and token[2].
    msg, sig, _ = signed(await auth.generate_nonce())
    token3 = (await auth.verify(msg, sig))["session_token"]
    assert auth.session_count() == 2
    assert await auth.validate_session(tokens[1]) is None
    assert await auth.validate_session(tokens[0]) is not None
    assert await auth.validate_session(token3) is not None

    # Advance past expiry; TTL sweep on write clears expired sessions before inserting.
    clock[0] = base + timedelta(seconds=module._SESSION_TTL_SECONDS + 1)
    assert auth._sessions.sweep_expired(now=clock[0]) == 2
    assert auth.session_count() == 0

    # Insert a session that expires soon, plus one that stays valid; sweep on read drops only expired.
    auth._sessions.set("short", {"expires_at": (clock[0] + timedelta(seconds=10)).isoformat()})
    auth._sessions.set("long", {"expires_at": (clock[0] + timedelta(seconds=100)).isoformat()})
    assert auth.session_count() == 2
    clock[0] = clock[0] + timedelta(seconds=20)
    assert await auth.validate_session("long") is not None
    assert auth.session_count() == 1
    assert "short" not in auth._sessions
