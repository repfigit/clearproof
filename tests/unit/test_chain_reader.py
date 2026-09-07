"""Cache tests use controlled RPC call objects; no external chain is contacted."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.chain import reader as reader_module
from src.chain.reader import ChainReader


def make_reader(root_byte=1, **kwargs):
    reader = ChainReader("https://rpc.example", {"sanctions_oracle": "0x" + "11" * 20}, **kwargs)
    contracts = {name: MagicMock() for name in ("sanctions_oracle", "vasp_registry", "compliance_registry")}
    reader._contracts.update(contracts)
    calls = {
        "root": contracts["sanctions_oracle"].functions.currentRoot.return_value,
        "stale": contracts["sanctions_oracle"].functions.isStale.return_value,
        "issuer": contracts["vasp_registry"].functions.issuerMerkleRoot.return_value,
        "active": contracts["vasp_registry"].functions.isActive.return_value,
        "revoked": contracts["compliance_registry"].functions.isRevoked.return_value,
        "proof": contracts["compliance_registry"].functions.proofs.return_value,
    }
    values = {
        "root": bytes([root_byte]) * 32,
        "stale": False,
        "issuer": bytes([root_byte]) * 32,
        "active": False,
        "revoked": False,
        "proof": (bytes(32), 0, False),
    }
    for key, call in calls.items():
        call.call = AsyncMock(return_value=values[key])
    return reader, {key: call.call for key, call in calls.items()}


async def test_readers_never_share_roots_or_registry_results():
    first, first_calls = make_reader(1)
    second, second_calls = make_reader(2)
    second_calls["active"].return_value = True
    second_calls["revoked"].return_value = True
    first_root = await first.get_sanctions_root()
    assert await second.get_sanctions_root() != first_root
    assert await first.get_issuer_root() != await second.get_issuer_root()
    for method in ("is_vasp_active", "is_credential_revoked"):
        assert await getattr(first, method)("0x" + "01" * 32) is False
        assert await getattr(second, method)("0x" + "01" * 32) is True
    assert first_calls["root"].await_count == second_calls["root"].await_count == 1


async def test_zero_false_and_absent_record_are_cacheable():
    reader, calls = make_reader(0)
    for _ in range(2):
        assert await reader.get_sanctions_root() == "0x" + "00" * 32
        assert await reader.is_sanctions_stale() is False
        assert await reader.get_proof_record("0x" + "00" * 32) is None
    assert calls["root"].await_count == calls["stale"].await_count == calls["proof"].await_count == 1


async def test_expiry_uses_monotonic_time_and_ttl_starts_before_rpc(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(reader_module, "monotonic", lambda: now[0])
    reader, calls = make_reader(cache_ttl=5)
    await reader.get_sanctions_root()
    now[0] = 104.9
    await reader.get_sanctions_root()
    assert calls["root"].await_count == 1
    now[0] = 105.0
    await reader.get_sanctions_root()
    assert calls["root"].await_count == 2

    async def slow_rpc():
        now[0] += 6
        return bytes(32)

    calls["root"].side_effect = slow_rpc
    reader.invalidate_cache()
    await reader.get_sanctions_root()
    await reader.get_sanctions_root()
    assert calls["root"].await_count == 4


async def test_concurrent_reads_share_one_call_and_cancellation_does_not_cancel_others():
    reader, calls = make_reader()
    entered, release = asyncio.Event(), asyncio.Event()

    async def rpc():
        entered.set()
        await release.wait()
        return bytes(32)

    calls["root"].side_effect = rpc
    cancelled = asyncio.create_task(reader.get_sanctions_root())
    await asyncio.wait_for(entered.wait(), timeout=2)
    remaining = [asyncio.create_task(reader.get_sanctions_root()) for _ in range(10)]
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    release.set()
    assert await asyncio.gather(*remaining) == ["0x" + "00" * 32] * 10
    assert calls["root"].await_count == 1


async def test_invalidation_during_rpc_prevents_old_request_from_refilling_cache():
    reader, calls = make_reader()
    entered, release = asyncio.Event(), asyncio.Event()
    count = 0

    async def rpc():
        nonlocal count
        count += 1
        if count == 1:
            entered.set()
            await release.wait()
            return bytes([1]) * 32
        return bytes([2]) * 32

    calls["root"].side_effect = rpc
    old = asyncio.create_task(reader.get_sanctions_root())
    await asyncio.wait_for(entered.wait(), timeout=2)
    reader.invalidate_cache()
    assert await reader.get_sanctions_root() == "0x" + "02" * 32
    release.set()
    assert await old == "0x" + "01" * 32
    assert await reader.get_sanctions_root() == "0x" + "02" * 32
    assert calls["root"].await_count == 2


async def test_rpc_errors_are_not_cached_or_reported_as_absence():
    reader, calls = make_reader()
    calls["proof"].side_effect = [TimeoutError("RPC unavailable"), (bytes(32), 0, False)]
    with pytest.raises(TimeoutError):
        await reader.get_proof_record("0x" + "01" * 32)
    assert await reader.get_proof_record("0x" + "01" * 32) is None
    assert calls["proof"].await_count == 2


async def test_cached_records_cannot_be_mutated_by_a_caller():
    reader, calls = make_reader()
    calls["proof"].return_value = (bytes([2]) * 32, 100, True)
    record = await reader.get_proof_record("0x" + "01" * 32)
    record["proof_hash"] = "changed"
    assert (await reader.get_proof_record("0x" + "01" * 32))["proof_hash"] == "0x" + "02" * 32


async def test_cache_is_bounded_and_hash_keys_are_normalized():
    reader, calls = make_reader(max_cache_entries=2)
    for value in ("aa", "bb", "cc"):
        await reader.is_vasp_active(value * 32)
    assert len(reader._cache) == 2
    await reader.is_vasp_active("0x" + "CC" * 32)
    assert calls["active"].await_count == 3
    await reader.is_vasp_active("aa" * 32)
    assert calls["active"].await_count == 4


async def test_zero_ttl_disables_caching():
    reader, calls = make_reader(cache_ttl=0)
    await reader.get_sanctions_root()
    await reader.get_sanctions_root()
    assert calls["root"].await_count == 2
    assert not reader._cache


@pytest.mark.parametrize("ttl", [-1, float("inf"), float("nan")])
def test_invalid_ttl_fails_early(ttl):
    with pytest.raises(ValueError, match="TTL"):
        make_reader(cache_ttl=ttl)


def test_deployment_configuration_is_copied_and_singleton_tracks_changes(monkeypatch):
    addresses = {"sanctions_oracle": "0x" + "11" * 20}
    reader = ChainReader("https://rpc.example", addresses)
    addresses["sanctions_oracle"] = "0x" + "22" * 20
    assert reader._addresses["sanctions_oracle"] == "0x" + "11" * 20
    monkeypatch.setattr(reader_module, "_reader_instance", None)
    monkeypatch.setenv("CHAIN_RPC_URL", "https://first.example")
    first = reader_module.get_chain_reader()
    assert reader_module.get_chain_reader() is first
    monkeypatch.setenv("SANCTIONS_ORACLE_ADDRESS", "0x" + "33" * 20)
    assert reader_module.get_chain_reader() is not first


@pytest.mark.parametrize("value", ["", "0x12", "0x" + "gg" * 32, "0x" + "00" * 33])
async def test_invalid_identifiers_are_rejected_before_rpc(value):
    reader, calls = make_reader()
    with pytest.raises(ValueError, match="32-byte"):
        await reader.is_vasp_active(value)
    assert calls["active"].await_count == 0


async def test_vasp_information_cache_is_scoped_and_immutable():
    first, _ = make_reader()
    second, _ = make_reader()
    for reader, code in [(first, "US"), (second, "EU")]:
        call = AsyncMock(return_value=["0x" + "11" * 20, code, "", True, 1])
        reader._contracts["vasp_registry"].functions.vasps.return_value.call = call
    record = await first.get_vasp_info("did:web:vasp.example")
    assert isinstance(record, tuple) and record[1] == "US"
    assert (await second.get_vasp_info("did:web:vasp.example"))[1] == "EU"
    assert await first.get_vasp_info("did:web:vasp.example") == record
    first._contracts["vasp_registry"].functions.vasps.return_value.call.assert_awaited_once()
