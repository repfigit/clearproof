"""Use real ABI encoding and transaction signing with an isolated RPC boundary."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from eth_account import Account
from hexbytes import HexBytes

from src.chain.writer import ChainWriter, _load_abi


@pytest.fixture
def writer():
    return ChainWriter("http://127.0.0.1:1", "11" * 32, {"compliance_registry": "0x" + "22" * 20})


def test_contract_cache_and_missing_configuration(writer):
    first = writer._compliance_registry
    assert writer._compliance_registry is first
    assert first.address.lower() == "0x" + "22" * 20
    with pytest.raises(RuntimeError, match="not configured"):
        writer._get_contract("missing", "ComplianceRegistry")
    with pytest.raises(FileNotFoundError):
        _load_abi("missing-synthetic-abi")


async def test_record_proof_encodes_the_actual_bytes32_contract_abi(writer, sample_compliance_proof):
    writer._send_tx = AsyncMock(return_value="0xresult")
    proof = {"pi_a": ["1", "2", "1"], "pi_b": [["3", "4"], ["5", "6"], ["1", "0"]], "pi_c": ["7", "8", "1"]}
    transfer = b"t" * 32
    assert await writer.record_proof(transfer, proof, sample_compliance_proof.public_signals, 123) == "0xresult"
    function = writer._send_tx.call_args.args[0]
    _, decoded = writer._compliance_registry.decode_function_input(function._encode_transaction_data())
    assert decoded["transferId"] == transfer
    assert decoded["_pA"] == [1, 2]
    assert decoded["_pB"] == [[4, 3], [6, 5]]
    assert decoded["_pC"] == [7, 8]
    assert decoded["_pubSignals"] == [int(value) for value in sample_compliance_proof.public_signals]
    assert decoded["vaspDidHash"] == (123).to_bytes(32, "big")


async def test_revocation_encodes_the_commitment(writer):
    writer._send_tx = AsyncMock(return_value="0xrevoked")
    assert await writer.revoke_credential(b"c" * 32) == "0xrevoked"
    function = writer._send_tx.call_args.args[0]
    _, decoded = writer._compliance_registry.decode_function_input(function._encode_transaction_data())
    assert decoded == {"commitment": b"c" * 32}


async def test_send_transaction_uses_pending_nonce_and_real_signature(writer, caplog):
    caplog.set_level("INFO", logger="src.chain.writer")
    chain_id = asyncio.get_running_loop().create_future()
    chain_id.set_result(31337)
    eth = SimpleNamespace(
        get_transaction_count=AsyncMock(return_value=7),
        chain_id=chain_id,
        account=Account,
        send_raw_transaction=AsyncMock(return_value=HexBytes("0x" + "cd" * 32)),
    )
    writer._w3 = SimpleNamespace(eth=eth)
    transaction = {
        "chainId": 31337,
        "nonce": 7,
        "gas": 21000,
        "gasPrice": 1000000000,
        "to": "0x" + "22" * 20,
        "value": 0,
        "data": b"",
    }
    function = SimpleNamespace(build_transaction=AsyncMock(return_value=transaction))
    assert await writer._send_tx(function) == "0x" + "cd" * 32
    eth.get_transaction_count.assert_awaited_once_with(writer._account.address, "pending")
    function.build_transaction.assert_awaited_once_with({"from": writer._account.address, "nonce": 7, "chainId": 31337})
    raw = eth.send_raw_transaction.call_args.args[0]
    assert Account.recover_transaction(raw) == writer._account.address
    assert "Transaction sent:" in caplog.text
    assert "11" * 32 not in caplog.text


async def test_rpc_failure_is_propagated_before_signing_or_submission(writer):
    writer._w3 = SimpleNamespace(eth=SimpleNamespace(get_transaction_count=AsyncMock(side_effect=OSError("offline"))))
    function = SimpleNamespace(build_transaction=AsyncMock())
    with pytest.raises(OSError, match="offline"):
        await writer._send_tx(function)
    function.build_transaction.assert_not_awaited()
