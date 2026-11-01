"""Unit tests for chain-side wallet-account verification (ERC-1271/6492, EIP-7702).

Uses a fake AsyncWeb3 double — no network, no real RPC.
"""

import pytest

from src.chain.wallet_account import (
    ERC_1271_MAGIC_VALUE,
    ERC_6492_MAGIC_SUFFIX,
    EoaVerificationRequired,
    WalletAccountRPCError,
    account_code,
    delegation_indicator,
    parse_erc6492,
    verify_signature,
)

MAGIC_RETURN = bytes.fromhex("1626ba7e" + "00" * 28)
DIGEST = bytes(range(32))
ADDRESS = "0x" + "ab" * 20
DELEGATE = "0x" + "cd" * 20
CONTRACT = "0x" + "11" * 20


class FakeEth:
    """Minimal AsyncWeb3 ``eth`` double with canned get_code / call results."""

    def __init__(self, code="0x", call_result=MAGIC_RETURN, call_error=None, get_code_error=None):
        self.code = code
        self.call_result = call_result
        self.call_error = call_error
        self.get_code_error = get_code_error
        self.calls = []

    async def get_code(self, address, block_identifier=None):
        if self.get_code_error is not None:
            raise self.get_code_error
        return bytes.fromhex(self.code[2:])

    async def call(self, transaction, block_identifier=None, state_override=None, ccip_read_enabled=None):
        self.calls.append({"transaction": transaction, "state_override": state_override})
        if self.call_error is not None:
            raise self.call_error
        return self.call_result


class FakeW3:
    def __init__(self, **kwargs):
        self.eth = FakeEth(**kwargs)


def valid_indicator_code(delegate=DELEGATE):
    return "0xef0100" + delegate[2:] + "000000"


def make_erc6492_signature(inner="0x" + "45" * 65, contract=CONTRACT, data="0x" + "ff" * 10):
    data_bytes = bytes.fromhex(data[2:])
    length_hex = len(data_bytes).to_bytes(32, "big").hex()
    payload = inner[2:] + contract[2:] + data_bytes.hex() + length_hex + ERC_6492_MAGIC_SUFFIX[2:]
    return "0x" + payload


# -- account_code -----------------------------------------------------------


@pytest.mark.asyncio
async def test_account_code_normalizes_lowercase_and_empty():
    assert await account_code(FakeW3(code="0x"), ADDRESS) == "0x"
    assert await account_code(FakeW3(code="0x60806040"), ADDRESS) == "0x60806040"
    assert await account_code(FakeW3(code="0xDEADBEEF"), ADDRESS) == "0xdeadbeef"


@pytest.mark.asyncio
async def test_account_code_fails_closed_on_rpc_error():
    with pytest.raises(WalletAccountRPCError):
        await account_code(FakeW3(get_code_error=ConnectionError("node down")), ADDRESS)


# -- delegation_indicator ---------------------------------------------------


def test_valid_indicator_is_delegated_with_exact_padding():
    result = delegation_indicator(valid_indicator_code())
    assert result == {"delegated": True, "delegate": DELEGATE, "indicator_malformed": False}


def test_indicator_requires_exact_padding_and_length():
    # Nonzero padding byte in the 23-byte payload → malformed, not delegated.
    malformed_padding = "0xef0100" + DELEGATE[2:] + "000001"
    assert delegation_indicator(malformed_padding) == {
        "delegated": False,
        "delegate": None,
        "indicator_malformed": True,
    }
    # Missing the 3 padding bytes (bare 0xef0100 + address) → malformed.
    short = "0xef0100" + DELEGATE[2:]
    assert delegation_indicator(short)["indicator_malformed"] is True
    assert delegation_indicator(short)["delegated"] is False
    # Extra junk beyond the 23-byte payload → malformed.
    long = valid_indicator_code() + "ff"
    assert delegation_indicator(long)["indicator_malformed"] is True
    # Truncated delegate address → malformed.
    truncated = "0xef0100" + DELEGATE[2:-2] + "000000"
    assert delegation_indicator(truncated)["indicator_malformed"] is True


def test_non_prefixed_code_is_ordinary_contract_code():
    code = "0x6080604052"
    assert delegation_indicator(code) == {"delegated": False, "delegate": None, "indicator_malformed": False}
    assert delegation_indicator("0x") == {"delegated": False, "delegate": None, "indicator_malformed": False}


# -- parse_erc6492 ----------------------------------------------------------


def test_parse_erc6492_round_trip():
    signature = make_erc6492_signature()
    parsed = parse_erc6492(signature)
    assert parsed == {
        "contract_address": CONTRACT,
        "data_to_sign": "0x" + "ff" * 10,
        "inner_signature": "0x" + "45" * 65,
    }


def test_parse_erc6492_returns_none_without_suffix():
    assert parse_erc6492("0x" + "45" * 65) is None
    assert parse_erc6492("0x" + ERC_6492_MAGIC_SUFFIX[2:10]) is None


@pytest.mark.parametrize(
    "bad",
    [
        "0x" + "45" * 65 + "11" * 20 + "ff" * 4 + (10).to_bytes(32, "big").hex() + ERC_6492_MAGIC_SUFFIX[2:] + "ff",
        "0x" + "45" * 65 + "11" * 20 + "ff" * 4 + (99).to_bytes(32, "big").hex() + ERC_6492_MAGIC_SUFFIX[2:],
        "0x" + "11" * 20 + "ff" * 4 + (10).to_bytes(32, "big").hex() + ERC_6492_MAGIC_SUFFIX[2:],
        "0x" + "11" * 20 + (10).to_bytes(32, "big").hex() + ERC_6492_MAGIC_SUFFIX[2:],
        "0x" + (10).to_bytes(32, "big").hex() + ERC_6492_MAGIC_SUFFIX[2:],
    ],
)
def test_parse_erc6492_rejects_junk_and_inconsistent_layout(bad):
    with pytest.raises(ValueError):
        parse_erc6492(bad)


def test_parse_erc6492_rejects_malformed_hex():
    with pytest.raises(ValueError):
        parse_erc6492("0xzz" + ERC_6492_MAGIC_SUFFIX[2:])
    with pytest.raises(ValueError):
        parse_erc6492("0x1" + ERC_6492_MAGIC_SUFFIX[2:])


def test_parse_erc6492_accepts_empty_data_to_sign():
    signature = make_erc6492_signature(data="0x")
    parsed = parse_erc6492(signature)
    assert parsed["data_to_sign"] == "0x"
    assert parsed["contract_address"] == CONTRACT


# -- verify_signature -------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_code_raises_eoa_sentinel():
    w3 = FakeW3(code="0x")
    with pytest.raises(EoaVerificationRequired):
        await verify_signature(w3, ADDRESS, DIGEST, "0x" + "45" * 65)
    assert w3.eth.calls == []  # no eth_call attempted on the EOA path


@pytest.mark.asyncio
async def test_contract_account_erc1271_success():
    w3 = FakeW3(code="0x60806040")
    valid, method = await verify_signature(w3, ADDRESS, DIGEST, "0x" + "45" * 65)
    assert (valid, method) == (True, "erc-1271")
    call = w3.eth.calls[0]["transaction"]
    assert call["to"] == ADDRESS
    assert call["data"].startswith("0x1626ba7e")
    assert bytes.fromhex(call["data"][2:])[36:68] == (0x40).to_bytes(32, "big")  # bytes offset
    assert bytes.fromhex(call["data"][2:])[68:100] == (65).to_bytes(32, "big")  # bytes length


@pytest.mark.asyncio
async def test_contract_account_erc1271_failure_on_wrong_return_value():
    w3 = FakeW3(code="0x60806040", call_result=b"\x00" * 32)
    assert await verify_signature(w3, ADDRESS, DIGEST, "0x" + "45" * 65) == (False, "erc-1271")
    w3.eth.call_result = MAGIC_RETURN[:-1] + b"\x01"
    assert await verify_signature(w3, ADDRESS, DIGEST, "0x" + "45" * 65) == (False, "erc-1271")


@pytest.mark.asyncio
async def test_contract_account_erc1271_revert_is_invalid_not_rpc_error():
    from web3.exceptions import ContractLogicError

    w3 = FakeW3(code="0x60806040", call_error=ContractLogicError("execution reverted"))
    assert await verify_signature(w3, ADDRESS, DIGEST, "0x" + "45" * 65) == (False, "erc-1271")


@pytest.mark.asyncio
async def test_delegated_eoa_is_treated_as_contract_code():
    # Valid indicator code: ERC-1271-style call decides, never the EOA sentinel.
    w3 = FakeW3(code=valid_indicator_code())
    assert await verify_signature(w3, ADDRESS, DIGEST, "0x" + "45" * 65) == (True, "erc-1271")
    w3.eth.call_result = b"\x01" + b"\x00" * 31
    assert await verify_signature(w3, ADDRESS, DIGEST, "0x" + "45" * 65) == (False, "erc-1271")


@pytest.mark.asyncio
async def test_verify_signature_fails_closed_on_rpc_errors():
    with pytest.raises(WalletAccountRPCError):
        await verify_signature(FakeW3(get_code_error=TimeoutError("rpc")), ADDRESS, DIGEST, "0x" + "45" * 65)
    with pytest.raises(WalletAccountRPCError):
        await verify_signature(
            FakeW3(code="0x6080", call_error=ConnectionError("node down")), ADDRESS, DIGEST, "0x" + "45" * 65
        )


@pytest.mark.asyncio
async def test_verify_signature_erc6492_success_simulates_deploy():
    signature = make_erc6492_signature()
    w3 = FakeW3(code="0x")  # counterfactual: account not yet deployed
    valid, method = await verify_signature(w3, ADDRESS, DIGEST, signature)
    assert (valid, method) == (True, "erc-6492")
    call = w3.eth.calls[0]
    assert call["transaction"]["to"] == CONTRACT
    assert call["state_override"] == {CONTRACT: {"code": "0x" + "ff" * 10}}


@pytest.mark.asyncio
async def test_verify_signature_erc6492_failure_and_malformed_wrapper():
    w3 = FakeW3(code="0x", call_result=b"\x00" * 32)
    assert await verify_signature(w3, ADDRESS, DIGEST, make_erc6492_signature()) == (False, "erc-6492")
    # 6492 wrapper wins over deployed code; revert maps to invalid, not RPC error.
    from web3.exceptions import ContractLogicError

    w2 = FakeW3(code="0x6080", call_error=ContractLogicError("reverted"))
    assert await verify_signature(w2, ADDRESS, DIGEST, make_erc6492_signature()) == (False, "erc-6492")
    # Structurally broken wrapper fails closed without touching the chain.
    w3.eth.calls.clear()
    broken = "0x" + "45" * 65 + "11" * 20 + (99).to_bytes(32, "big").hex() + ERC_6492_MAGIC_SUFFIX[2:]
    assert await verify_signature(FakeW3(code="0x"), ADDRESS, DIGEST, broken) == (False, "erc-6492")


@pytest.mark.asyncio
async def test_verify_signature_erc6492_rpc_error_raises():
    with pytest.raises(WalletAccountRPCError):
        await verify_signature(
            FakeW3(code="0x", call_error=ConnectionError("node down")), ADDRESS, DIGEST, make_erc6492_signature()
        )


@pytest.mark.asyncio
async def test_verify_signature_validates_inputs():
    w3 = FakeW3(code="0x6080")
    with pytest.raises(ValueError):
        await verify_signature(w3, ADDRESS, b"\x01" * 31, "0x" + "45" * 65)  # short digest
    with pytest.raises(ValueError):
        await verify_signature(w3, "0x123", DIGEST, "0x" + "45" * 65)  # bad address
    with pytest.raises(ValueError):
        await verify_signature(w3, ADDRESS, DIGEST, "0x454")  # odd-length signature


def test_magic_constant_matches_expected_value():
    assert ERC_1271_MAGIC_VALUE == "0x1626ba7e"
    assert MAGIC_RETURN == bytes.fromhex("1626ba7e" + "00" * 28)
