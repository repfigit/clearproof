"""Signed transaction binding checks independent of RPC/provider assertions."""

import hashlib

import pytest
from eth_account import Account
from web3 import Web3

from src.storage.publication_journal import PublicationBinding, signed_identity


def transaction_case():
    account = Account.from_key(b"a" * 32)
    transaction = dict(
        type=2,
        chainId=31337,
        nonce=4,
        to="0x" + "12" * 20,
        value=0,
        data=b"synthetic-calldata",
        gas=200000,
        maxFeePerGas=2000000000,
        maxPriorityFeePerGas=1000000000,
    )
    binding = PublicationBinding(
        receipt_id="11" * 32,
        statement_id="22" * 32,
        phase="publish",
        chain_id=31337,
        registry=transaction["to"],
        sender=account.address.lower(),
        calldata_digest=hashlib.sha256(transaction["data"]).hexdigest(),
        plan_digest="33" * 32,
        runtime_sha256="44" * 32,
        expires_at=100,
    )
    return account, transaction, binding


def test_signed_identity_is_computed_from_exact_transaction_bytes():
    account, transaction, binding = transaction_case()
    signed = account.sign_transaction(transaction)
    identity, nonce = signed_identity(binding, bytes(signed.raw_transaction))
    assert identity == bytes(signed.hash).hex() == bytes(Web3.keccak(signed.raw_transaction)).hex()
    assert nonce == 4


@pytest.mark.parametrize(
    "change", [dict(chainId=1), dict(to="0x" + "13" * 20), dict(value=1), dict(data=b"changed"), dict(nonce=2**53)]
)
def test_other_signed_transactions_cannot_borrow_binding(change):
    account, transaction, binding = transaction_case()
    signed = account.sign_transaction({**transaction, **change})
    with pytest.raises(ValueError):
        signed_identity(binding, bytes(signed.raw_transaction))


def test_wrong_signer_and_malformed_or_unsupported_encodings_reject():
    _, transaction, binding = transaction_case()
    wrong = Account.from_key(b"b" * 32).sign_transaction(transaction)
    for raw in (bytes(wrong.raw_transaction), b"", b"\x02", b"\x01junk", b"\x02" * 16385):
        with pytest.raises(ValueError):
            signed_identity(binding, raw)


@pytest.mark.parametrize("field", ["registry", "sender"])
def test_publication_requires_nonzero_destination_and_sender(field):
    _, _, binding = transaction_case()
    with pytest.raises(ValueError, match="configured registry and sender"):
        PublicationBinding.model_validate({**binding.model_dump(), field: "0x" + "00" * 20})
