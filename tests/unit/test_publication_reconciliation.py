"""Adversarial RPC observations cannot become publication success or resend permission."""

import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from web3 import Web3
from web3.exceptions import TransactionNotFound

from src.chain.publication_reconciliation import (
    PublicationChainPolicy,
    PublicationObservationError,
    PublicationReconciler,
)
from src.protocol.canonical import record_digest
from tests.unit.test_publication_journal import transaction_case


@pytest.fixture
def case():
    _, _, binding = transaction_case()
    runtime = b"synthetic-reviewed-runtime"
    binding = binding.model_copy(update={"runtime_sha256": hashlib.sha256(runtime).hexdigest()})
    hash_ = bytes.fromhex("ab" * 32)
    block = dict(number=9, hash=b"b" * 32, timestamp=99, transactions=[hash_])
    anchor = dict(number=10, hash=b"a" * 32, timestamp=100, transactions=[])
    transaction = dict(
        hash=hash_,
        chainId=binding.chain_id,
        nonce=4,
        to=binding.registry,
        value=0,
        input=b"synthetic-calldata",
        blockNumber=9,
        blockHash=block["hash"],
    )
    transaction["from"] = binding.sender
    tenant = bytes.fromhex(record_digest("clearproof/tenant-checkpoint/v1", {"tenant_id": "tenant-a"}))
    event = dict(
        address=binding.registry,
        topics=[
            Web3.keccak(text="StatementPublished(bytes32,bytes32,bytes32)"),
            tenant,
            bytes.fromhex(binding.statement_id),
        ],
        data=b"c" * 32,
    )
    receipt = dict(
        transactionHash=hash_,
        status=1,
        to=binding.registry,
        blockNumber=9,
        blockHash=block["hash"],
        transactionIndex=0,
        logs=[event],
    )
    receipt["from"] = binding.sender
    contract = Mock()
    contract.functions.statementPublication.return_value.call = AsyncMock(return_value=(True, 1))

    class Eth:
        @property
        async def chain_id(self):
            return 31337

    eth = Eth()
    eth.contract = Mock(return_value=contract)
    eth.get_code = AsyncMock(return_value=runtime)
    eth.get_transaction = AsyncMock(return_value=transaction)
    eth.get_transaction_receipt = AsyncMock(return_value=receipt)
    eth.get_block = AsyncMock(side_effect=lambda number: block if number == 9 else anchor)
    journal = SimpleNamespace(
        store=SimpleNamespace(tenant_id="tenant-a"),
        inspect=AsyncMock(
            return_value={
                "binding": binding.model_dump(mode="json"),
                "transaction_hash": hash_.hex(),
                "account_nonce": 4,
            }
        ),
    )
    policy = PublicationChainPolicy(
        chain_id=31337,
        registry=binding.registry,
        runtime_sha256=binding.runtime_sha256,
        block_tag="latest",
        minimum_confirmations=2,
    )
    reconciler = PublicationReconciler(SimpleNamespace(eth=eth), journal, policy)
    return reconciler, eth, transaction, receipt, block, anchor, contract


async def test_confirmed_execution_requires_event_and_state_without_authorizing_transfer(case):
    reconciler, *_ = case
    result = await reconciler.reconcile("01" * 32, now=100)
    assert result["status"] == "confirmed-success" and result["confirmations"] == 2
    assert result["registry_effect"] == "statement-published-at-inclusion"
    assert result["current_authorization"] == "not-evaluated" and result["resubmission"] == "not-authorized"


@pytest.mark.parametrize(
    "state", ["not-found", "pending", "confirmed-failure", "awaiting-confirmations", "noncanonical"]
)
async def test_non_success_states_are_distinct_and_never_authorize_resubmission(case, state):
    reconciler, eth, transaction, receipt, block, _, _ = case
    if state == "not-found":
        eth.get_transaction.side_effect = TransactionNotFound("Synthetic provider has no transaction")
    elif state == "pending":
        transaction.update(blockNumber=None, blockHash=None)
        eth.get_transaction_receipt.side_effect = TransactionNotFound("Synthetic provider has no transaction")
    elif state == "confirmed-failure":
        receipt["status"] = 0
        receipt["logs"] = []
    elif state == "awaiting-confirmations":
        reconciler.policy = reconciler.policy.model_copy(update={"minimum_confirmations": 3})
    else:
        block["hash"] = b"x" * 32
    result = await reconciler.reconcile("01" * 32, now=100)
    assert result["status"] == state and result["resubmission"] == "not-authorized"


@pytest.mark.parametrize(
    "mutation",
    [
        "chain",
        "runtime",
        "input",
        "nonce",
        "destination",
        "receipt",
        "index",
        "event",
        "tenant",
        "statement",
        "state",
        "stale",
        "missing_receipt",
    ],
)
async def test_inconsistent_observations_fail_closed(case, mutation):
    reconciler, eth, transaction, receipt, _, _, contract = case
    now = 100
    if mutation == "chain":
        reconciler.policy = reconciler.policy.model_copy(update={"chain_id": 1})
    elif mutation == "runtime":
        eth.get_code.return_value = b"wrong"
    elif mutation == "input":
        transaction["input"] = b"substituted"
    elif mutation == "nonce":
        transaction["nonce"] += 1
    elif mutation == "destination":
        transaction["to"] = "0x" + "00" * 20
    elif mutation == "receipt":
        receipt["transactionHash"] = bytes(32)
    elif mutation == "index":
        receipt["transactionIndex"] = 1
    elif mutation == "event":
        receipt["logs"] = []
    elif mutation in ("tenant", "statement"):
        receipt["logs"][0]["topics"][1 if mutation == "tenant" else 2] = bytes(32)
    elif mutation == "state":
        contract.functions.statementPublication.return_value.call.return_value = (False, 0)
    elif mutation == "stale":
        now = 10000
    else:
        eth.get_transaction_receipt.side_effect = TransactionNotFound("Synthetic provider has no transaction")
    with pytest.raises(PublicationObservationError):
        await reconciler.reconcile("01" * 32, now=now)


async def test_anchor_change_during_reconciliation_rejects_success(case):
    reconciler, eth, _, _, block, anchor, _ = case

    def blocks(number):
        if number == 9:
            return block
        if number == 10:
            return {**anchor, "hash": b"x" * 32}
        return anchor

    eth.get_block.side_effect = blocks
    with pytest.raises(PublicationObservationError, match="anchor changed"):
        await reconciler.reconcile("01" * 32, now=100)


@pytest.mark.parametrize("mutation", [None, "receipt", "nullifier", "statement", "state"])
async def test_mirror_reconciliation_binds_exact_receipt_nullifier_and_state(case, mutation):
    reconciler, _, _, receipt, _, _, contract = case
    retained = reconciler.journal.inspect.return_value
    retained["binding"]["phase"] = "mirror"
    binding = retained["binding"]
    nullifier = "07" * 32
    reconciler.journal.store.get = AsyncMock(return_value={"nullifier": nullifier})
    event = receipt["logs"][0]
    event["topics"] = [
        Web3.keccak(text="AuthorizationMirrored(bytes32,bytes32,bytes32,uint256)"),
        event["topics"][1],
        bytes.fromhex(binding["receipt_id"]),
        bytes.fromhex(nullifier),
    ]
    event["data"] = bytes.fromhex(binding["statement_id"])
    contract.functions.mirroredReceipts.return_value.call = AsyncMock(return_value=bytes.fromhex(binding["receipt_id"]))
    if mutation == "receipt":
        event["topics"][2] = bytes(32)
    elif mutation == "nullifier":
        event["topics"][3] = bytes(32)
    elif mutation == "statement":
        event["data"] = bytes(32)
    elif mutation == "state":
        contract.functions.mirroredReceipts.return_value.call.return_value = bytes(32)
    if mutation:
        with pytest.raises(PublicationObservationError):
            await reconciler.reconcile("01" * 32, now=100)
    else:
        observed = await reconciler.reconcile("01" * 32, now=100)
        assert observed["status"] == "confirmed-success"
        assert observed["registry_effect"] == "receipt-mirrored-at-inclusion"
