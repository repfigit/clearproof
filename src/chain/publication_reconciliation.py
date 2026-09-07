"""Read-only publication reconciliation against an independently pinned chain and runtime."""

import asyncio
import hashlib
from typing import Literal

from pydantic import Field
from web3 import Web3
from web3.exceptions import TransactionNotFound

from src.protocol.canonical import record_digest
from src.protocol.transfer import Address, Hex32, Record
from src.storage.publication_journal import PublicationBinding

STATE_ABI = [
    {
        "type": "function",
        "name": "statementPublication",
        "stateMutability": "view",
        "inputs": [{"name": "id", "type": "bytes32"}],
        "outputs": [{"name": "exists", "type": "bool"}, {"name": "epoch", "type": "uint64"}],
    },
    {
        "type": "function",
        "name": "mirroredReceipts",
        "stateMutability": "view",
        "inputs": [{"name": "tenant", "type": "bytes32"}, {"name": "nullifier", "type": "uint256"}],
        "outputs": [{"name": "receipt", "type": "bytes32"}],
    },
]


class PublicationChainPolicy(Record):
    chain_id: int = Field(strict=True, ge=1, le=2**53 - 1)
    registry: Address
    runtime_sha256: Hex32
    block_tag: Literal["latest", "safe", "finalized"] = "finalized"
    minimum_confirmations: int = Field(strict=True, ge=1, le=10000, default=1)
    max_block_age: int = Field(strict=True, ge=1, le=86400, default=3600)


class PublicationObservationError(ValueError):
    """RPC observations are inconsistent with the approved deployment or retained transaction."""


class PublicationReconciler:
    def __init__(self, web3, journal, policy: PublicationChainPolicy):
        self.web3, self.journal = web3, journal
        self.policy = PublicationChainPolicy.model_validate(policy)
        if int(self.policy.registry, 16) == 0:
            raise ValueError("A deployed registry is required")
        self.address = Web3.to_checksum_address(self.policy.registry)
        self.contract = web3.eth.contract(address=self.address, abi=STATE_ABI)

    async def reconcile(self, identity: str, *, now: int) -> dict:
        async with asyncio.timeout(30):
            return await self._observe(identity, now=now)

    async def _code(self, number):
        code = await self.web3.eth.get_code(self.address, block_identifier=number)
        if not code or hashlib.sha256(code).hexdigest() != self.policy.runtime_sha256:
            raise PublicationObservationError("Publication runtime differs from independent policy")

    async def _observe(self, identity, *, now):
        if type(now) is not int or not 0 <= now < 2**53:
            raise PublicationObservationError("Invalid observation clock")
        retained = await self.journal.inspect(identity)
        if retained is None:
            raise PublicationObservationError("Retained publication is unavailable")
        binding = PublicationBinding.model_validate(retained["binding"])
        if (
            binding.chain_id != self.policy.chain_id
            or binding.registry != self.policy.registry
            or binding.runtime_sha256 != self.policy.runtime_sha256
            or await self.web3.eth.chain_id != self.policy.chain_id
        ):
            raise PublicationObservationError("Publication chain or deployment scope differs")
        anchor = await self.web3.eth.get_block(self.policy.block_tag)
        if not 0 <= now - anchor["timestamp"] <= self.policy.max_block_age:
            raise PublicationObservationError("Observation block is stale or in the future")
        await self._code(anchor["number"])
        expected_hash = bytes.fromhex(retained["transaction_hash"])
        report = dict(
            schema_version="clearproof-publication-observation-v1",
            intent_id=identity,
            transaction_hash=retained["transaction_hash"],
            phase=binding.phase,
            anchor_number=anchor["number"],
            anchor_hash=bytes(anchor["hash"]).hex(),
            block_tag=self.policy.block_tag,
            minimum_confirmations=self.policy.minimum_confirmations,
            confirmations=0,
            execution="not-established",
            registry_effect="not-established",
            current_authorization="not-evaluated",
            resubmission="not-authorized",
        )
        try:
            transaction = await self.web3.eth.get_transaction(expected_hash)
        except TransactionNotFound:
            # Absence at this provider cannot establish that the account nonce is safe to reuse.
            report["status"] = "not-found"
            return await self._stable(report, anchor)
        if (
            bytes(transaction["hash"]) != expected_hash
            or transaction["from"].lower() != binding.sender
            or transaction["to"] is None
            or transaction["to"].lower() != binding.registry
            or transaction["chainId"] != binding.chain_id
            or transaction["nonce"] != retained["account_nonce"]
            or transaction["value"] != 0
            or hashlib.sha256(bytes(transaction["input"])).hexdigest() != binding.calldata_digest
        ):
            raise PublicationObservationError("Observed transaction differs from retained signed intent")
        try:
            receipt = await self.web3.eth.get_transaction_receipt(expected_hash)
        except TransactionNotFound:
            if transaction["blockHash"] is not None or transaction["blockNumber"] is not None:
                raise PublicationObservationError("Mined transaction has no receipt in this observation")
            report["status"] = "pending"
            return await self._stable(report, anchor)
        if (
            bytes(receipt["transactionHash"]) != expected_hash
            or receipt["status"] not in (0, 1)
            or receipt["from"].lower() != binding.sender
            or receipt["to"] is None
            or receipt["to"].lower() != binding.registry
            or receipt["blockNumber"] != transaction["blockNumber"]
            or receipt["blockHash"] != transaction["blockHash"]
        ):
            raise PublicationObservationError("Receipt does not match retained transaction inclusion")
        inclusion = await self.web3.eth.get_block(receipt["blockNumber"])
        report.update(inclusion_number=inclusion["number"], inclusion_hash=bytes(receipt["blockHash"]).hex())
        if receipt["blockHash"] != inclusion["hash"]:
            report["status"] = "noncanonical"
            return await self._stable(report, anchor)
        index = receipt["transactionIndex"]
        if not 0 <= index < len(inclusion["transactions"]) or bytes(inclusion["transactions"][index]) != expected_hash:
            raise PublicationObservationError("Canonical block does not contain the retained transaction at its index")
        await self._code(inclusion["number"])
        report["confirmations"] = max(0, anchor["number"] - inclusion["number"] + 1)
        report["execution"] = "succeeded" if receipt["status"] == 1 else "reverted"
        report["status"] = (
            ("confirmed-success" if receipt["status"] == 1 else "confirmed-failure")
            if report["confirmations"] >= self.policy.minimum_confirmations
            else "awaiting-confirmations"
        )
        if receipt["status"] == 1:
            report["registry_effect"] = await self._effect(binding, receipt, inclusion["number"])
        # Read both headers and the receipt again; a changed view yields no stable success claim.
        confirmed = await self.web3.eth.get_block(inclusion["number"])
        if confirmed["hash"] != inclusion["hash"]:
            raise PublicationObservationError("Inclusion changed during reconciliation")
        checked = await self.web3.eth.get_transaction_receipt(expected_hash)
        if checked != receipt:
            raise PublicationObservationError("Receipt changed during reconciliation")
        return await self._stable(report, anchor)

    async def _effect(self, binding, receipt, number):
        tenant = bytes.fromhex(
            record_digest("clearproof/tenant-checkpoint/v1", {"tenant_id": self.journal.store.tenant_id})
        )
        statement = bytes.fromhex(binding.statement_id)
        if binding.phase == "publish":
            topic = bytes(Web3.keccak(text="StatementPublished(bytes32,bytes32,bytes32)"))
        else:
            topic = bytes(Web3.keccak(text="AuthorizationMirrored(bytes32,bytes32,bytes32,uint256)"))
        logs = [
            log
            for log in receipt["logs"]
            if log["address"].lower() == self.policy.registry and log["topics"] and bytes(log["topics"][0]) == topic
        ]
        if len(logs) != 1:
            raise PublicationObservationError("Expected exact registry event is absent or ambiguous")
        log = logs[0]
        topics = [bytes(value) for value in log["topics"]]
        if log.get("removed", False) or len(topics) != (3 if binding.phase == "publish" else 4) or topics[1] != tenant:
            raise PublicationObservationError("Registry event scope differs")
        if binding.phase == "publish":
            if topics[2] != statement or len(log["data"]) != 32:
                raise PublicationObservationError("Published statement identity differs")
            exists, epoch = await self.contract.functions.statementPublication(statement).call(block_identifier=number)
            if not exists or epoch < 1:
                raise PublicationObservationError("Published statement is absent from registry state")
            return "statement-published-at-inclusion"
        receipt_id = bytes.fromhex(binding.receipt_id)
        if topics[2] != receipt_id or bytes(log["data"]) != statement:
            raise PublicationObservationError("Mirrored receipt identity differs")
        source = await self.journal.store.get("receipt", binding.receipt_id)
        if source is None or topics[3].hex() != source["nullifier"]:
            raise PublicationObservationError("Mirror does not bind the retained receipt nullifier")
        mirrored = await self.contract.functions.mirroredReceipts(tenant, int(source["nullifier"], 16)).call(
            block_identifier=number
        )
        if bytes(mirrored) != receipt_id:
            raise PublicationObservationError("Receipt mirror is absent from registry state")
        return "receipt-mirrored-at-inclusion"

    async def _stable(self, report, anchor):
        current = await self.web3.eth.get_block(anchor["number"])
        if current["hash"] != anchor["hash"]:
            raise PublicationObservationError("Observation anchor changed during reconciliation")
        return report
