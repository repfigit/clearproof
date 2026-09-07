"""Synthetic PostgreSQL-to-EVM gate. Only an explicitly configured loopback node is allowed."""

import hashlib
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from eth_account import Account
from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.exceptions import ContractLogicError

from src.chain.publication_reconciliation import PublicationChainPolicy, PublicationReconciler
from src.protocol.canonical import record_digest
from src.services.publication_recovery import PublicationRecoveryService
from src.storage.pilot import RecordConflict
from src.storage.publication_journal import PublicationBinding

ROOT = Path(__file__).resolve().parents[2]


def artifact(name):
    return json.loads((ROOT / f"packages/contracts/artifacts/contracts/{name}.sol/{name}.json").read_text())


def g1(point):
    return [int(x) for x in point[:2]]


def g2(point):
    return [[int(row[1]), int(row[0])] for row in point[:2]]


class LocalAuthorizationEVM:
    def __init__(self, url):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
            raise ValueError("Authorization EVM gate requires explicit loopback HTTP")
        self.web3 = AsyncWeb3(AsyncHTTPProvider(url, request_kwargs={"timeout": 10}))

    async def deploy(self, directory):
        assert await self.web3.eth.chain_id == 31337
        self.admin, self.publisher, self.consumer = (await self.web3.eth.accounts)[:3]
        vk = json.loads((directory / "verification-key.json").read_text())
        self.manifest = bytes.fromhex((directory / "development-manifest-pin.txt").read_text().strip())
        pairing_artifact = artifact("PilotGroth16Verifier")
        key = (
            g1(vk["vk_alpha_1"]),
            g2(vk["vk_beta_2"]),
            g2(vk["vk_gamma_2"]),
            g2(vk["vk_delta_2"]),
            [g1(p) for p in vk["IC"]],
        )
        factory = self.web3.eth.contract(abi=pairing_artifact["abi"], bytecode=pairing_artifact["bytecode"])
        deployed = await self.send(factory.constructor(key, self.manifest), self.admin)
        registry = artifact("PilotCurrentRegistry")
        factory = self.web3.eth.contract(abi=registry["abi"], bytecode=registry["bytecode"])
        deployed = await self.send(factory.constructor(self.admin, deployed["contractAddress"]), self.admin)
        self.address = deployed["contractAddress"].lower()
        self.contract = self.web3.eth.contract(address=deployed["contractAddress"], abi=registry["abi"])
        self.runtime_sha256 = hashlib.sha256(await self.web3.eth.get_code(self.contract.address)).hexdigest()

    async def send(self, operation, sender):
        transaction = await operation.transact({"from": sender})
        receipt = await self.web3.eth.wait_for_transaction_receipt(transaction, timeout=30)
        assert receipt["status"] == 1
        return receipt

    async def journal_send(self, operation, sender, phase, statement_id, plan, journal, revalidate):
        # Public Hardhat mnemonic, exclusively for this owned loopback development node.
        Account.enable_unaudited_hdwallet_features()
        index = [self.admin, self.publisher, self.consumer].index(sender)
        signer = Account.from_mnemonic(
            "test test test test test test test test test test test junk", account_path=f"m/44'/60'/0'/0/{index}"
        )
        assert signer.address == sender
        transaction = await operation.build_transaction(
            {"from": sender, "nonce": await self.web3.eth.get_transaction_count(sender, "pending")}
        )
        signed = signer.sign_transaction(transaction)
        semantic_plan = {k: v for k, v in plan.items() if k != "prepared_at"}
        binding = PublicationBinding(
            receipt_id=plan["receipt_id"],
            statement_id=bytes(statement_id).hex(),
            phase=phase,
            chain_id=31337,
            registry=self.address,
            sender=sender.lower(),
            calldata_digest=hashlib.sha256(bytes.fromhex(transaction["data"][2:])).hexdigest(),
            plan_digest=record_digest("clearproof/mirror-plan/v1", semantic_plan),
            runtime_sha256=self.runtime_sha256,
            expires_at=plan["publish_before"],
        )
        identity = await journal.reserve(binding, bytes(signed.raw_transaction), now=int(time.time()))
        assert await journal.reserve(binding, bytes(signed.raw_transaction), now=int(time.time())) == identity
        reconciler = PublicationReconciler(
            self.web3,
            journal,
            PublicationChainPolicy(
                chain_id=31337,
                registry=self.address,
                runtime_sha256=self.runtime_sha256,
                block_tag="latest",
                minimum_confirmations=2,
            ),
        )

        recovery = PublicationRecoveryService(reconciler)

        async def observe():
            now = max(int(time.time()), (await self.web3.eth.get_block("latest"))["timestamp"])
            retained = await recovery.observe(identity, now=now)
            return retained["observation"]

        assert (await observe())["status"] == "not-found"
        sent = []

        async def send(raw):
            sent.append(raw)
            if phase == "mirror":
                raise TimeoutError("Synthetic crash before sending the claimed transaction")
            result = await self.web3.eth.send_raw_transaction(raw)
            if phase == "publish":
                # Node accepted it, but this caller lost the response before recording it.
                raise TimeoutError("Synthetic lost publication response")
            return result

        with pytest.raises(TimeoutError):
            await journal.broadcast_once(identity, revalidate=revalidate, send_raw=send)
        await journal.store._db.close()
        await journal.store._db.connect()
        observed = await journal.inspect(identity)
        assert observed["broadcast_claimed"] and observed["chain_outcome"] == "not-established"
        assert observed["transaction_hash"] == bytes(signed.hash).hex()
        if phase == "mirror":
            now = max(int(time.time()), (await self.web3.eth.get_block("latest"))["timestamp"])
            recovered_hash = await recovery.rebroadcast_missing(
                identity, expected_attempts=1, now=now, revalidate=revalidate
            )
            assert recovered_hash == observed["transaction_hash"]
            assert (await journal.inspect(identity))["broadcast_attempts"] == 2
        else:
            assert observed["broadcast_attempts"] == 1
        included = await self.web3.eth.wait_for_transaction_receipt(
            bytes.fromhex(observed["transaction_hash"]), timeout=30
        )
        assert included["status"] == 1
        assert (await observe())["status"] == "awaiting-confirmations"
        await self.web3.provider.make_request("evm_mine", [])
        confirmed = await observe()
        assert confirmed["status"] == "confirmed-success" and confirmed["confirmations"] == 2
        assert confirmed["registry_effect"] == (
            "statement-published-at-inclusion" if phase == "publish" else "receipt-mirrored-at-inclusion"
        )
        assert confirmed["current_authorization"] == "not-evaluated"
        assert confirmed["resubmission"] == "not-authorized"
        history = await recovery.history.page(identity)
        assert history["current_chain_state"] == "not-established"
        statuses = [row["observation"]["status"] for row in history["items"]]
        assert statuses[-2:] == ["awaiting-confirmations", "confirmed-success"]
        assert all(status == "not-found" for status in statuses[:-2])
        assert history["items"][-1]["sequence"] == len(statuses)
        attempts = (await journal.inspect(identity))["broadcast_attempts"]
        now = max(int(time.time()), (await self.web3.eth.get_block("latest"))["timestamp"])
        with pytest.raises(RecordConflict):
            await recovery.rebroadcast_missing(identity, expected_attempts=attempts, now=now, revalidate=revalidate)
        assert (await journal.inspect(identity))["broadcast_attempts"] == attempts
        with pytest.raises(RecordConflict):
            await journal.broadcast_once(identity, revalidate=revalidate, send_raw=send)
        assert len(sent) == 1

    async def check(self, plan, journal, revalidate):
        assert plan["publication_state"] == "not-published"
        assert plan["consumption_owner"] == "postgresql" and plan["contract_effect"] == "audit-mirror-only"
        assert plan["assurance"] == "development-unapproved"
        assert plan["consumer"].lower() == self.consumer.lower()
        assert int(plan["public_signals"][7]) == int(self.address, 16)
        assert bytes.fromhex(plan["manifest_digest"]) == self.manifest
        tenant, receipt_id = (bytes.fromhex(plan[k]) for k in ("tenant_digest", "receipt_id"))
        fn = self.contract.functions
        await self.send(fn.setPublisher(tenant, self.publisher), self.admin)
        epoch = await fn.publisherEpochs(tenant).call()
        heads = plan["heads"]
        updates = [
            (
                bytes.fromhex(h["scope"]),
                bytes.fromhex(h["digest"]),
                int(h["value"]),
                0,
                h["valid_from"],
                h["valid_until"],
                h["enabled"],
                True,
            )
            for h in heads
        ]
        pins = [(bytes.fromhex(h["scope"]), bytes.fromhex(h["digest"]), 1) for h in heads]
        signals = [int(v) for v in plan["public_signals"]]
        statement = (
            bytes.fromhex(plan["context_digest"]),
            bytes.fromhex(plan["transfer_digest"]),
            signals[0],
            plan["evaluated_at"],
            plan["valid_until"],
            self.consumer,
            pins,
        )
        identity = await fn.statementId(tenant, statement).call()
        assert await fn.statementPublication(identity).call() == [False, 0]
        await self.journal_send(
            fn.publishBatch(tenant, epoch, updates, statement),
            self.publisher,
            "publish",
            identity,
            plan,
            journal,
            revalidate,
        )
        # Read-back works without relying on the publication response or client memory.
        reconnected = self.web3.eth.contract(address=self.contract.address, abi=artifact("PilotCurrentRegistry")["abi"])
        assert await reconnected.functions.statementPublication(identity).call() == [True, epoch]
        proof = plan["proof"]
        args = (tenant, identity, g1(proof["pi_a"]), g2(proof["pi_b"]), g1(proof["pi_c"]), signals)
        assert await fn.inspect(*args).call()
        assert await fn.mirroredReceipts(tenant, signals[3]).call() == bytes(32)
        for bad_receipt, sender in [(bytes(32), self.consumer), (receipt_id, self.publisher)]:
            with pytest.raises((ContractLogicError, ValueError)):
                await fn.mirror(tenant, identity, bad_receipt, *args[2:]).call({"from": sender})
        await self.journal_send(
            fn.mirror(tenant, identity, receipt_id, *args[2:]),
            self.consumer,
            "mirror",
            identity,
            plan,
            journal,
            revalidate,
        )
        assert await reconnected.functions.mirroredReceipts(tenant, signals[3]).call() == receipt_id
        with pytest.raises((ContractLogicError, ValueError)):
            await fn.mirror(tenant, identity, receipt_id, *args[2:]).call({"from": self.consumer})
        # Revoking an attested checkpoint invalidates inspection without erasing audit history.
        head = heads[3]
        await self.send(
            fn.publishHead(
                tenant,
                3,
                bytes.fromhex(head["scope"]),
                bytes.fromhex(head["digest"]),
                0,
                1,
                head["valid_from"],
                head["valid_until"],
                False,
            ),
            self.publisher,
        )
        with pytest.raises((ContractLogicError, ValueError)):
            await fn.inspect(*args).call()
        assert await fn.mirroredReceipts(tenant, signals[3]).call() == receipt_id
        return receipt_id.hex()

    async def close(self):
        await self.web3.provider.disconnect()
