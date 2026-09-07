"""Persist fresh reconciliation evidence without converting history into current authorization."""

import asyncio

from src.protocol.canonical import record_digest
from src.storage.publication_history import PublicationHistory


class PublicationRecoveryService:
    def __init__(self, reconciler):
        self.reconciler = reconciler
        self.history = PublicationHistory(reconciler.journal)

    async def observe(self, identity: str, *, now: int):
        # Do not persist a guessed failure when RPC/pin/current-observation validation raises.
        policy = self.reconciler.policy
        observation = await self.reconciler.reconcile(identity, now=now)
        if (
            self.reconciler.policy != policy
            or observation["block_tag"] != policy.block_tag
            or observation["minimum_confirmations"] != policy.minimum_confirmations
        ):
            raise ValueError("Reconciliation policy changed or differs from the observation")
        policy_digest = record_digest("clearproof/publication-chain-policy/v1", policy.model_dump(mode="json"))
        return await self.history.append(identity, observation, policy_digest=policy_digest, observed_at=now)

    async def rebroadcast_missing(self, identity, *, expected_attempts: int, now: int, revalidate):
        """Recover a missing transaction using identical bytes after fresh policy, nonce and simulation checks."""
        async with asyncio.timeout(30):
            return await self._rebroadcast_missing(
                identity, expected_attempts=expected_attempts, now=now, revalidate=revalidate
            )

    async def _rebroadcast_missing(self, identity, *, expected_attempts, now, revalidate):
        import hashlib

        from eth_account.typed_transactions import TypedTransaction
        from hexbytes import HexBytes
        from web3 import Web3

        from src.storage.pilot import RecordConflict

        journal, web3 = self.reconciler.journal, self.reconciler.web3
        journal._require()
        if type(expected_attempts) is not int or not 1 <= expected_attempts <= 2:
            raise ValueError("Expected one of the two remaining recovery attempts")
        retained = await journal.inspect(identity)
        if retained is None or retained["broadcast_attempts"] != expected_attempts:
            raise RecordConflict("Recovery attempt differs from retained journal; inspect it again")

        async def preflight(binding):
            if type(now) is not int or not 0 <= now < binding.expires_at:
                raise ValueError("Publication recovery window has expired")
            policy = self.reconciler.policy
            observed = await self.observe(identity, now=now)
            if observed["observation"]["status"] != "not-found":
                raise RecordConflict("Only a freshly missing transaction can be explicitly rebroadcast")
            await revalidate(binding)
            if self.reconciler.policy != policy:
                raise ValueError("Recovery policy changed during source validation")
            address = Web3.to_checksum_address(binding.registry)
            sender = Web3.to_checksum_address(binding.sender)
            latest = await web3.eth.get_block("latest")
            if not 0 <= now - latest["timestamp"] <= policy.max_block_age:
                raise ValueError("Recovery head is stale or in the future")
            if (
                await web3.eth.chain_id != binding.chain_id
                or hashlib.sha256(await web3.eth.get_code(address, block_identifier=latest["number"])).hexdigest()
                != policy.runtime_sha256
            ):
                raise ValueError("Recovery deployment differs from pinned policy")
            for tag in (latest["number"], "pending"):
                if await web3.eth.get_transaction_count(sender, tag) != retained["account_nonce"]:
                    raise RecordConflict(
                        "Account nonce advanced or has another pending transaction; reconcile manually"
                    )
            async with journal.store.transaction() as tx:
                row = await journal._row(tx, identity)
                value = journal._open(identity, row)
                raw = bytes.fromhex("".join(value["raw_chunks"]))
            transaction = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
            await web3.eth.call(
                {"from": sender, "to": address, "data": transaction["data"], "gas": transaction["gas"], "value": 0},
                block_identifier=latest["number"],
            )
            checked = await web3.eth.get_block(latest["number"])
            if checked["hash"] != latest["hash"] or self.reconciler.policy != policy:
                raise ValueError("Recovery chain or policy changed during preflight")

        return await journal.rebroadcast_once(
            identity, expected_attempts=expected_attempts, revalidate=preflight, send_raw=web3.eth.send_raw_transaction
        )
