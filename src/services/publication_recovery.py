"""Persist fresh reconciliation evidence without converting history into current authorization."""

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
