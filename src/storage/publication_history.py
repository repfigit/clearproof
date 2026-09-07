"""Encrypted append-only history of publication observations; no automatic recovery actions."""

from typing import Literal

from psycopg.rows import dict_row
from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.transfer import Epoch, Hex32, Record
from src.storage.pilot import RecordConflict


class PublicationObservation(Record):
    schema_version: Literal["clearproof-publication-observation-v1"]
    intent_id: Hex32
    transaction_hash: Hex32
    phase: Literal["publish", "mirror"]
    anchor_number: Epoch
    anchor_hash: Hex32
    block_tag: Literal["latest", "safe", "finalized"]
    minimum_confirmations: int = Field(strict=True, ge=1, le=10000)
    confirmations: int = Field(strict=True, ge=0, le=2**53 - 1)
    execution: Literal["not-established", "succeeded", "reverted"]
    registry_effect: Literal["not-established", "statement-published-at-inclusion", "receipt-mirrored-at-inclusion"]
    current_authorization: Literal["not-evaluated"]
    resubmission: Literal["not-authorized"]
    status: Literal[
        "not-found", "pending", "noncanonical", "awaiting-confirmations", "confirmed-success", "confirmed-failure"
    ]
    inclusion_number: Epoch | None = None
    inclusion_hash: Hex32 | None = None

    @model_validator(mode="after")
    def coherent(self):
        missing = self.status in ("not-found", "pending")
        unestablished = missing or self.status == "noncanonical"
        if missing != (self.inclusion_number is None and self.inclusion_hash is None):
            raise ValueError("Observation inclusion fields do not match its status")
        if not missing and (self.inclusion_number is None or self.inclusion_hash is None):
            raise ValueError("Included observation requires complete inclusion identity")
        if unestablished:
            if (
                self.confirmations != 0
                or self.execution != "not-established"
                or self.registry_effect != "not-established"
            ):
                raise ValueError("Unestablished inclusion cannot claim execution or registry effect")
        else:
            if self.confirmations != max(0, self.anchor_number - self.inclusion_number + 1):
                raise ValueError("Confirmation count does not match observation blocks")
            confirmed = self.confirmations >= self.minimum_confirmations
            if (self.status == "awaiting-confirmations") == confirmed:
                raise ValueError("Confirmation policy does not match observation status")
            success = self.execution == "succeeded"
            if self.execution == "not-established" or (
                confirmed and self.status != ("confirmed-success" if success else "confirmed-failure")
            ):
                raise ValueError("Observed execution does not match its status")
            effect = (
                ("statement-published-at-inclusion" if self.phase == "publish" else "receipt-mirrored-at-inclusion")
                if success
                else "not-established"
            )
            if self.registry_effect != effect:
                raise ValueError("Registry effect does not match execution and phase")
        return self


class PublicationHistory:
    def __init__(self, journal):
        self.journal = journal

    async def _rows(self, tx, identity, *, after, limit):
        async with tx._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM pilot_publication_observations WHERE tenant_id=%s AND intent_id=%s "
                "AND sequence>%s ORDER BY sequence LIMIT %s",
                (tx.tenant_id, identity, after, limit),
            )
            return await cur.fetchall()

    def _open(self, row):
        identity = row["observation_id"]
        value = self.journal.cipher.open(
            self.journal.store.tenant_id,
            "publication-observation",
            identity,
            {**row, "nonce": row["cipher_nonce"], "revision": 1},
        )
        if (
            record_digest("clearproof/publication-observation/v1", value) != identity
            or value["tenant_id"] != self.journal.store.tenant_id
            or value["intent_id"] != row["intent_id"]
            or value["sequence"] != row["sequence"]
            or value["previous_observation_id"] != row["previous_observation_id"]
        ):
            raise ValueError("Publication history identity differs from retained evidence")
        PublicationObservation.model_validate(value["observation"])
        return {"observation_id": identity, **value}

    async def append(self, identity, observation, *, policy_digest: str, observed_at: int):
        self.journal._require()
        parsed = PublicationObservation.model_validate(observation)
        if parsed.intent_id != identity or type(observed_at) is not int or not 0 <= observed_at < 2**53:
            raise ValueError("Publication history scope or clock is invalid")

        # Validate the independently captured policy identifier using the existing canonical hash type.
        class PolicyPin(Record):
            digest: Hex32

        PolicyPin(digest=policy_digest)
        observation = parsed.model_dump(mode="json", exclude_none=True)
        async with self.journal.store.transaction() as tx:
            intent = await self.journal._row(tx, identity)
            if intent is None:
                raise ValueError("Publication intent is unavailable")
            retained = self.journal._open(identity, intent)
            if parsed.transaction_hash != retained["transaction_hash"] or parsed.phase != retained["binding"]["phase"]:
                raise ValueError("Observation does not bind the retained transaction")
            async with tx._conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    "SELECT * FROM pilot_publication_observations WHERE tenant_id=%s AND intent_id=%s "
                    "ORDER BY sequence DESC LIMIT 1",
                    (tx.tenant_id, identity),
                )
                row = await cur.fetchone()
            previous = self._open(row) if row else None
            if previous:
                if observed_at < previous["observed_at"]:
                    raise RecordConflict("Observation clock precedes retained history; obtain a fresh observation")
                if (
                    observed_at == previous["observed_at"]
                    and policy_digest == previous["policy_digest"]
                    and observation == previous["observation"]
                ):
                    return previous
            value = dict(
                schema_version="clearproof-publication-history-v1",
                tenant_id=tx.tenant_id,
                intent_id=identity,
                sequence=previous["sequence"] + 1 if previous else 1,
                previous_observation_id=previous["observation_id"] if previous else None,
                observed_at=observed_at,
                policy_digest=policy_digest,
                observation=observation,
            )
            record_id = record_digest("clearproof/publication-observation/v1", value)
            sealed = self.journal.cipher.seal(tx.tenant_id, "publication-observation", record_id, 1, value)
            await tx._conn.execute(
                "INSERT INTO pilot_publication_observations "
                "(tenant_id,intent_id,sequence,observation_id,previous_observation_id,key_id,content_tag,"
                "cipher_nonce,ciphertext) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    tx.tenant_id,
                    identity,
                    value["sequence"],
                    record_id,
                    value["previous_observation_id"],
                    sealed["key_id"],
                    sealed["content_tag"],
                    sealed["nonce"],
                    sealed["ciphertext"],
                ),
            )
            return {"observation_id": record_id, **value}

    async def page(self, identity, *, after: int = 0, limit: int = 32):
        self.journal._require()
        if type(after) is not int or not 0 <= after < 2**53 or type(limit) is not int or not 1 <= limit <= 64:
            raise ValueError("Invalid publication history page")
        async with self.journal.store.transaction() as tx:
            await self.journal._row(tx, identity)  # Validate tenant-bound selector even on empty history.
            prior = await self._rows(tx, identity, after=after - 1, limit=1) if after else []
            if after and (not prior or prior[0]["sequence"] != after):
                raise ValueError("History cursor does not identify a retained observation")
            previous = self._open(prior[0]) if prior else None
            rows = await self._rows(tx, identity, after=after, limit=limit + 1)
            items = []
            for row in rows[:limit]:
                value = self._open(row)
                if value["sequence"] != (previous["sequence"] + 1 if previous else 1) or value[
                    "previous_observation_id"
                ] != (previous["observation_id"] if previous else None):
                    raise ValueError("Publication history chain is incomplete")
                items.append(value)
                previous = value
            return dict(
                schema_version="clearproof-publication-history-page-v1",
                scope="retained-observations",
                current_chain_state="not-established",
                items=items,
                next_after=items[-1]["sequence"] if len(rows) > limit else None,
            )
