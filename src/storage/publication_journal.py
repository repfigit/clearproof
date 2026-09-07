"""Encrypted write-ahead transaction identity. Source approval and finality remain writer responsibilities."""

import hashlib
from typing import Literal

from eth_account import Account
from eth_account.typed_transactions import TypedTransaction
from hexbytes import HexBytes
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from pydantic import Field, model_validator
from web3 import Web3

from src.protocol.canonical import record_digest
from src.protocol.transfer import Address, Epoch, Hex32, Record
from src.storage.pilot import PilotStore, RecordConflict


class PublicationBinding(Record):
    receipt_id: Hex32
    statement_id: Hex32
    phase: Literal["publish", "mirror"]
    chain_id: int = Field(strict=True, ge=1, le=2**53 - 1)
    registry: Address
    sender: Address
    calldata_digest: Hex32
    plan_digest: Hex32
    runtime_sha256: Hex32
    expires_at: Epoch

    @model_validator(mode="after")
    def nonzero(self):
        if int(self.registry, 16) == 0 or int(self.sender, 16) == 0:
            raise ValueError("Publication requires configured registry and sender")
        return self


def signed_identity(binding: PublicationBinding, raw: bytes) -> tuple[str, int]:
    """Bounded EIP-1559 profile, exact destination/calldata, no transferred value."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 16384 or raw[0] != 2:
        raise ValueError("Publication requires a bounded signed type-2 transaction")
    try:
        transaction = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
        sender = Account.recover_transaction(raw).lower()
    except Exception:
        raise ValueError("Invalid signed publication transaction") from None
    nonce = transaction["nonce"]
    if (
        transaction["chainId"] != binding.chain_id
        or sender != binding.sender
        or bytes(transaction["to"]).hex() != binding.registry[2:]
        or transaction["value"] != 0
        or hashlib.sha256(transaction["data"]).hexdigest() != binding.calldata_digest
        or not 0 <= nonce <= 2**53 - 1
    ):
        raise ValueError("Signed transaction does not match the approved publication binding")
    return bytes(Web3.keccak(raw)).hex(), nonce


class PublicationJournal:
    """Operator-only persistence, never an authority for source approval or chain inclusion."""

    def __init__(self, db, cipher, principal):
        self.store = PilotStore(db, cipher, principal)
        self.principal, self.cipher = principal, cipher

    def _require(self):
        for role in ("tenant:admin", "evidence:decrypt", "proof:inspect"):
            self.principal.require(role)

    async def reserve(self, binding: PublicationBinding, raw: bytes, *, now: int) -> str:
        self._require()
        binding = PublicationBinding.model_validate(binding)
        if type(now) is not int or not 0 <= now < binding.expires_at:
            raise ValueError("Publication intent is not current")
        transaction_hash, nonce = signed_identity(binding, raw)
        identity = record_digest(
            "clearproof/publication-intent/v1",
            {
                "tenant_id": self.store.tenant_id,
                "binding": binding.model_dump(mode="json"),
                "transaction_hash": transaction_hash,
            },
        )
        value = {
            "binding": binding.model_dump(mode="json"),
            "transaction_hash": transaction_hash,
            "raw_chunks": [raw.hex()[i : i + 4096] for i in range(0, len(raw) * 2, 4096)],
        }
        async with self.store.transaction() as tx:
            receipt = await tx.get("receipt", binding.receipt_id)
            if (
                receipt is None
                or record_digest("clearproof/local-authorization/v1", receipt) != binding.receipt_id
                or receipt.get("tenant_id") != tx.tenant_id
                or receipt.get("outcome") != "ALLOW"
                or binding.expires_at > receipt["expires_at"]
                or await tx.consumed_proof_id(receipt["nullifier"]) != receipt["proof_id"]
            ):
                raise ValueError("Publication requires an existing consumed receipt")
            existing = await self._row(tx, identity)
            if existing:
                if self._open(identity, existing) != value:
                    raise RecordConflict("Publication intent differs from retained transaction")
                return identity
            sealed = self.cipher.seal(tx.tenant_id, "publication-intent", identity, 1, value)
            try:
                await tx._conn.execute(
                    "INSERT INTO pilot_publications "
                    "(tenant_id,intent_id,receipt_id,phase,chain_id,sender,nonce,key_id,content_tag,"
                    "cipher_nonce,ciphertext) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        tx.tenant_id,
                        identity,
                        binding.receipt_id,
                        binding.phase,
                        binding.chain_id,
                        binding.sender,
                        nonce,
                        sealed["key_id"],
                        sealed["content_tag"],
                        sealed["nonce"],
                        sealed["ciphertext"],
                    ),
                )
            except UniqueViolation:
                raise RecordConflict("Publication phase or account nonce is already reserved") from None
        return identity

    async def _row(self, tx, identity):
        # Validate selectors even for read-only reconciliation of expired intents.
        if type(identity) is not str or len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise ValueError("Expected canonical publication intent ID")
        async with tx._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM pilot_publications WHERE tenant_id=%s AND intent_id=%s", (tx.tenant_id, identity)
            )
            return await cur.fetchone()

    def _open(self, identity, row):
        value = self.cipher.open(
            self.store.tenant_id, "publication-intent", identity, {**row, "nonce": row["cipher_nonce"], "revision": 1}
        )
        binding = PublicationBinding.model_validate(value["binding"])
        raw = bytes.fromhex("".join(value["raw_chunks"]))
        transaction_hash, nonce = signed_identity(binding, raw)
        expected = record_digest(
            "clearproof/publication-intent/v1",
            {
                "tenant_id": self.store.tenant_id,
                "binding": binding.model_dump(mode="json"),
                "transaction_hash": transaction_hash,
            },
        )
        if (
            identity != expected
            or value["transaction_hash"] != transaction_hash
            or nonce != row["nonce"]
            or binding.receipt_id != row["receipt_id"]
            or binding.phase != row["phase"]
            or binding.chain_id != row["chain_id"]
            or binding.sender != row["sender"]
        ):
            raise ValueError("Retained publication binding is inconsistent")
        return value

    async def inspect(self, identity):
        self._require()
        async with self.store.transaction() as tx:
            row = await self._row(tx, identity)
            if row is None:
                return None
            value = self._open(identity, row)
            return {
                "intent_id": identity,
                "binding": value["binding"],
                "transaction_hash": value["transaction_hash"],
                "broadcast_claimed": row["broadcast_claimed"],
                "account_nonce": row["nonce"],
                "chain_outcome": "not-established",
            }

    async def broadcast_once(self, identity, *, revalidate, send_raw):
        """Claim before RPC. Any lost response remains uncertain; no implicit retry or fee replacement."""
        self._require()
        observed = await self.inspect(identity)
        if observed is None:
            raise ValueError("Publication intent is unavailable")
        if observed["broadcast_claimed"]:
            raise RecordConflict("Publication was already claimed; reconcile its transaction hash")
        # Independent writer rechecks source evidence, destination/code, clock and chain state here.
        await revalidate(PublicationBinding.model_validate(observed["binding"]))
        async with self.store.transaction() as tx:
            row = await self._row(tx, identity)
            value = self._open(identity, row)
            if row["broadcast_claimed"]:
                raise RecordConflict("Publication was already claimed; reconcile its transaction hash")
            await tx._conn.execute(
                "UPDATE pilot_publications SET broadcast_claimed=true WHERE tenant_id=%s AND intent_id=%s",
                (tx.tenant_id, identity),
            )
            raw = bytes.fromhex("".join(value["raw_chunks"]))
        # The committed claim survives a crash before or after this call. Never clear it on an exception.
        result = await send_raw(raw)
        if bytes(HexBytes(result)).hex() != value["transaction_hash"]:
            raise ValueError("RPC did not confirm the retained transaction hash; reconcile before proceeding")
        return value["transaction_hash"]
