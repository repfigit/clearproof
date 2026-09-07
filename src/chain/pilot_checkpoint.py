"""Read approved root heads from an operator-pinned checkpoint deployment."""

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from web3 import AsyncWeb3

from src.protocol.canonical import record_digest
from src.protocol.root_snapshot import RootKind, RootSnapshot, RootTrustError, RootTrustStore, SignedRootSnapshot
from src.protocol.root_snapshot import root_scope_id as root_record_id

HEAD_ABI = [
    {
        "type": "function",
        "name": "head",
        "stateMutability": "view",
        "inputs": [{"name": "tenantHash", "type": "bytes32"}, {"name": "rootScope", "type": "bytes32"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "snapshotDigest", "type": "bytes32"},
                    {"name": "root", "type": "uint256"},
                    {"name": "revision", "type": "uint64"},
                    {"name": "validFrom", "type": "uint64"},
                    {"name": "validUntil", "type": "uint64"},
                    {"name": "publishedAt", "type": "uint64"},
                ],
            }
        ],
    }
]


def tenant_checkpoint_hash(tenant_id: str) -> bytes:
    if type(tenant_id) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", tenant_id):
        raise ValueError("Expected opaque tenant ID")
    return bytes.fromhex(record_digest("clearproof/checkpoint-tenant/v1", tenant_id))


def publication_arguments(
    signed: SignedRootSnapshot, trust: RootTrustStore, *, now: int, expected_revision: int
) -> tuple:
    """Authenticate before constructing arguments for an operator-controlled publisher."""
    snapshot = trust.verify_historical(signed, evaluated_at=now)
    if type(expected_revision) is not int or not 0 <= expected_revision < snapshot.revision:
        raise ValueError("Publication requires a preceding checkpoint revision")
    return (
        tenant_checkpoint_hash(snapshot.tenant_id),
        bytes.fromhex(root_record_id(snapshot)),
        bytes.fromhex(snapshot.digest),
        int(snapshot.root),
        expected_revision,
        snapshot.revision,
        snapshot.issued_at,
        snapshot.expires_at,
    )


@dataclass(frozen=True)
class ObservedRootCheckpoint:
    snapshot: RootSnapshot
    block_number: int
    block_hash: str
    published_at: int


class PilotCheckpointReader:
    def __init__(
        self,
        web3: AsyncWeb3,
        *,
        address: str,
        chain_id: int,
        runtime_sha256: str,
        block_tag: Literal["latest", "safe", "finalized"] = "finalized",
        max_block_age: int = 3600,
    ):
        if type(address) is not str or not re.fullmatch(r"0x[0-9a-f]{40}", address) or address == "0x" + "0" * 40:
            raise ValueError("Expected canonical checkpoint contract address")
        if type(chain_id) is not int or not 1 <= chain_id <= 2**53 - 1:
            raise ValueError("Expected safe integer chain ID")
        if type(runtime_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", runtime_sha256):
            raise ValueError("Expected pinned runtime bytecode SHA-256")
        if (
            block_tag not in ("latest", "safe", "finalized")
            or type(max_block_age) is not int
            or not 1 <= max_block_age <= 86400
        ):
            raise ValueError("Invalid block observation policy")
        self._web3, self._chain_id, self._code_hash = web3, chain_id, runtime_sha256
        self._address = AsyncWeb3.to_checksum_address(address)
        self._tag, self._max_age = block_tag, max_block_age
        self._contract = web3.eth.contract(address=self._address, abi=HEAD_ABI)

    async def verify_current(
        self,
        signed: SignedRootSnapshot,
        trust: RootTrustStore,
        *,
        tenant_id: str,
        registry_address: str,
        now: int,
        kind: RootKind = "issuer-root",
        issuer_did: str | None = None,
    ) -> ObservedRootCheckpoint:
        async with asyncio.timeout(30):
            return await self._observe(
                signed,
                trust,
                tenant_id=tenant_id,
                registry_address=registry_address,
                now=now,
                kind=kind,
                issuer_did=issuer_did,
            )

    async def _observe(
        self,
        signed: SignedRootSnapshot,
        trust: RootTrustStore,
        *,
        tenant_id: str,
        registry_address: str,
        now: int,
        kind: RootKind,
        issuer_did: str | None,
    ) -> ObservedRootCheckpoint:
        snapshot = trust.verify_historical(signed, evaluated_at=now)
        if (
            snapshot.kind != kind
            or snapshot.issuer_did != issuer_did
            or snapshot.tenant_id != tenant_id
            or snapshot.chain_id != self._chain_id
            or snapshot.registry_address != registry_address
        ):
            raise RootTrustError("Checkpoint verification context mismatch")
        if await self._web3.eth.chain_id != self._chain_id:
            raise RootTrustError("Checkpoint RPC chain ID mismatch")
        block = await self._web3.eth.get_block(self._tag)
        number = block["number"]
        if not 0 <= now - block["timestamp"] <= self._max_age:
            raise RootTrustError("Checkpoint block is stale or in the future")
        code = await self._web3.eth.get_code(self._address, block_identifier=number)
        if not code or hashlib.sha256(code).hexdigest() != self._code_hash:
            raise RootTrustError("Checkpoint runtime does not match the approved bytecode")
        head = await self._contract.functions.head(
            tenant_checkpoint_hash(tenant_id), bytes.fromhex(root_record_id(snapshot))
        ).call(block_identifier=number)
        digest, root, revision, valid_from, valid_until, published_at = head
        if (
            bytes(digest).hex() != snapshot.digest
            or root != int(snapshot.root)
            or revision != snapshot.revision
            or valid_from != snapshot.issued_at
            or valid_until != snapshot.expires_at
            or not valid_from <= published_at <= block["timestamp"]
        ):
            raise RootTrustError("Approval does not match the observed chain head")
        confirmed = await self._web3.eth.get_block(number)
        if bytes(confirmed["hash"]) != bytes(block["hash"]):
            raise RootTrustError("Checkpoint observation changed during verification")
        return ObservedRootCheckpoint(snapshot, number, bytes(block["hash"]).hex(), published_at)
