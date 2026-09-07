"""Read on-chain state from VASPRegistry, SanctionsOracle, ComplianceRegistry.

All reads use eth_call (no gas, no tx).
Each reader owns a bounded in-memory cache for its immutable deployment configuration.
"""

import asyncio
import json
import logging
import math
import os
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from copy import deepcopy
from pathlib import Path
from time import monotonic
from types import MappingProxyType
from typing import Any

from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

logger = logging.getLogger(__name__)

_ABI_DIR = Path(__file__).parent / "abis"

_MISSING = object()


def _load_abi(name: str) -> list[dict]:
    """Load a contract ABI from the abis/ directory."""
    abi_path = _ABI_DIR / f"{name}.json"
    with open(abi_path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_reader_instance: "ChainReader | None" = None


def get_chain_reader() -> "ChainReader":
    """Return a module-level ChainReader configured from env vars.

    Required env vars:
        CHAIN_RPC_URL — Ethereum JSON-RPC endpoint
        VASP_REGISTRY_ADDRESS — VASPRegistry contract address
        SANCTIONS_ORACLE_ADDRESS — SanctionsOracle contract address
        COMPLIANCE_REGISTRY_ADDRESS — ComplianceRegistry contract address
    """
    global _reader_instance
    rpc_url = os.environ.get("CHAIN_RPC_URL", "http://127.0.0.1:8545")
    contracts = {
        "vasp_registry": os.environ.get("VASP_REGISTRY_ADDRESS", ""),
        "sanctions_oracle": os.environ.get("SANCTIONS_ORACLE_ADDRESS", ""),
        "compliance_registry": os.environ.get("COMPLIANCE_REGISTRY_ADDRESS", ""),
    }
    ttl = float(os.getenv("CHAIN_CACHE_TTL", "30"))
    if (
        _reader_instance is None
        or _reader_instance._rpc_url != rpc_url
        or _reader_instance._addresses != contracts
        or _reader_instance._cache_ttl != ttl
    ):
        _reader_instance = ChainReader(rpc_url, contracts, cache_ttl=ttl)
    return _reader_instance


class ChainReader:
    """Read on-chain compliance state with deployment-local caching.

    All reads use eth_call (no gas, no tx).
    Results are cached with configurable TTL.
    """

    def __init__(
        self, rpc_url: str, contracts: dict[str, str], *, cache_ttl: float | None = None, max_cache_entries: int = 512
    ) -> None:
        """
        Args:
            rpc_url: Ethereum RPC endpoint.
            contracts: Mapping of contract name to deployed address, e.g.
                {"vasp_registry": "0x...", "sanctions_oracle": "0x...", "compliance_registry": "0x..."}.
        """
        ttl = float(os.getenv("CHAIN_CACHE_TTL", "30")) if cache_ttl is None else float(cache_ttl)
        if not math.isfinite(ttl) or ttl < 0:
            raise ValueError("Chain cache TTL must be finite and nonnegative")
        if type(max_cache_entries) is not int or max_cache_entries < 1:
            raise ValueError("Chain cache entry limit must be a positive integer")
        self._rpc_url = rpc_url
        self._w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
        self._addresses = MappingProxyType(contracts.copy())
        self._contracts: dict[str, Any] = {}
        self._cache_ttl = ttl
        self._max_cache_entries = max_cache_entries
        self._cache: OrderedDict[tuple, tuple[float, Any]] = OrderedDict()
        self._generation = 0
        self._inflight: dict[tuple, asyncio.Task] = {}

    def invalidate_cache(self) -> None:
        """Discard cached observations after state changes or a detected reorganization.

        Earlier in-flight requests may still return to their original callers, but
        cannot refill the cache or be joined by callers after invalidation.
        """
        self._generation += 1
        self._cache.clear()

    async def _read_cached(self, key: tuple, fetch: Callable[[], Awaitable[Any]]) -> Any:
        if self._cache_ttl == 0:
            return await fetch()
        cached = self._cache.get(key, _MISSING)
        if cached is not _MISSING:
            expires_at, value = cached
            if monotonic() < expires_at:
                self._cache.move_to_end(key)
                return deepcopy(value)
            del self._cache[key]

        generation = self._generation
        inflight_key = (generation, key)
        task = self._inflight.get(inflight_key)
        if task is None or task.done():

            async def load():
                # Network time counts against the TTL; a slow reply cannot extend it.
                expires_at = monotonic() + self._cache_ttl
                value = await fetch()
                if generation == self._generation and monotonic() < expires_at:
                    self._cache[key] = (expires_at, deepcopy(value))
                    self._cache.move_to_end(key)
                    while len(self._cache) > self._max_cache_entries:
                        self._cache.popitem(last=False)
                return value

            task = asyncio.create_task(load())
            self._inflight[inflight_key] = task

            def finished(done):
                if self._inflight.get(inflight_key) is done:
                    self._inflight.pop(inflight_key)
                # Retrieve errors even if every waiter cancels.
                if not done.cancelled():
                    done.exception()

            task.add_done_callback(finished)
        return deepcopy(await asyncio.shield(task))

    @staticmethod
    def _hash_bytes(value: str) -> bytes:
        if not isinstance(value, str):
            raise ValueError("Chain identifier must be a 32-byte hexadecimal value")
        encoded = value[2:] if value[:2].lower() == "0x" else value
        if len(encoded) != 64:
            raise ValueError("Chain identifier must be a 32-byte hexadecimal value")
        try:
            raw = bytes.fromhex(encoded)
        except ValueError:
            raise ValueError("Chain identifier must be a 32-byte hexadecimal value") from None
        if len(raw) != 32:
            raise ValueError("Chain identifier must be a 32-byte hexadecimal value")
        return raw

    @staticmethod
    def _root_hex(value: bytes) -> str:
        if not isinstance(value, bytes) or len(value) != 32:
            raise ValueError("Chain root must contain exactly 32 bytes")
        return "0x" + value.hex()

    # -- lazy contract helpers -------------------------------------------------

    def _get_contract(self, name: str, abi_name: str) -> Any:
        """Return a web3 contract instance, creating it lazily."""
        if name not in self._contracts:
            address = self._addresses.get(name, "")
            if not address:
                raise RuntimeError(f"Contract address for '{name}' not configured")
            abi = _load_abi(abi_name)
            self._contracts[name] = self._w3.eth.contract(
                address=self._w3.to_checksum_address(address),
                abi=abi,
            )
        return self._contracts[name]

    @property
    def _sanctions_oracle(self) -> Any:
        return self._get_contract("sanctions_oracle", "SanctionsOracle")

    @property
    def _vasp_registry(self) -> Any:
        return self._get_contract("vasp_registry", "VASPRegistry")

    @property
    def _compliance_registry(self) -> Any:
        return self._get_contract("compliance_registry", "ComplianceRegistry")

    # -- public read methods ---------------------------------------------------

    async def get_sanctions_root(self) -> str:
        """Read current sanctions Merkle root from SanctionsOracle."""

        async def fetch():
            return self._root_hex(await self._sanctions_oracle.functions.currentRoot().call())

        return await self._read_cached(("sanctions_root",), fetch)

    async def is_sanctions_stale(self) -> bool:
        """Check if sanctions root is past grace period."""
        return await self._read_cached(("sanctions_stale",), self._sanctions_oracle.functions.isStale().call)

    async def get_issuer_root(self) -> str:
        """Read current issuer Merkle root from VASPRegistry."""

        async def fetch():
            return self._root_hex(await self._vasp_registry.functions.issuerMerkleRoot().call())

        return await self._read_cached(("issuer_root",), fetch)

    async def is_vasp_active(self, did_hash: str) -> bool:
        """Check if a VASP is registered and active.

        Args:
            did_hash: keccak256 hash of the VASP DID (hex string, 0x-prefixed).
        """
        did_bytes = self._hash_bytes(did_hash)
        return await self._read_cached(
            ("vasp_active", did_bytes), self._vasp_registry.functions.isActive(did_bytes).call
        )

    async def get_vasp_info(self, did: str) -> tuple:
        """Observe the selected registry's record with instance-scoped caching."""
        if not isinstance(did, str) or not did.startswith("did:web:") or len(did) > 1024:
            raise ValueError("Invalid VASP DID")
        did_hash = self._w3.keccak(text=did)

        async def fetch():
            record = await self._vasp_registry.functions.vasps(did_hash).call()
            if len(record) != 5 or type(record[3]) is not bool or type(record[4]) is not int:
                raise ValueError("Malformed VASP record")
            return tuple(record)

        return await self._read_cached(("vasp_info", bytes(did_hash)), fetch)

    async def is_credential_revoked(self, commitment: str) -> bool:
        """Check if a credential commitment has been revoked.

        Args:
            commitment: The credential commitment hash (hex string, 0x-prefixed).
        """
        commitment_bytes = self._hash_bytes(commitment)
        return await self._read_cached(
            ("cred_revoked", commitment_bytes), self._compliance_registry.functions.isRevoked(commitment_bytes).call
        )

    async def get_proof_record(self, transfer_id: str) -> dict | None:
        """Read a proof verification record from ComplianceRegistry.

        Args:
            transfer_id: The transfer identifier (hex string, 0x-prefixed).

        Returns:
            Dict with proof record fields, or None if no record exists.
        """
        transfer_bytes = self._hash_bytes(transfer_id)

        async def fetch():
            record = await self._compliance_registry.functions.proofs(transfer_bytes).call()
            # The current public mapping returns (proofHash, timestamp, verified).
            if len(record) != 3 or type(record[1]) is not int or type(record[2]) is not bool or record[1] < 0:
                raise ValueError("Malformed chain proof record")
            proof_hash = self._root_hex(record[0])
            if record[1] == 0:
                return None
            return {
                "transfer_id": "0x" + transfer_bytes.hex(),
                "proof_hash": proof_hash,
                "verified_at": record[1],
                "verified": record[2],
            }

        return await self._read_cached(("proof_record", transfer_bytes), fetch)
