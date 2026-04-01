"""Read on-chain state from VASPRegistry, SanctionsOracle, ComplianceRegistry.

All reads use eth_call (no gas, no tx).
Results can be cached in Redis with configurable TTL.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

logger = logging.getLogger(__name__)

_ABI_DIR = Path(__file__).parent / "abis"

# In-memory cache for simple deployments (replaced by Redis in production)
_cache: dict[str, tuple[float, Any]] = {}
_CACHE_TTL_SECONDS = int(os.getenv("CHAIN_CACHE_TTL", "30"))


def _load_abi(name: str) -> list[dict]:
    """Load a contract ABI from the abis/ directory."""
    abi_path = _ABI_DIR / f"{name}.json"
    with open(abi_path, "r") as f:
        return json.load(f)


def _cache_get(key: str) -> Any | None:
    """Return cached value if still fresh, else None."""
    if key in _cache:
        ts, value = _cache[key]
        if time.time() - ts < _CACHE_TTL_SECONDS:
            return value
        del _cache[key]
    return None


def _cache_set(key: str, value: Any) -> None:
    _cache[key] = (time.time(), value)


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
    if _reader_instance is None:
        rpc_url = os.environ.get("CHAIN_RPC_URL", "http://127.0.0.1:8545")
        contracts = {
            "vasp_registry": os.environ.get("VASP_REGISTRY_ADDRESS", ""),
            "sanctions_oracle": os.environ.get("SANCTIONS_ORACLE_ADDRESS", ""),
            "compliance_registry": os.environ.get("COMPLIANCE_REGISTRY_ADDRESS", ""),
        }
        _reader_instance = ChainReader(rpc_url, contracts)
    return _reader_instance


class ChainReader:
    """Stateless reader for on-chain compliance state.

    All reads use eth_call (no gas, no tx).
    Results are cached with configurable TTL.
    """

    def __init__(self, rpc_url: str, contracts: dict[str, str]) -> None:
        """
        Args:
            rpc_url: Ethereum RPC endpoint.
            contracts: Mapping of contract name to deployed address, e.g.
                {"vasp_registry": "0x...", "sanctions_oracle": "0x...", "compliance_registry": "0x..."}.
        """
        self._w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
        self._addresses = contracts
        self._contracts: dict[str, Any] = {}

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
        cached = _cache_get("sanctions_root")
        if cached is not None:
            return cached

        root: bytes = await self._sanctions_oracle.functions.currentRoot().call()
        hex_root = "0x" + root.hex()
        _cache_set("sanctions_root", hex_root)
        return hex_root

    async def is_sanctions_stale(self) -> bool:
        """Check if sanctions root is past grace period."""
        cached = _cache_get("sanctions_stale")
        if cached is not None:
            return cached

        stale: bool = await self._sanctions_oracle.functions.isStale().call()
        _cache_set("sanctions_stale", stale)
        return stale

    async def get_issuer_root(self) -> str:
        """Read current issuer Merkle root from VASPRegistry."""
        cached = _cache_get("issuer_root")
        if cached is not None:
            return cached

        root: bytes = await self._vasp_registry.functions.issuerMerkleRoot().call()
        hex_root = "0x" + root.hex()
        _cache_set("issuer_root", hex_root)
        return hex_root

    async def is_vasp_active(self, did_hash: str) -> bool:
        """Check if a VASP is registered and active.

        Args:
            did_hash: keccak256 hash of the VASP DID (hex string, 0x-prefixed).
        """
        cache_key = f"vasp_active:{did_hash}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        did_bytes = bytes.fromhex(did_hash.removeprefix("0x"))
        active: bool = await self._vasp_registry.functions.isActive(did_bytes).call()
        _cache_set(cache_key, active)
        return active

    async def is_credential_revoked(self, commitment: str) -> bool:
        """Check if a credential commitment has been revoked.

        Args:
            commitment: The credential commitment hash (hex string, 0x-prefixed).
        """
        cache_key = f"cred_revoked:{commitment}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        commitment_bytes = bytes.fromhex(commitment.removeprefix("0x"))
        revoked: bool = await self._compliance_registry.functions.isRevoked(commitment_bytes).call()
        _cache_set(cache_key, revoked)
        return revoked

    async def get_proof_record(self, transfer_id: str) -> dict | None:
        """Read a proof verification record from ComplianceRegistry.

        Args:
            transfer_id: The transfer identifier (hex string, 0x-prefixed).

        Returns:
            Dict with proof record fields, or None if no record exists.
        """
        cache_key = f"proof_record:{transfer_id}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        transfer_bytes = bytes.fromhex(transfer_id.removeprefix("0x"))
        try:
            record = await self._compliance_registry.functions.proofs(transfer_bytes).call()
        except Exception:
            logger.debug("No proof record found for transfer_id=%s", transfer_id)
            return None

        # Contract returns a tuple: (transferId, proofHash, verifiedAt, verifier)
        if not record or record[2] == 0:
            return None

        result = {
            "transfer_id": "0x" + record[0].hex(),
            "proof_hash": "0x" + record[1].hex(),
            "verified_at": record[2],
            "verifier": record[3],
        }
        _cache_set(cache_key, result)
        return result
