"""Submit transactions to on-chain contracts.

All writes are signed with the VASP's wallet key and submitted as transactions.
"""

import json
import logging
from pathlib import Path
from typing import Any

from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

logger = logging.getLogger(__name__)

_ABI_DIR = Path(__file__).parent / "abis"


def _load_abi(name: str) -> list[dict]:
    """Load a contract ABI from the abis/ directory."""
    abi_path = _ABI_DIR / f"{name}.json"
    with open(abi_path, "r") as f:
        return json.load(f)


class ChainWriter:
    """Submit compliance transactions to chain.

    All writes are signed with the VASP's wallet key and submitted as transactions.
    """

    def __init__(self, rpc_url: str, private_key: str, contracts: dict[str, str]) -> None:
        """
        Args:
            rpc_url: Ethereum RPC endpoint.
            private_key: The VASP operator's wallet private key (hex, 0x-prefixed).
            contracts: Mapping of contract name to deployed address, e.g.
                {"compliance_registry": "0x...", "vasp_registry": "0x..."}.
        """
        self._w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
        self._private_key = private_key
        self._account = self._w3.eth.account.from_key(private_key)
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
    def _compliance_registry(self) -> Any:
        return self._get_contract("compliance_registry", "ComplianceRegistry")

    async def _send_tx(self, tx_func: Any) -> str:
        """Build, sign, and send a contract transaction. Returns tx hash hex."""
        nonce = await self._w3.eth.get_transaction_count(self._account.address)
        chain_id = await self._w3.eth.chain_id

        tx = await tx_func.build_transaction({
            "from": self._account.address,
            "nonce": nonce,
            "chainId": chain_id,
        })

        signed = self._w3.eth.account.sign_transaction(tx, self._private_key)
        tx_hash = await self._w3.eth.send_raw_transaction(signed.raw_transaction)
        hex_hash = "0x" + tx_hash.hex()
        logger.info("Transaction sent: %s", hex_hash)
        return hex_hash

    # -- public write methods --------------------------------------------------

    async def record_proof(
        self,
        transfer_id: bytes,
        proof: dict,
        public_signals: list[str],
        vasp_did_hash: int,
    ) -> str:
        """Submit proof verification to ComplianceRegistry via verifyAndRecord.

        Args:
            transfer_id: Unique transfer identifier as bytes32.
            proof: Groth16 proof dict with keys pi_a, pi_b, pi_c.
            public_signals: List of public signal strings.
            vasp_did_hash: Integer hash of the VASP DID.

        Returns:
            Transaction hash (hex string, 0x-prefixed).
        """
        # Destructure Groth16 proof components for on-chain verifier
        _pA = [int(x) for x in proof["pi_a"][:2]]
        _pB = [
            [int(proof["pi_b"][0][1]), int(proof["pi_b"][0][0])],
            [int(proof["pi_b"][1][1]), int(proof["pi_b"][1][0])],
        ]
        _pC = [int(x) for x in proof["pi_c"][:2]]
        _pubSignals = [int(s) for s in public_signals]

        tx_func = self._compliance_registry.functions.verifyAndRecord(
            transfer_id,
            _pA,
            _pB,
            _pC,
            _pubSignals,
            vasp_did_hash,
        )
        return await self._send_tx(tx_func)

    async def revoke_credential(self, commitment: bytes) -> str:
        """Revoke a credential on-chain.

        Args:
            commitment: The credential commitment as bytes32.

        Returns:
            Transaction hash (hex string, 0x-prefixed).
        """
        tx_func = self._compliance_registry.functions.revokeCredential(commitment)
        return await self._send_tx(tx_func)
