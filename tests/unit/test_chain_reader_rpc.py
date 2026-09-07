"""Exercise the bundled ABIs through Web3's actual eth_call encoder/decoder."""

from eth_abi import encode
from web3 import AsyncWeb3, Web3
from web3.providers.async_base import AsyncBaseProvider

from src.chain.reader import ChainReader


class FixtureProvider(AsyncBaseProvider):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.responses = {
            Web3.keccak(text=signature)[:4].hex(): "0x" + encode(types, values).hex()
            for signature, types, values in (
                ("currentRoot()", ["bytes32"], [bytes([1]) * 32]),
                ("isStale()", ["bool"], [False]),
                ("issuerMerkleRoot()", ["bytes32"], [bytes([2]) * 32]),
                ("isActive(bytes32)", ["bool"], [True]),
                ("isRevoked(bytes32)", ["bool"], [False]),
                ("proofs(bytes32)", ["bytes32", "uint256", "bool"], [bytes([3]) * 32, 100, True]),
            )
        }

    async def make_request(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            result = "0x1"
        elif method == "eth_call":
            result = self.responses[params[0]["data"][2:10]]
        else:
            raise AssertionError(f"Unexpected RPC method: {method}")
        return {"jsonrpc": "2.0", "id": 1, "result": result}


async def test_current_abi_calls_decode_and_target_the_configured_contracts():
    provider = FixtureProvider()
    addresses = {
        "sanctions_oracle": "0x" + "11" * 20,
        "vasp_registry": "0x" + "22" * 20,
        "compliance_registry": "0x" + "33" * 20,
    }
    reader = ChainReader("https://unused.example", addresses)
    reader._w3 = AsyncWeb3(provider)
    identifier = "0x" + "44" * 32
    assert await reader.get_sanctions_root() == "0x" + "01" * 32
    assert await reader.is_sanctions_stale() is False
    assert await reader.get_issuer_root() == "0x" + "02" * 32
    assert await reader.is_vasp_active(identifier) is True
    assert await reader.is_credential_revoked(identifier) is False
    assert await reader.get_proof_record(identifier) == {
        "transfer_id": identifier,
        "proof_hash": "0x" + "03" * 32,
        "verified_at": 100,
        "verified": True,
    }
    calls = [params[0] for method, params in provider.calls if method == "eth_call"]
    assert [call["to"] for call in calls] == [
        addresses["sanctions_oracle"],
        addresses["sanctions_oracle"],
        addresses["vasp_registry"],
        addresses["vasp_registry"],
        addresses["compliance_registry"],
        addresses["compliance_registry"],
    ]
    assert all(call["data"][10:] == identifier[2:] for call in calls[3:])
