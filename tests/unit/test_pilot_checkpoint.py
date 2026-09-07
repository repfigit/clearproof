"""Checkpoint rejection paths using real signatures and Web3 ABI decoding."""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_abi import encode
from web3 import AsyncWeb3
from web3.providers.async_base import AsyncBaseProvider

from src.chain.pilot_checkpoint import PilotCheckpointReader, publication_arguments, tenant_checkpoint_hash
from src.protocol.root_snapshot import RootAuthority, RootSnapshot, RootTrustError, RootTrustStore, sign_root


class CheckpointProvider(AsyncBaseProvider):
    def __init__(self, snapshot):
        super().__init__()
        self.calls = []
        self.chain = 31337
        self.code = b"synthetic-reviewed-runtime"
        self.timestamp = 110
        self.hash = "0x" + "ab" * 32
        self.confirmed_hash = self.hash
        self.head = [bytes.fromhex(snapshot.digest), 123, 1, 100, 200, 105]

    async def make_request(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            result = hex(self.chain)
        elif method == "eth_getBlockByNumber":
            result = {
                "number": "0x7",
                "timestamp": hex(self.timestamp),
                "hash": self.confirmed_hash if params[0] == "0x7" else self.hash,
            }
        elif method == "eth_getCode":
            result = "0x" + self.code.hex()
        elif method == "eth_call":
            result = "0x" + encode(["(bytes32,uint256,uint64,uint64,uint64,uint64)"], [self.head]).hex()
        else:
            raise AssertionError(f"Unexpected RPC operation: {method}")
        return {"jsonrpc": "2.0", "id": 1, "result": result}


@pytest.fixture
def checkpoint_case():
    private = Ed25519PrivateKey.generate()
    authority = RootAuthority(
        public_key=private.public_key().public_bytes_raw().hex(),
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address="0x" + "12" * 20,
        kinds=("issuer-root",),
        not_before=0,
        not_after=300,
    )
    snapshot = RootSnapshot(
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address=authority.registry_address,
        kind="issuer-root",
        root="123",
        tree_depth=8,
        source_digest="a" * 64,
        revision=1,
        issued_at=100,
        expires_at=200,
        key_id=authority.key_id,
    )
    provider = CheckpointProvider(snapshot)
    config = dict(
        address="0x" + "34" * 20,
        chain_id=31337,
        runtime_sha256=hashlib.sha256(provider.code).hexdigest(),
        max_block_age=10,
    )
    return provider, config, sign_root(snapshot, private), RootTrustStore([authority])


async def observe(case, **changes):
    provider, config, signed, trust = case
    reader = PilotCheckpointReader(AsyncWeb3(provider), **config)
    return await reader.verify_current(
        signed,
        trust,
        **{"tenant_id": "tenant-a", "registry_address": "0x" + "12" * 20, "now": 110, **changes},
    )


@pytest.mark.parametrize("tenant", [None, 1, "", "UPPER", "a" * 65, "../tenant"])
def test_checkpoint_tenant_requires_opaque_identifier(tenant):
    with pytest.raises(ValueError, match="opaque tenant ID"):
        tenant_checkpoint_hash(tenant)


@pytest.mark.parametrize("revision", [True, "0", -1, 1, 2])
def test_publication_requires_preceding_integer_revision(checkpoint_case, revision):
    _, _, signed, trust = checkpoint_case
    with pytest.raises(ValueError, match="preceding checkpoint revision"):
        publication_arguments(signed, trust, now=110, expected_revision=revision)
    assert publication_arguments(signed, trust, now=110, expected_revision=0)[4:6] == (0, 1)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"address": None}, "canonical checkpoint"),
        ({"address": "0x" + "00" * 20}, "canonical checkpoint"),
        ({"address": "0x" + "AB" * 20}, "canonical checkpoint"),
        ({"chain_id": True}, "safe integer"),
        ({"chain_id": 0}, "safe integer"),
        ({"chain_id": 2**53}, "safe integer"),
        ({"runtime_sha256": None}, "pinned runtime"),
        ({"runtime_sha256": "A" * 64}, "pinned runtime"),
        ({"runtime_sha256": "a" * 63}, "pinned runtime"),
        ({"block_tag": "pending"}, "observation policy"),
        ({"max_block_age": True}, "observation policy"),
        ({"max_block_age": 0}, "observation policy"),
        ({"max_block_age": 86401}, "observation policy"),
    ],
)
def test_checkpoint_configuration_rejected_before_rpc(checkpoint_case, changes, message):
    provider, config, _, _ = checkpoint_case
    with pytest.raises(ValueError, match=message):
        PilotCheckpointReader(AsyncWeb3(provider), **{**config, **changes})
    assert provider.calls == []


async def test_checkpoint_reads_are_pinned_to_observed_block(checkpoint_case):
    provider, _, signed, _ = checkpoint_case
    result = await observe(checkpoint_case)
    assert result.snapshot == signed.snapshot
    assert (result.block_number, result.block_hash, result.published_at) == (7, "ab" * 32, 105)
    block_calls = [list(params) for method, params in provider.calls if method == "eth_getBlockByNumber"]
    assert block_calls == [["finalized", False], ["0x7", False]]
    for method, params in provider.calls:
        if method in ("eth_getCode", "eth_call"):
            assert params[1] == "0x7"


async def test_checkpoint_rpc_chain_mismatch(checkpoint_case):
    provider, _, _, _ = checkpoint_case
    provider.chain = 1
    with pytest.raises(RootTrustError, match="RPC chain ID mismatch"):
        await observe(checkpoint_case)
    assert all(method == "eth_chainId" for method, _ in provider.calls)


@pytest.mark.parametrize("timestamp", [99, 111])
async def test_checkpoint_stale_or_future_block_rejected(checkpoint_case, timestamp):
    provider, _, _, _ = checkpoint_case
    provider.timestamp = timestamp
    with pytest.raises(RootTrustError, match="stale or in the future"):
        await observe(checkpoint_case)
    assert not any(method == "eth_getCode" for method, _ in provider.calls)


async def test_checkpoint_accepts_exact_maximum_block_age(checkpoint_case):
    provider, _, _, _ = checkpoint_case
    provider.timestamp = 100
    provider.head[5] = 100
    assert (await observe(checkpoint_case)).published_at == 100


@pytest.mark.parametrize("code", [b"", b"synthetic-unapproved-runtime"])
async def test_checkpoint_empty_or_unapproved_code_rejected(checkpoint_case, code):
    provider, _, _, _ = checkpoint_case
    provider.code = code
    with pytest.raises(RootTrustError, match="approved bytecode"):
        await observe(checkpoint_case)
    assert not any(method == "eth_call" for method, _ in provider.calls)


@pytest.mark.parametrize(
    "index,value",
    [(0, bytes(32)), (1, 124), (2, 2), (3, 99), (4, 201), (5, 99), (5, 111)],
)
async def test_checkpoint_head_must_match_every_signed_field(checkpoint_case, index, value):
    provider, _, _, _ = checkpoint_case
    provider.head[index] = value
    with pytest.raises(RootTrustError, match="observed chain head"):
        await observe(checkpoint_case)


async def test_checkpoint_reorg_during_observation_rejected(checkpoint_case):
    provider, _, _, _ = checkpoint_case
    provider.confirmed_hash = "0x" + "cd" * 32
    with pytest.raises(RootTrustError, match="changed during verification"):
        await observe(checkpoint_case)


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": "tenant-b"},
        {"registry_address": "0x" + "56" * 20},
        {"kind": "sanctions-root"},
        {"issuer_did": "did:web:synthetic.example"},
    ],
)
async def test_checkpoint_signed_context_mismatch_rejected_before_rpc(checkpoint_case, changes):
    provider, _, _, _ = checkpoint_case
    with pytest.raises(RootTrustError, match="context mismatch"):
        await observe(checkpoint_case, **changes)
    assert provider.calls == []


async def test_checkpoint_signed_chain_must_match_configured_chain(checkpoint_case):
    provider, config, _, _ = checkpoint_case
    config["chain_id"] = 1
    with pytest.raises(RootTrustError, match="context mismatch"):
        await observe(checkpoint_case)
    assert provider.calls == []
