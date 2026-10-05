"""Python reader and publication arguments exercised against a real local EVM."""

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from web3 import AsyncHTTPProvider, AsyncWeb3

from src.chain.pilot_checkpoint import PilotCheckpointReader, publication_arguments
from src.protocol.canonical import record_digest
from src.protocol.root_snapshot import (
    RootAuthority,
    RootSnapshot,
    RootTrustError,
    RootTrustStore,
    root_scope_id,
    sign_root,
)

pytestmark = pytest.mark.skipif(not os.getenv("CHECKPOINT_TEST_RPC"), reason="requires isolated local Hardhat node")
ROOT = Path(__file__).resolve().parents[2]


async def test_real_chain_checkpoint_current_head_and_scope():
    url = os.environ["CHECKPOINT_TEST_RPC"]
    assert urlsplit(url).hostname == "127.0.0.1", "test deployment is restricted to loopback"
    web3 = AsyncWeb3(AsyncHTTPProvider(url, request_kwargs={"timeout": 10}))
    try:
        assert await web3.eth.chain_id == 31337
        accounts = await web3.eth.accounts
        artifact = json.loads(
            (
                ROOT / "packages/contracts/artifacts/contracts/PilotRootCheckpoint.sol/PilotRootCheckpoint.json"
            ).read_text()
        )
        factory = web3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
        deployment = await factory.constructor(accounts[0]).transact({"from": accounts[0]})
        receipt = await web3.eth.wait_for_transaction_receipt(deployment)
        address = receipt["contractAddress"]
        contract = web3.eth.contract(address=address, abi=artifact["abi"])
        # Pin from the reviewed build artifact, never from the RPC being checked.
        code_hash = hashlib.sha256(bytes.fromhex(artifact["deployedBytecode"][2:])).hexdigest()
        now = (await web3.eth.get_block("latest"))["timestamp"]
        private = Ed25519PrivateKey.generate()
        authority = RootAuthority(
            public_key=private.public_key().public_bytes_raw().hex(),
            tenant_id="tenant-a",
            chain_id=31337,
            registry_address=accounts[2].lower(),
            kinds=("issuer-root",),
            not_before=now - 1,
            not_after=now + 10000,
        )
        trust = RootTrustStore([authority])
        snapshot = RootSnapshot(
            tenant_id="tenant-a",
            chain_id=31337,
            registry_address=accounts[2].lower(),
            kind="issuer-root",
            root="123",
            tree_depth=8,
            source_digest="a" * 64,
            revision=1,
            issued_at=now,
            expires_at=now + 1000,
            key_id=authority.key_id,
        )
        signed = sign_root(snapshot, private)
        args = publication_arguments(signed, trust, now=now, expected_revision=0)
        tx = await contract.functions.setPublisher(args[0], accounts[1]).transact({"from": accounts[0]})
        await web3.eth.wait_for_transaction_receipt(tx)
        tx = await contract.functions.publish(*args).transact({"from": accounts[1]})
        await web3.eth.wait_for_transaction_receipt(tx)
        reader = PilotCheckpointReader(
            web3, address=address.lower(), chain_id=31337, runtime_sha256=code_hash, block_tag="latest"
        )
        now = (await web3.eth.get_block("latest"))["timestamp"]
        observed = await reader.verify_current(
            signed, trust, tenant_id="tenant-a", registry_address=accounts[2].lower(), now=now
        )
        assert observed.snapshot == snapshot and len(observed.block_hash) == 64
        for tenant, audience in [("tenant-b", accounts[2].lower()), ("tenant-a", accounts[3].lower())]:
            with pytest.raises(RootTrustError):
                await reader.verify_current(signed, trust, tenant_id=tenant, registry_address=audience, now=now)
        bad_code = PilotCheckpointReader(
            web3, address=address.lower(), chain_id=31337, runtime_sha256="0" * 64, block_tag="latest"
        )
        with pytest.raises(RootTrustError, match="bytecode"):
            await bad_code.verify_current(
                signed, trust, tenant_id="tenant-a", registry_address=accounts[2].lower(), now=now
            )
        next_snapshot = RootSnapshot.model_validate(
            {
                **snapshot.model_dump(),
                "revision": 2,
                "previous_digest": snapshot.digest,
                "root": "124",
                "issued_at": now,
            }
        )
        next_signed = sign_root(next_snapshot, private)
        tx = await contract.functions.publish(
            *publication_arguments(next_signed, trust, now=now, expected_revision=1)
        ).transact({"from": accounts[1]})
        await web3.eth.wait_for_transaction_receipt(tx)
        now = (await web3.eth.get_block("latest"))["timestamp"]
        with pytest.raises(RootTrustError, match="chain head"):
            await reader.verify_current(
                signed, trust, tenant_id="tenant-a", registry_address=accounts[2].lower(), now=now
            )
        assert (
            await reader.verify_current(
                next_signed, trust, tenant_id="tenant-a", registry_address=accounts[2].lower(), now=now
            )
        ).snapshot == next_snapshot
        # Read-only verification never sends a transaction.
        before = await web3.eth.get_transaction_count(accounts[1])
        await reader.verify_current(
            next_signed, trust, tenant_id="tenant-a", registry_address=accounts[2].lower(), now=now
        )
        assert await web3.eth.get_transaction_count(accounts[1]) == before
        # Reassigning (even the same address) or disabling the publisher supersedes the head.
        for publisher in (accounts[1], "0x" + "00" * 20):
            tx = await contract.functions.setPublisher(args[0], publisher).transact({"from": accounts[0]})
            await web3.eth.wait_for_transaction_receipt(tx)
            now = (await web3.eth.get_block("latest"))["timestamp"]
            with pytest.raises(RootTrustError, match="current tenant publisher"):
                await reader.verify_current(
                    next_signed, trust, tenant_id="tenant-a", registry_address=accounts[2].lower(), now=now
                )
    finally:
        await web3.provider.disconnect()


def test_real_chain_pilot_sanctions_head_publication(tmp_path):
    """Build, authenticate and publish a pilot sanctions root to both pilot destinations."""
    from eth_account import Account
    from web3 import HTTPProvider, Web3

    from scripts import publish_pilot_sanctions_head as publisher_cli
    from src.chain.pilot_sanctions_head import registry_tenant_hash
    from src.registry.pilot_sanctions import PilotSanctionsTree

    url = os.environ["CHECKPOINT_TEST_RPC"]
    assert urlsplit(url).hostname == "127.0.0.1", "test deployment is restricted to loopback"
    web3 = Web3(HTTPProvider(url, request_kwargs={"timeout": 10}))
    admin = web3.eth.accounts[0]

    def artifact(name, folder="contracts"):
        return json.loads((ROOT / f"packages/contracts/artifacts/{folder}/{name}.sol/{name}.json").read_text())

    def deploy(data, *args):
        factory = web3.eth.contract(abi=data["abi"], bytecode=data["bytecode"])
        receipt = web3.eth.wait_for_transaction_receipt(factory.constructor(*args).transact({"from": admin}))
        return web3.eth.contract(address=receipt["contractAddress"], abi=data["abi"]), data

    verifier, _ = deploy(artifact("MockPilotVerifier", "contracts/test"), "0x" + "11" * 32)
    registry, _ = deploy(artifact("PilotCurrentRegistry"), admin, verifier.address)
    checkpoint, checkpoint_data = deploy(artifact("PilotRootCheckpoint"), admin)
    # A fresh, test-only publisher key; never a configured or well-known key.
    account = Account.create()
    web3.eth.wait_for_transaction_receipt(
        web3.eth.send_transaction({"from": admin, "to": account.address, "value": 10**18})
    )
    audience = registry.address.lower()
    for contract, tenant in (
        (registry, registry_tenant_hash("tenant-a")),
        (checkpoint, bytes.fromhex(record_digest("clearproof/checkpoint-tenant/v1", "tenant-a"))),
    ):
        tx = contract.functions.setPublisher(tenant, account.address).transact({"from": admin})
        web3.eth.wait_for_transaction_receipt(tx)

    tree = PilotSanctionsTree(["0x" + "12" * 20, "0x" + "ab" * 20, "0x" + "03" * 20])
    (tmp_path / "tree.json").write_text(json.dumps(tree.artifact()))
    now = web3.eth.get_block("latest")["timestamp"]
    private = Ed25519PrivateKey.generate()
    authority = RootAuthority(
        public_key=private.public_key().public_bytes_raw().hex(),
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address=audience,
        kinds=("sanctions-root",),
        not_before=now - 10,
        not_after=now + 10000,
    )
    snapshot = RootSnapshot(
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address=audience,
        kind="sanctions-root",
        root=tree.root,
        tree_depth=tree.depth,
        source_digest=tree.source_digest,
        revision=1,
        issued_at=now - 5,
        expires_at=now + 3600,
        key_id=authority.key_id,
    )
    (tmp_path / "approval.json").write_text(sign_root(snapshot, private).model_dump_json())
    (tmp_path / "trust.json").write_text(json.dumps([authority.model_dump(mode="json")]))
    environ = {"PILOT_PUBLISHER_PRIVATE_KEY": account.key.hex(), "SKIP_CONFIRM": "1"}
    pins = {
        # The registry embeds immutables (verifier, code hash, manifest), so its pin is taken
        # from the reviewed deployment's runtime; the checkpoint has none and matches its build.
        "registry": hashlib.sha256(bytes(web3.eth.get_code(registry.address))).hexdigest(),
        "checkpoint": hashlib.sha256(bytes.fromhex(checkpoint_data["deployedBytecode"][2:])).hexdigest(),
    }
    for target, contract in (("registry", registry), ("checkpoint", checkpoint)):
        argv = [
            "--artifact", str(tmp_path / "tree.json"),
            "--approval", str(tmp_path / "approval.json"),
            "--trust", str(tmp_path / "trust.json"),
            "--target", target,
            "--contract", contract.address.lower(),
            "--chain-id", "31337",
            "--runtime-sha256", pins[target],
        ]  # fmt: skip
        assert publisher_cli.main(argv, web3=web3, environ=environ) == 0
        # The same approval is now current: a second run sends nothing.
        nonce = web3.eth.get_transaction_count(account.address)
        assert publisher_cli.main(argv, web3=web3, environ=environ) == 0
        assert web3.eth.get_transaction_count(account.address) == nonce
    head = registry.functions.head(registry_tenant_hash("tenant-a"), 2, bytes.fromhex(root_scope_id(snapshot))).call()
    assert (bytes(head[0]).hex(), head[1], head[2], head[6]) == (snapshot.digest, int(tree.root), 1, True)
