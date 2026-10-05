#!/usr/bin/env python3
"""Publish a pilot sanctions root as a checkpoint, after explicit operator confirmation.

Pilot counterpart of the legacy ``update-sanctions-root.ts`` oracle update. Steps:

1. Rebuild the tree from ``artifacts/pilot_sanctions_tree.json`` and reject any
   ordering, count, root or source-digest mismatch (``PilotSanctionsTree.from_artifact``).
2. Authenticate the registrar-signed ``sanctions-root`` approval against the pinned
   trust store and require it to approve exactly that root, depth and source digest.
3. Check the RPC chain ID, the pinned runtime-bytecode SHA-256, pause state and the
   current head at one block; skip if that exact approval is already current.
4. Print the plan. Stop for ``--dry-run``. Otherwise require the configured tenant
   publisher key and a typed ``publish`` confirmation (``SKIP_CONFIRM=1`` for scripted
   use, as with the legacy oracle update), then send one transaction and read back.

Targets: ``registry`` (default) publishes ``PilotCurrentRegistry.publishHead`` with
``Kind.Sanctions`` -- the head ``inspect`` compares with public signal 2 -- and
``checkpoint`` publishes ``PilotRootCheckpoint.publish``. Run once per deployment.

Usage:
    uv run python scripts/publish_pilot_sanctions_head.py --approval approval.json \\
        --trust authorities.json --rpc-url $PILOT_RPC_URL --contract 0x... \\
        --chain-id 11155111 --runtime-sha256 <hex> [--target checkpoint] [--dry-run]

Environment: ``PILOT_PUBLISHER_PRIVATE_KEY`` (broadcast only), ``SKIP_CONFIRM=1``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from eth_account import Account  # noqa: E402
from web3 import HTTPProvider, Web3  # noqa: E402

from src.chain.pilot_checkpoint import tenant_checkpoint_hash  # noqa: E402
from src.chain.pilot_sanctions_head import (  # noqa: E402
    CHECKPOINT_ABI,
    REGISTRY_ABI,
    SANCTIONS_KIND,
    authenticate_sanctions_root,
    checkpoint_arguments,
    registry_head_arguments,
    registry_tenant_hash,
)
from src.protocol.root_snapshot import RootAuthority, RootTrustStore, SignedRootSnapshot, root_scope_id  # noqa: E402
from src.registry.pilot_sanctions import PilotSanctionsTree  # noqa: E402

DEFAULT_ARTIFACT = os.path.join(os.path.dirname(__file__), "..", "artifacts", "pilot_sanctions_tree.json")
MAX_BLOCK_AGE = 600
MAX_CLOCK_SKEW = 300  # local dev nodes advance block time by at least 1s per block


class PublishError(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Publish a pilot sanctions root checkpoint (human-confirmed)")
    parser.add_argument("--artifact", default=DEFAULT_ARTIFACT, help="pilot_sanctions_tree.json to rebuild")
    parser.add_argument("--approval", required=True, help="Registrar-signed sanctions-root approval JSON")
    parser.add_argument("--trust", required=True, help="JSON list of pinned root authorities")
    parser.add_argument("--target", choices=("registry", "checkpoint"), default="registry")
    parser.add_argument("--rpc-url", default=os.environ.get("PILOT_RPC_URL"))
    parser.add_argument("--contract", required=True, help="Canonical lowercase contract address")
    parser.add_argument("--chain-id", required=True, type=int)
    parser.add_argument("--runtime-sha256", required=True, help="Pinned SHA-256 of the approved runtime bytecode")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan without sending")
    return parser


def load_inputs(args: argparse.Namespace) -> tuple[PilotSanctionsTree, SignedRootSnapshot, RootTrustStore]:
    tree = PilotSanctionsTree.from_artifact(json.loads(Path(args.artifact).read_text()))
    signed = SignedRootSnapshot.model_validate_json(Path(args.approval).read_text())
    authorities = json.loads(Path(args.trust).read_text())
    if type(authorities) is not list:
        raise PublishError("Trust file must be a JSON list of root authorities")
    return tree, signed, RootTrustStore([RootAuthority.model_validate_json(json.dumps(item)) for item in authorities])


def plan_publication(args, web3, tree, signed, trust, *, clock: Callable[[], float] = time.time) -> dict[str, Any]:
    """Read-only checks at one block; returns the transaction function and a printable plan."""
    if not re.fullmatch(r"0x[0-9a-f]{40}", args.contract) or int(args.contract, 16) == 0:
        raise PublishError("Expected a canonical nonzero lowercase contract address")
    if not re.fullmatch(r"[0-9a-f]{64}", args.runtime_sha256):
        raise PublishError("Expected a pinned lowercase runtime SHA-256")
    if web3.eth.chain_id != args.chain_id:
        raise PublishError("RPC chain ID differs from --chain-id")
    block = web3.eth.get_block("latest")
    now, number = int(block["timestamp"]), block["number"]
    if not -MAX_CLOCK_SKEW <= int(clock()) - now <= MAX_BLOCK_AGE:
        raise PublishError("Latest block is stale or ahead of the local clock")
    address = Web3.to_checksum_address(args.contract)
    code = web3.eth.get_code(address, block_identifier=number)
    if not code or hashlib.sha256(bytes(code)).hexdigest() != args.runtime_sha256:
        raise PublishError("Contract runtime does not match the pinned bytecode")
    snapshot = authenticate_sanctions_root(signed, trust, tree, now=now)
    scope = bytes.fromhex(root_scope_id(snapshot))
    if args.target == "registry":
        contract = web3.eth.contract(address=address, abi=REGISTRY_ABI)
        tenant = registry_tenant_hash(snapshot.tenant_id)
        current = contract.functions.head(tenant, SANCTIONS_KIND, scope).call(block_identifier=number)
        digest, value, revision, _, _, head_epoch, enabled = current
        done = bytes(digest).hex() == snapshot.digest and value == int(snapshot.root) and enabled
        build = registry_head_arguments
        function_name = "publishHead"
    else:
        contract = web3.eth.contract(address=address, abi=CHECKPOINT_ABI)
        tenant = tenant_checkpoint_hash(snapshot.tenant_id)
        current = contract.functions.head(tenant, scope).call(block_identifier=number)
        digest, _, revision, _, _, _, head_epoch = current
        done = bytes(digest).hex() == snapshot.digest and revision == snapshot.revision
        build = checkpoint_arguments
        function_name = "publish"
    functions = contract.functions
    publisher = functions.publishers(tenant).call(block_identifier=number)
    epoch = functions.publisherEpochs(tenant).call(block_identifier=number)
    if int(publisher, 16) == 0:
        raise PublishError("Tenant publisher is disabled on this contract")
    if functions.paused().call(block_identifier=number):
        raise PublishError("Contract is paused; publication would revert")
    plan = {
        "target": args.target,
        "contract": args.contract,
        "chain_id": args.chain_id,
        "block": number,
        "tenant_id": snapshot.tenant_id,
        "publisher": publisher.lower(),
        "root": tree.root,
        "address_count": len(tree.addresses),
        "source_digest": tree.source_digest,
        "approval_digest": snapshot.digest,
        "approval_revision": snapshot.revision,
        "current_revision": revision,
        "valid_from": snapshot.issued_at,
        "valid_until": snapshot.expires_at,
        "already_current": bool(done and head_epoch == epoch),
    }
    call = None
    if not plan["already_current"]:
        call = getattr(functions, function_name)(*build(signed, trust, tree, now=now, expected_revision=revision))
    return {"plan": plan, "call": call, "verify": (contract, tenant, scope)}


def _verify_published(target, contract, tenant, scope, snapshot, receipt) -> None:
    number = receipt["blockNumber"]
    if target == "registry":
        digest, value, _, _, _, _, enabled = contract.functions.head(tenant, SANCTIONS_KIND, scope).call(
            block_identifier=number
        )
        matches = value == int(snapshot.root) and enabled
    else:
        digest, root, revision, *_ = contract.functions.head(tenant, scope).call(block_identifier=number)
        matches = root == int(snapshot.root) and revision == snapshot.revision
    if not matches or bytes(digest).hex() != snapshot.digest:
        raise PublishError("Published head does not match the approval after inclusion")


def main(
    argv: list[str] | None = None,
    *,
    web3: Any = None,
    prompt: Callable[[str], str] = input,
    environ: dict[str, str] | None = None,
    clock: Callable[[], float] = lambda: time.time(),
) -> int:
    environ = os.environ if environ is None else environ
    args = _parser().parse_args(argv)
    try:
        tree, signed, trust = load_inputs(args)
        if web3 is None:
            if not args.rpc_url:
                raise PublishError("Provide --rpc-url or PILOT_RPC_URL")
            web3 = Web3(HTTPProvider(args.rpc_url, request_kwargs={"timeout": 30}))
        prepared = plan_publication(args, web3, tree, signed, trust, clock=clock)
        plan = prepared["plan"]
        print(json.dumps(plan, indent=2))
        if plan["already_current"]:
            print("On-chain sanctions head already matches this approval. Nothing to do.")
            return 0
        if args.dry_run:
            print("Dry run: nothing sent.")
            return 0
        key = environ.get("PILOT_PUBLISHER_PRIVATE_KEY")
        if not key:
            raise PublishError("PILOT_PUBLISHER_PRIVATE_KEY is required to broadcast")
        account = Account.from_key(key)
        if account.address.lower() != plan["publisher"]:
            raise PublishError("Signing key is not the configured tenant publisher")
        if environ.get("SKIP_CONFIRM") != "1" and prompt("Type 'publish' to broadcast: ").strip() != "publish":
            print("Aborted: nothing sent.")
            return 1
        transaction = prepared["call"].build_transaction(
            {
                "from": account.address,
                "nonce": web3.eth.get_transaction_count(account.address),
                "chainId": args.chain_id,
            }
        )
        signed_tx = account.sign_transaction(transaction)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        if receipt["status"] != 1:
            raise PublishError("Publication transaction reverted")
        _verify_published(args.target, *prepared["verify"], signed.snapshot, receipt)
        print(f"Published sanctions head in block {receipt['blockNumber']} (tx 0x{bytes(tx_hash).hex()})")
        return 0
    except (OSError, ValueError, PublishError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
