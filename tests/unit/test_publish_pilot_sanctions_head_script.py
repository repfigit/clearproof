"""Human-confirmed pilot sanctions head publication over a synthetic JSON-RPC provider."""

import hashlib
import json
import runpy
import sys

import pytest
from eth_abi import encode
from eth_account import Account
from web3 import Web3
from web3.providers.base import BaseProvider

from scripts import publish_pilot_sanctions_head as cli
from tests.unit.test_pilot_sanctions_head import sanctions_case

CONTRACT = "0x" + "56" * 20
CODE = b"synthetic-reviewed-runtime"


def selector(signature):
    return "0x" + Web3.keccak(text=signature)[:4].hex().removeprefix("0x")


REGISTRY_HEAD = selector("head(bytes32,uint8,bytes32)")
CHECKPOINT_HEAD = selector("head(bytes32,bytes32)")
PUBLISHERS = selector("publishers(bytes32)")
EPOCHS = selector("publisherEpochs(bytes32)")
PAUSED = selector("paused()")


class ChainProvider(BaseProvider):
    """Answers only the RPC operations the publisher needs; anything else fails the test."""

    def __init__(self, snapshot, publisher):
        super().__init__()
        self.snapshot = snapshot
        self.calls = []
        self.chain = 31337
        self.timestamp = 150
        self.code = CODE
        self.publisher = publisher
        self.epoch = 1
        self.paused = False
        self.status = 1
        self.sent = []
        self.registry_head = [bytes(32), 0, 0, 0, 0, 0, False]
        self.checkpoint_head = [bytes(32), 0, 0, 0, 0, 0, 0]
        self.after = None

    def publish(self):
        snapshot = self.snapshot
        digest = bytes.fromhex(snapshot.digest)
        if self.after == "wrong":
            digest = bytes(32)
        self.registry_head = [digest, int(snapshot.root), 1, snapshot.issued_at, snapshot.expires_at, self.epoch, True]
        self.checkpoint_head = [
            digest, int(snapshot.root), snapshot.revision, snapshot.issued_at, snapshot.expires_at, 150, self.epoch,
        ]  # fmt: skip

    def make_request(self, method, params):
        self.calls.append(method)
        if method == "eth_chainId":
            result = hex(self.chain)
        elif method == "eth_getBlockByNumber":
            result = {
                "number": "0x7",
                "timestamp": hex(self.timestamp),
                "hash": "0x" + "ab" * 32,
                "baseFeePerGas": "0x1",
            }
        elif method == "eth_getCode":
            result = "0x" + self.code.hex()
        elif method == "eth_call":
            data = params[0]["data"]
            if data.startswith(REGISTRY_HEAD):
                result = encode(["(bytes32,uint256,uint64,uint64,uint64,uint64,bool)"], [self.registry_head])
            elif data.startswith(CHECKPOINT_HEAD):
                result = encode(["(bytes32,uint256,uint64,uint64,uint64,uint64,uint64)"], [self.checkpoint_head])
            elif data.startswith(PUBLISHERS):
                result = encode(["address"], [self.publisher])
            elif data.startswith(EPOCHS):
                result = encode(["uint64"], [self.epoch])
            elif data.startswith(PAUSED):
                result = encode(["bool"], [self.paused])
            else:
                raise AssertionError(f"Unexpected call {data[:10]}")
            result = "0x" + result.hex()
        elif method == "eth_getTransactionCount":
            result = hex(len(self.sent))
        elif method in ("eth_estimateGas", "eth_maxPriorityFeePerGas", "eth_gasPrice"):
            result = "0x5208"
        elif method == "eth_sendRawTransaction":
            self.sent.append(params[0])
            self.publish()
            result = "0x" + "cd" * 32
        elif method == "eth_getTransactionReceipt":
            result = {
                "transactionHash": "0x" + "cd" * 32,
                "status": hex(self.status),
                "blockNumber": "0x8",
                "blockHash": "0x" + "ef" * 32,
                "logs": [],
                "transactionIndex": "0x0",
                "cumulativeGasUsed": "0x1",
                "gasUsed": "0x1",
                "contractAddress": None,
                "from": "0x" + "00" * 20,
                "to": CONTRACT,
                "logsBloom": "0x" + "00" * 256,
                "effectiveGasPrice": "0x1",
                "type": "0x2",
            }
        else:
            raise AssertionError(f"Unexpected RPC operation: {method}")
        return {"jsonrpc": "2.0", "id": 1, "result": result}


@pytest.fixture
def case(tmp_path):
    tree, signed, trust = sanctions_case()
    account = Account.create()
    (tmp_path / "tree.json").write_text(json.dumps(tree.artifact()))
    (tmp_path / "approval.json").write_text(signed.model_dump_json())
    authorities = [a.model_dump(mode="json") for a in trust._authorities]
    (tmp_path / "trust.json").write_text(json.dumps(authorities))
    provider = ChainProvider(signed.snapshot, account.address)
    argv = [
        "--artifact", str(tmp_path / "tree.json"),
        "--approval", str(tmp_path / "approval.json"),
        "--trust", str(tmp_path / "trust.json"),
        "--contract", CONTRACT,
        "--chain-id", "31337",
        "--runtime-sha256", hashlib.sha256(CODE).hexdigest(),
    ]  # fmt: skip
    environ = {"PILOT_PUBLISHER_PRIVATE_KEY": account.key.hex(), "SKIP_CONFIRM": "1"}
    return provider, argv, environ, tmp_path


def run(case, *extra, prompt=None, environ=None, argv=None):
    provider, base, env, _ = case
    return cli.main(
        (argv if argv is not None else base) + list(extra),
        web3=Web3(provider),
        prompt=prompt or (lambda _: pytest.fail("unexpected prompt")),
        environ=env if environ is None else environ,
        clock=lambda: 150,
    )


@pytest.mark.parametrize("target", ["registry", "checkpoint"])
def test_broadcast_publishes_and_reads_back(case, target, capsys):
    provider, _, _, _ = case
    assert run(case, "--target", target) == 0
    assert len(provider.sent) == 1
    out = capsys.readouterr().out
    assert '"already_current": false' in out and "Published sanctions head in block 8" in out
    # The approval is now current, so a second run sends nothing.
    assert run(case, "--target", target) == 0
    assert len(provider.sent) == 1
    assert "Nothing to do" in capsys.readouterr().out


def test_dry_run_prints_plan_without_key_or_send(case, capsys):
    provider, _, _, _ = case
    assert run(case, "--dry-run", environ={}) == 0
    assert provider.sent == [] and "Dry run" in capsys.readouterr().out
    assert "eth_sendRawTransaction" not in provider.calls


@pytest.mark.parametrize("answer,code,sent", [("no", 1, 0), (" publish ", 0, 1)])
def test_interactive_confirmation_is_required(case, answer, code, sent):
    provider, _, environ, _ = case
    prompts = []
    result = run(case, environ={**environ, "SKIP_CONFIRM": "0"}, prompt=lambda text: prompts.append(text) or answer)
    assert (result, len(provider.sent), len(prompts)) == (code, sent, 1)


def test_republish_after_publisher_epoch_change(case):
    provider, _, _, _ = case
    assert run(case) == 0
    provider.epoch = 2
    assert run(case) == 0
    assert len(provider.sent) == 2


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda p, e: p.__setattr__("chain", 1), "chain ID"),
        (lambda p, e: p.__setattr__("timestamp", 150 - 601), "stale"),
        (lambda p, e: p.__setattr__("timestamp", 150 + 301), "stale"),
        (lambda p, e: p.__setattr__("code", b""), "pinned bytecode"),
        (lambda p, e: p.__setattr__("code", b"other"), "pinned bytecode"),
        (lambda p, e: p.__setattr__("publisher", "0x" + "00" * 20), "disabled"),
        (lambda p, e: p.__setattr__("paused", True), "paused"),
        (lambda p, e: e.pop("PILOT_PUBLISHER_PRIVATE_KEY"), "PRIVATE_KEY is required"),
        (lambda p, e: e.__setitem__("PILOT_PUBLISHER_PRIVATE_KEY", Account.create().key.hex()), "not the configured"),
        (lambda p, e: p.__setattr__("status", 0), "reverted"),
        (lambda p, e: p.__setattr__("after", "wrong"), "after inclusion"),
    ],
)
def test_failures_are_reported_without_success(case, mutate, message, capsys):
    provider, _, environ, _ = case
    environ = dict(environ)
    mutate(provider, environ)
    assert run(case, environ=environ) == 1
    assert message in capsys.readouterr().err


def test_checkpoint_post_inclusion_mismatch_is_reported(case, capsys):
    provider, _, _, _ = case
    provider.after = "wrong"
    assert run(case, "--target", "checkpoint") == 1
    assert "after inclusion" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flag,value,message",
    [
        ("--contract", "0x" + "AB" * 20, "canonical nonzero"),
        ("--contract", "0x" + "00" * 20, "canonical nonzero"),
        ("--runtime-sha256", "A" * 64, "runtime SHA-256"),
    ],
)
def test_configuration_rejected_before_rpc(case, flag, value, message, capsys):
    provider, argv, _, _ = case
    changed = list(argv)
    changed[changed.index(flag) + 1] = value
    assert run(case, argv=changed) == 1
    assert message in capsys.readouterr().err and provider.calls == []


def test_trust_file_must_be_a_list(case, capsys):
    _, _, _, tmp_path = case
    (tmp_path / "trust.json").write_text("{}")
    assert run(case) == 1
    assert "JSON list" in capsys.readouterr().err


def test_altered_artifact_is_rejected_before_rpc(case, capsys):
    provider, _, _, tmp_path = case
    artifact = json.loads((tmp_path / "tree.json").read_text())
    artifact["sorted_addresses"].reverse()
    (tmp_path / "tree.json").write_text(json.dumps(artifact))
    assert run(case) == 1
    assert "strictly sorted" in capsys.readouterr().err and provider.calls == []


def test_rpc_url_is_required_without_injected_client(case, capsys):
    _, argv, environ, _ = case
    assert cli.main(argv, environ=environ) == 1
    assert "--rpc-url" in capsys.readouterr().err


def test_rpc_url_constructs_http_client(case, monkeypatch):
    provider, argv, environ, _ = case
    created = []

    def http(url, request_kwargs):
        created.append((url, request_kwargs))
        return provider

    monkeypatch.setattr(cli, "HTTPProvider", http)
    monkeypatch.setattr(cli.time, "time", lambda: 150)
    assert cli.main(argv + ["--rpc-url", "http://127.0.0.1:8545", "--dry-run"], environ=environ) == 0
    assert created == [("http://127.0.0.1:8545", {"timeout": 30})]


def test_cli_entry_reports_missing_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [cli.__file__, "--approval", str(tmp_path / "missing.json"), "--trust", "x", "--contract", CONTRACT,
         "--chain-id", "1", "--runtime-sha256", "0" * 64],
    )  # fmt: skip
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(cli.__file__, run_name="__main__")
    assert exit_info.value.code == 1
