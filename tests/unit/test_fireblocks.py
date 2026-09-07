"""Local signed V2 notification simulator; no Fireblocks account or keys used."""

import json
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from src.adapters.fireblocks import FireblocksBinding, FireblocksError, FireblocksVerifier, b64encode
from src.reconciliation.events import TransferEvent, TransferScope, reconcile

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/fireblocks/transaction-status-v2.json"
NOW = 1700000001000


@pytest.fixture
def setup():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk = {k: jwk[k] for k in ("kty", "n", "e")}
    jwk.update(kid="synthetic-key", alg="RS512", use="sig")
    inventory = json.dumps({"keys": [jwk]}).encode()
    verifier = FireblocksVerifier(inventory, valid_from=NOW - 100000, valid_until=NOW + 100000)
    binding = FireblocksBinding(
        workspace_id="33333333-3333-4333-8333-333333333333",
        transaction_id="22222222-2222-4222-8222-222222222222",
        external_transaction_id="synthetic-transfer-a",
        provider_asset_id="USDC_ETH_TEST3",
        source_id="fireblocks-simulator",
        scope=TransferScope(
            tenant_id="tenant-a", transfer_id="transfer-a", chain_id="1", registry_address="0x" + "12" * 20
        ),
    )
    return verifier, key, binding, inventory


def sign(raw, key, **headers):
    full = jwt.api_jws.encode(raw, key, algorithm="RS512", headers={"kid": "synthetic-key", "typ": None, **headers})
    header, _, signature = full.split(".")
    return header + ".." + signature


def test_signed_fixture_maps_custody_without_finality_or_private_fields(setup):
    verifier, key, binding, _ = setup
    raw = FIXTURE.read_bytes()
    event = verifier.verify(raw, sign(raw, key), binding, now_ms=NOW)
    assert event.state == "completed" and event.dimension == "custody"
    assert event.source_sequence == 1700000000000 and event.occurred_at == 1700000000
    assert "synthetic-private-marker" not in event.model_dump_json()
    report = reconcile(binding.scope, (TransferEvent(**event.model_dump(), ingested_at=NOW // 1000),), now=NOW // 1000)
    assert report.states["chain"] == report.states["compliance"] == "unknown"


@pytest.mark.parametrize(
    "change",
    [
        {"workspaceId": "other"},
        {"resourceId": "other"},
        {"eventType": "transaction.approval_status.updated"},
        {"createdAt": NOW + 1},
        {"createdAt": True},
    ],
)
def test_signed_wrong_scope_type_or_time_rejected(setup, change):
    verifier, key, binding, _ = setup
    raw = json.dumps({**json.loads(FIXTURE.read_bytes()), **change}).encode()
    with pytest.raises(FireblocksError):
        verifier.verify(raw, sign(raw, key), binding, now_ms=NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "other"),
        ("externalTxId", "other"),
        ("assetId", "USDC_OTHER"),
        ("operation", "RAW"),
        ("status", "UNKNOWN_NEW_STATUS"),
    ],
)
def test_signed_wrong_transaction_mapping_and_unsupported_status_rejected(setup, field, value):
    verifier, key, binding, _ = setup
    payload = json.loads(FIXTURE.read_bytes())
    payload["data"][field] = value
    raw = json.dumps(payload).encode()
    with pytest.raises(FireblocksError):
        verifier.verify(raw, sign(raw, key), binding, now_ms=NOW)


def test_wrong_key_body_mutation_and_header_extensions_reject(setup):
    verifier, key, binding, _ = setup
    raw = FIXTURE.read_bytes()
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attempts = [
        (raw + b" ", sign(raw, key)),
        (raw, sign(raw, wrong)),
        (raw, sign(raw, key, kid="unknown")),
        (raw, sign(raw, key, jku="https://attacker.invalid/keys")),
        (raw, sign(raw, key, crit=["b64"], b64=False)),
        (raw, "e30.." + b64encode(b"x")),
    ]
    for body, signature in attempts:
        with pytest.raises(FireblocksError):
            verifier.verify(body, signature, binding, now_ms=NOW)


def test_key_expiry_and_duplicates_fail_closed(setup):
    verifier, key, binding, inventory = setup
    raw = FIXTURE.read_bytes()
    with pytest.raises(FireblocksError):
        verifier.verify(raw, sign(raw, key), binding, now_ms=NOW + 100000)
    value = json.loads(inventory)
    value["keys"] *= 2
    with pytest.raises(ValueError):
        FireblocksVerifier(json.dumps(value).encode(), valid_from=1, valid_until=NOW + 10000)
    duplicate = b'{"id":"duplicate",' + raw.lstrip()[1:]
    with pytest.raises(FireblocksError):
        verifier.verify(duplicate, sign(duplicate, key), binding, now_ms=NOW)
    with pytest.raises(FireblocksError):
        verifier.verify(b"x" * 65537, sign(raw, key), binding, now_ms=NOW)


@pytest.mark.parametrize("segment", ["", "AA=", "+A", "AB"])
def test_detached_segments_reject_noncanonical_base64url(segment):
    from src.adapters.fireblocks import decode_segment

    with pytest.raises(FireblocksError):
        decode_segment(segment)
    assert decode_segment("AA") == b"\0"


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"valid_from": True}, "key snapshot interval"),
        ({"valid_until": "100"}, "key snapshot interval"),
        ({"valid_from": -1}, "key snapshot interval"),
        ({"valid_from": 10, "valid_until": 10}, "key snapshot interval"),
        ({"valid_until": 2**53}, "key snapshot interval"),
        ({"max_age_ms": True}, "notification age bound"),
        ({"max_age_ms": 0}, "notification age bound"),
        ({"max_age_ms": 30 * 86400000 + 1}, "notification age bound"),
    ],
)
def test_operator_key_configuration_bounds(setup, changes, message):
    _, _, _, inventory = setup
    with pytest.raises(ValueError, match=message):
        FireblocksVerifier(inventory, **{"valid_from": 1, "valid_until": NOW, **changes})


@pytest.mark.parametrize(
    "inventory", [None, [], {}, {"keys": {}}, {"keys": []}, {"keys": [None] * 17}, {"keys": [], "extra": 1}]
)
def test_invalid_jwks_inventory_rejected(inventory):
    with pytest.raises(ValueError, match="Invalid JWKS inventory"):
        FireblocksVerifier(json.dumps(inventory).encode(), valid_from=1, valid_until=NOW)


def test_undersized_real_rsa_key_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk = {k: jwk[k] for k in ("kty", "n", "e")}
    jwk.update(kid="synthetic-small-key", alg="RS512", use="sig")
    with pytest.raises(ValueError, match="Unsupported RSA key size"):
        FireblocksVerifier(json.dumps({"keys": [jwk]}).encode(), valid_from=1, valid_until=NOW)


@pytest.mark.parametrize("signature", ["no-dots", "header.payload.signature", "header...signature"])
def test_signature_requires_three_parts_and_detached_payload(setup, signature):
    verifier, _, binding, _ = setup
    with pytest.raises(FireblocksError, match="Webhook signature, scope or payload rejected"):
        verifier.verify(FIXTURE.read_bytes(), signature, binding, now_ms=NOW)
