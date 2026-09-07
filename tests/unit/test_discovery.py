"""Cross-language profile vectors, publishing and cache trust boundaries."""

from __future__ import annotations

import asyncio
import base64
import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.protocol.discovery import DiscoveryClient
from src.protocol.discovery_profile import (
    DiscoveryInvalid,
    DiscoveryUnavailable,
    DiscoveryUnsupported,
    decode_hpke_key,
    parse_target,
    validate_document,
)
from src.protocol.discovery_transport import EgressPolicy, PinnedBackend

FIXTURES = Path(__file__).resolve().parents[2] / "specs/fixtures"
DOCUMENT = json.loads((FIXTURES / "discovery-0.4.0.json").read_text())
INVALID = json.loads((FIXTURES / "discovery-invalid.json").read_text())
NETWORK = json.loads((FIXTURES / "discovery-network.json").read_text())


@pytest.mark.parametrize("case", INVALID, ids=lambda c: f"{c['path']}={c['value']}")
def test_shared_invalid_vectors(case):
    doc = copy.deepcopy(DOCUMENT)
    parent = doc
    parts = case["path"].split(".")
    for part in parts[:-1]:
        parent = parent[part]
    parent[parts[-1]] = case["value"]
    error = DiscoveryUnsupported if case["error"] == "unsupported" else DiscoveryInvalid
    with pytest.raises(error):
        validate_document(doc, parse_target("beneficiary.example"))


def test_full_did_path_is_identity():
    target = parse_target("did:web:beneficiary.example%3A8443:vasps:eu")
    assert target.url == "https://beneficiary.example:8443/.well-known/clearproof.json"
    doc = copy.deepcopy(DOCUMENT)
    with pytest.raises(DiscoveryInvalid, match="identity"):
        validate_document(doc, target)
    doc["vasp"]["did"] = target.did
    doc["clearproof"]["endpoint"] = "https://beneficiary.example:8443/clearproof/v1"
    assert validate_document(doc, target) == doc


@pytest.mark.parametrize(
    "identity",
    [
        "127.0.0.1",
        "169.254.169.254",
        "2130706433",
        "0x7f000001",
        "[::1]",
        "localhost",
        "https://x.example/",
        "x.example/other",
        "x.example@evil.example",
        "x.example?query",
        "x.example#fragment",
        "X.example",
        "x.example.",
        "x.example:443",
        "x.example:0",
        "x.example:65536",
        "x.example\n",
        "did:web:x.example:..",
        "did:web:x.example%3a8443",
        "did:web:x.example:alice\n",
        "did:web:x.example:a%2fb",
    ],
)
def test_ambiguous_or_unsupported_targets(identity):
    with pytest.raises(DiscoveryInvalid):
        parse_target(identity)


@pytest.mark.parametrize("case", NETWORK, ids=lambda c: c["address"])
def test_shared_network_policy(case):
    assert EgressPolicy().permits("beneficiary.example", case["address"]) is case["allowed"]


def test_private_policy_is_exact_and_defensively_copied():
    config = {"beneficiary.example:8443": ["10.0.0.0/8"]}
    policy = EgressPolicy(config)
    config["beneficiary.example:8443"].append("127.0.0.0/8")
    assert policy.permits("beneficiary.example:8443", "10.1.2.3")
    assert not policy.permits("beneficiary.example", "10.1.2.3")
    assert not policy.permits("other.example:8443", "10.1.2.3")
    assert not policy.permits("beneficiary.example:8443", "127.0.0.1")


async def test_backend_pins_the_actual_connected_ip():
    resolver = AsyncMock(return_value=["8.8.8.8", "1.1.1.1"])
    backend = PinnedBackend(parse_target("beneficiary.example"), EgressPolicy(), resolver)
    connector = AsyncMock()
    backend.backend = connector
    await backend.connect_tcp("beneficiary.example", 443)
    assert connector.connect_tcp.call_args.args == ("8.8.8.8", 443)
    resolver.assert_awaited_once_with("beneficiary.example", 443)
    resolver.return_value = ["8.8.8.8", "169.254.169.254"]
    with pytest.raises(DiscoveryInvalid):
        await backend.connect_tcp("beneficiary.example", 443)
    assert connector.connect_tcp.await_count == 1


async def test_cache_isolation_expiry_and_defensive_copy(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("src.protocol.discovery.time.monotonic", lambda: clock[0])
    fetch = AsyncMock(return_value=DOCUMENT)
    monkeypatch.setattr("src.protocol.discovery.fetch_document", fetch)
    a, b = DiscoveryClient(cache_ttl=5), DiscoveryClient()
    first = await a.discover("beneficiary.example")
    first["clearproof"]["hpkeKeyId"] = "changed"
    assert (await a.discover("did:web:beneficiary.example")) == DOCUMENT
    assert fetch.await_count == 1
    await b.discover("beneficiary.example")
    assert fetch.await_count == 2
    clock[0] = 105
    await a.discover("beneficiary.example")
    assert fetch.await_count == 3
    a.clear_cache()
    fetch.side_effect = DiscoveryUnavailable("offline")
    with pytest.raises(DiscoveryUnavailable):
        await a.discover("beneficiary.example")
    fetch.side_effect = None
    await a.discover("beneficiary.example")
    assert fetch.await_count == 5


async def test_invalidation_fences_inflight_response(monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()

    async def fetch(*args):
        entered.set()
        await release.wait()
        return DOCUMENT

    monkeypatch.setattr("src.protocol.discovery.fetch_document", fetch)
    client = DiscoveryClient()
    task = asyncio.create_task(client.discover("beneficiary.example"))
    await entered.wait()
    client.clear_cache()
    release.set()
    await task
    assert not client._cache


async def test_cache_zero_and_bounded_size(monkeypatch):
    async def fetch(target, *args):
        doc = copy.deepcopy(DOCUMENT)
        doc["vasp"]["did"] = target.did
        doc["clearproof"]["endpoint"] = f"https://{target.authority}/clearproof/v1"
        return doc

    monkeypatch.setattr("src.protocol.discovery.fetch_document", fetch)
    client = DiscoveryClient(cache_ttl=0)
    await client.discover("beneficiary.example")
    assert not client._cache
    bounded = DiscoveryClient()
    for index in range(130):
        await bounded.discover(f"{index}.example")
    assert len(bounded._cache) == 128


@pytest.mark.parametrize(
    "option,value", [("cache_ttl", -1), ("cache_ttl", float("nan")), ("timeout", 0), ("timeout", 61)]
)
def test_invalid_options(option, value):
    with pytest.raises(ValueError):
        DiscoveryClient(**{option: value})


@pytest.fixture
def publisher_env(monkeypatch):
    for name in (
        "VASP_DID",
        "VASP_HPKE_PRIVATE_KEY",
        "CLEARPROOF_ENDPOINT",
        "SUPPORTED_CHAINS",
        "VASP_NAME",
        "VASP_JURISDICTION",
        "COMPLIANCE_CONTACT",
        "TECHNICAL_CONTACT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VASP_DOMAIN", "beneficiary.example")
    monkeypatch.setenv("VASP_HPKE_PUBLIC_KEY", DOCUMENT["clearproof"]["hpkePublicKey"])


def test_python_publisher_reproduces_shared_fixture(publisher_env):
    from src.api.routes.discovery import build_discovery_document

    doc, expected = build_discovery_document(), copy.deepcopy(DOCUMENT)
    doc.pop("updatedAt")
    expected.pop("updatedAt")
    assert doc == expected
    assert validate_document(doc, parse_target("beneficiary.example")) == doc


def test_publisher_rejects_missing_key_or_wrong_identity(publisher_env, monkeypatch):
    from src.api.routes.discovery import build_discovery_document

    monkeypatch.setenv("VASP_DID", "did:web:other.example")
    with pytest.raises(RuntimeError, match="VASP_DID"):
        build_discovery_document()
    monkeypatch.delenv("VASP_DID")
    monkeypatch.delenv("VASP_HPKE_PUBLIC_KEY")
    with pytest.raises(RuntimeError, match="HPKE key"):
        build_discovery_document()


def test_publisher_requires_matching_keypair(publisher_env, monkeypatch):
    from src.api.routes.discovery import build_discovery_document
    from src.sar.hpke_envelope import generate_keypair

    private, public = generate_keypair()
    monkeypatch.setenv("VASP_HPKE_PRIVATE_KEY", base64.urlsafe_b64encode(private).decode())
    with pytest.raises(RuntimeError, match="do not match"):
        build_discovery_document()
    monkeypatch.delenv("VASP_HPKE_PUBLIC_KEY")
    assert decode_hpke_key(build_discovery_document()["clearproof"]["hpkePublicKey"]) == public


async def test_api_default_cache_is_replaced_when_operator_policy_changes(monkeypatch):
    import src.protocol.discovery as discovery

    monkeypatch.setattr(discovery, "_default_client", DiscoveryClient())
    monkeypatch.setattr(discovery, "_default_settings", ("{}", None, None))
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("DISCOVERY_PRIVATE_DESTINATIONS", "{}")
    fetch = AsyncMock(return_value=DOCUMENT)
    monkeypatch.setattr(discovery, "fetch_document", fetch)
    await discovery.resolve_hpke_public_key("beneficiary.example")
    await discovery.resolve_hpke_public_key("beneficiary.example")
    assert fetch.await_count == 1
    monkeypatch.setenv("DISCOVERY_PRIVATE_DESTINATIONS", '{"beneficiary.example":["10.0.0.0/8"]}')
    await discovery.resolve_hpke_public_key("beneficiary.example")
    assert fetch.await_count == 2
    assert fetch.call_args.args[1].permits("beneficiary.example", "10.1.2.3")
    monkeypatch.setenv("DISCOVERY_PRIVATE_DESTINATIONS", '{"beneficiary.example":"10.0.0.0/8"}')
    with pytest.raises(DiscoveryInvalid, match="operator"):
        await discovery.resolve_hpke_public_key("beneficiary.example")
    assert fetch.await_count == 2


def test_numeric_chain_semantics_match_json_consumers():
    doc = copy.deepcopy(DOCUMENT)
    doc["clearproof"]["supportedChains"] = [1.0]
    assert validate_document(doc, parse_target("beneficiary.example")) == doc
    doc["clearproof"]["supportedChains"] = [10**400]
    with pytest.raises(DiscoveryInvalid):
        validate_document(doc, parse_target("beneficiary.example"))


@pytest.mark.parametrize("integer", [0, 1, 2**255 - 20, 2**255 - 19, 2**255 - 18, 2**255 + 9])
def test_rejects_low_order_and_noncanonical_x25519_points(integer):
    with pytest.raises(DiscoveryInvalid):
        decode_hpke_key(base64.urlsafe_b64encode(integer.to_bytes(32, "little")).decode())


async def test_publisher_http_advertises_optional_metadata(publisher_env, monkeypatch):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from src.api.routes.discovery import router

    for name, value in {
        "VASP_NAME": "Synthetic VASP",
        "VASP_JURISDICTION": "840",
        "COMPLIANCE_CONTACT": "synthetic-compliance@example.invalid",
        "TECHNICAL_CONTACT": "synthetic-technical@example.invalid",
        "SUPPORTED_CHAINS": "1, ,11155111,",
        "CLEARPROOF_ENDPOINT": "https://beneficiary.example/exchange/v1",
    }.items():
        monkeypatch.setenv(name, value)
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/.well-known/clearproof.json")
    assert response.status_code == 200
    doc = response.json()
    assert doc["vasp"]["name"] == "Synthetic VASP"
    assert doc["vasp"]["jurisdiction"] == "840"
    assert doc["contact"] == {
        "compliance": "synthetic-compliance@example.invalid",
        "technical": "synthetic-technical@example.invalid",
    }
    assert doc["clearproof"]["supportedChains"] == [1, 11155111]
    assert doc["clearproof"]["endpoint"] == "https://beneficiary.example/exchange/v1"


@pytest.mark.parametrize(
    "name,value",
    [
        ("VASP_DOMAIN", ""),
        ("VASP_DOMAIN", "https://beneficiary.example"),
        ("VASP_DID", "did:web:other.example"),
        ("SUPPORTED_CHAINS", "secret-invalid-chain"),
        ("SUPPORTED_CHAINS", "1,1"),
        ("CLEARPROOF_ENDPOINT", "http://beneficiary.example/exchange"),
        ("VASP_HPKE_PRIVATE_KEY", "é-private-secret"),
        ("VASP_HPKE_PRIVATE_KEY", base64.urlsafe_b64encode(b"short").decode()),
        ("VASP_HPKE_PRIVATE_KEY", "!" + base64.urlsafe_b64encode(b"x" * 32).decode()),
        ("VASP_HPKE_PUBLIC_KEY", "invalid-public-key"),
    ],
)
async def test_publisher_http_configuration_errors_are_minimized(publisher_env, monkeypatch, name, value):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from src.api.routes.discovery import router

    monkeypatch.setenv(name, value)
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/.well-known/clearproof.json")
    assert response.status_code == 503
    assert response.json() == {"detail": "Discovery is not configured correctly"}


def test_publisher_accepts_matching_private_and_public_keys(publisher_env, monkeypatch):
    from src.api.routes.discovery import get_own_hpke_public_key
    from src.sar.hpke_envelope import generate_keypair

    private, public = generate_keypair()
    monkeypatch.setenv("VASP_HPKE_PRIVATE_KEY", base64.urlsafe_b64encode(private).decode())
    monkeypatch.setenv("VASP_HPKE_PUBLIC_KEY", base64.urlsafe_b64encode(public).decode())
    assert get_own_hpke_public_key() == public


@pytest.mark.parametrize("target", [None, 1, "a" * 513])
def test_discovery_target_requires_bounded_string(target):
    with pytest.raises(DiscoveryInvalid, match="Expected a canonical domain or did:web identifier"):
        parse_target(target)


@pytest.mark.parametrize("coordinate", [2**255 - 19, 2**255, 2**256 - 1])
def test_discovery_key_rejects_noncanonical_x25519_coordinates(coordinate):
    encoded = base64.urlsafe_b64encode(coordinate.to_bytes(32, "little")).decode()
    with pytest.raises(DiscoveryInvalid, match="not a canonical X25519 point"):
        decode_hpke_key(encoded)


@pytest.mark.parametrize(
    "document,message",
    [
        (None, "Discovery document must be an object"),
        ([], "Discovery document must be an object"),
        ({}, "Discovery version is required"),
        ({"version": 4}, "Discovery version is required"),
    ],
)
def test_discovery_document_requires_object_and_version(document, message):
    with pytest.raises(DiscoveryInvalid, match=message):
        validate_document(document, parse_target("beneficiary.example"))


@pytest.mark.parametrize("capabilities", [None, [], "unsupported"])
def test_discovery_document_requires_capability_object(capabilities):
    document = {**DOCUMENT, "clearproof": capabilities}
    with pytest.raises(DiscoveryInvalid, match="Missing clearproof capabilities"):
        validate_document(document, parse_target("beneficiary.example"))


def test_discovery_key_rejects_base64_padding_bit_alias():
    encoded = DOCUMENT["clearproof"]["hpkePublicKey"].rstrip("=")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(encoded[-1])
    assert last % 4 == 0
    alias = encoded[:-1] + alphabet[last + 1]
    assert base64.urlsafe_b64decode(alias + "=") == base64.urlsafe_b64decode(encoded + "=")
    with pytest.raises(DiscoveryInvalid, match="HPKE public key has noncanonical encoding"):
        decode_hpke_key(alias)


@pytest.mark.parametrize("settings", ["[]", "null", '"synthetic"', "{", " " * 16385])
async def test_invalid_operator_egress_settings_do_not_replace_or_use_cached_client(monkeypatch, settings):
    import src.protocol.discovery as discovery

    client = DiscoveryClient()
    fetch = AsyncMock(return_value=DOCUMENT)
    monkeypatch.setattr(discovery, "fetch_document", fetch)
    await client.discover("beneficiary.example")
    assert client._cache
    monkeypatch.setattr(discovery, "_default_client", client)
    monkeypatch.setattr(discovery, "_default_settings", ("{}", None, None))
    monkeypatch.setenv("DISCOVERY_PRIVATE_DESTINATIONS", settings)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    with pytest.raises(DiscoveryInvalid, match="^Invalid operator discovery egress configuration$"):
        await discovery.resolve_hpke_public_key("beneficiary.example")
    assert discovery._default_client is client
    assert discovery._default_settings == ("{}", None, None)
    fetch.assert_awaited_once()


async def test_public_cache_clear_forces_key_refetch(monkeypatch):
    import src.protocol.discovery as discovery

    client = DiscoveryClient()
    monkeypatch.setattr(discovery, "_default_client", client)
    monkeypatch.setattr(discovery, "_default_settings", ("{}", None, None))
    monkeypatch.setenv("DISCOVERY_PRIVATE_DESTINATIONS", "{}")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    fetch = AsyncMock(return_value=DOCUMENT)
    monkeypatch.setattr(discovery, "fetch_document", fetch)
    first = await discovery.resolve_hpke_public_key("beneficiary.example")
    assert await discovery.resolve_hpke_public_key("beneficiary.example") == first
    fetch.assert_awaited_once()
    discovery.clear_discovery_cache()
    assert await discovery.resolve_hpke_public_key("beneficiary.example") == first
    assert fetch.await_count == 2
