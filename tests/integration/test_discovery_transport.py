"""Real loopback TLS with explicit per-authority policy; no public network calls."""

from __future__ import annotations

import asyncio
import copy
import json
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.protocol.discovery import DiscoveryClient
from src.protocol.discovery_profile import DiscoveryInvalid, DiscoveryUnavailable, DiscoveryUnsupported
from src.protocol.discovery_transport import EgressPolicy

DOCUMENT = json.loads((Path(__file__).resolve().parents[2] / "specs/fixtures/discovery-0.4.0.json").read_text())


@pytest.fixture
async def tls_endpoint(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "beneficiary.example")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("beneficiary.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cafile=str(cert_path))
    state = SimpleNamespace(
        status=200,
        body=None,
        content_type="application/json",
        encoding="identity",
        requests=[],
        sni=[],
        delay=0,
        tasks=set(),
    )
    server_context.set_servername_callback(lambda sock, name, ctx: state.sni.append(name))

    async def handle(reader, writer):
        state.tasks.add(asyncio.current_task())
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            state.requests.append(request)
            await asyncio.sleep(state.delay)
            body = state.body if state.body is not None else json.dumps(state.document).encode()
            headers = (
                f"HTTP/1.1 {state.status} Test\r\nContent-Type: {state.content_type}\r\n"
                f"Content-Encoding: {state.encoding}\r\nContent-Length: {len(body)}\r\n"
                "Location: https://169.254.169.254/credentials\r\nConnection: close\r\n\r\n"
            ).encode()
            writer.write(headers + body)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            state.tasks.discard(asyncio.current_task())

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    state.authority = f"beneficiary.example:{port}"
    state.document = copy.deepcopy(DOCUMENT)
    state.document["vasp"]["did"] = f"did:web:beneficiary.example%3A{port}"
    state.document["clearproof"]["endpoint"] = f"https://{state.authority}/clearproof/v1"
    state.resolver = AsyncMock(return_value=["127.0.0.1"])
    state.options = dict(
        policy=EgressPolicy({state.authority: ["127.0.0.1/32"]}),
        resolver=state.resolver,
        ssl_context=client_context,
        cache_ttl=0,
    )
    try:
        yield state
    finally:
        server.close()
        await server.wait_closed()
        for task in list(state.tasks):
            task.cancel()
        await asyncio.gather(*state.tasks, return_exceptions=True)


async def test_real_tls_retains_identity_and_pins_dns(tls_endpoint, monkeypatch):
    state = tls_endpoint
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    client = DiscoveryClient(**state.options)
    assert await client.discover(state.authority) == state.document
    state.resolver.assert_awaited_once_with("beneficiary.example", int(state.authority.split(":")[1]))
    assert state.sni == ["beneficiary.example"]
    assert state.requests[0].startswith(b"GET /.well-known/clearproof.json HTTP/1.1\r\n")
    assert f"Host: {state.authority}".lower().encode() in state.requests[0].lower()
    # A later DNS answer cannot reuse a vetted connection or evade the policy.
    state.resolver.return_value = ["169.254.169.254"]
    with pytest.raises(DiscoveryInvalid, match="disallowed"):
        await client.discover(state.authority)
    assert len(state.requests) == 1


async def test_default_policy_and_mixed_answers_block_before_connect(tls_endpoint):
    state = tls_endpoint
    with pytest.raises(DiscoveryInvalid, match="disallowed"):
        await DiscoveryClient(resolver=state.resolver).discover(state.authority)
    state.resolver.return_value = ["8.8.8.8", "127.0.0.1"]
    with pytest.raises(DiscoveryInvalid, match="disallowed"):
        await DiscoveryClient(resolver=state.resolver).discover(state.authority)
    assert state.requests == []
    assert state.sni == []


async def test_tls_certificate_and_hostname_are_required(tls_endpoint):
    state = tls_endpoint
    options = {**state.options, "ssl_context": None}
    with pytest.raises(DiscoveryUnavailable):
        await DiscoveryClient(**options).discover(state.authority)
    wrong = state.authority.replace("beneficiary", "wrong")
    options = {**state.options, "policy": EgressPolicy({wrong: ["127.0.0.1/32"]})}
    with pytest.raises(DiscoveryUnavailable):
        await DiscoveryClient(**options).discover(wrong)
    insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    with pytest.raises(DiscoveryInvalid, match="TLS"):
        await DiscoveryClient(**{**state.options, "ssl_context": insecure}).discover(state.authority)
    assert state.requests == []


@pytest.mark.parametrize(
    "status,error",
    [
        (301, DiscoveryInvalid),
        (302, DiscoveryInvalid),
        (307, DiscoveryInvalid),
        (404, DiscoveryUnsupported),
        (503, DiscoveryUnavailable),
    ],
)
async def test_http_results_never_redirect_or_downgrade(tls_endpoint, status, error):
    state = tls_endpoint
    state.status = status
    with pytest.raises(error):
        await DiscoveryClient(**state.options).discover(state.authority)
    assert state.resolver.await_count == 1
    assert len(state.requests) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("content_type", "text/html"),
        ("encoding", "gzip"),
        ("body", b"{invalid"),
        ("body", b"\xff"),
        ("body", b" " * 65537),
    ],
)
async def test_bounded_response_policy(tls_endpoint, field, value):
    state = tls_endpoint
    setattr(state, field, value)
    with pytest.raises(DiscoveryInvalid):
        await DiscoveryClient(**state.options).discover(state.authority)


async def test_deadline_covers_dns_and_response_body(tls_endpoint):
    state = tls_endpoint

    async def slow_dns(*args):
        await asyncio.sleep(10)
        return ["127.0.0.1"]

    with pytest.raises(DiscoveryUnavailable):
        await DiscoveryClient(**{**state.options, "resolver": slow_dns}, timeout=0.03).discover(state.authority)
    state.delay = 10
    with pytest.raises(DiscoveryUnavailable):
        await DiscoveryClient(**state.options, timeout=0.1).discover(state.authority)
