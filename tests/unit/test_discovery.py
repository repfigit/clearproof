"""
Tests for counterparty discovery (src/protocol/discovery.py) and the
well-known serving endpoint (src/api/routes/discovery.py).
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from src.protocol.discovery import (
    DiscoveryError,
    clear_discovery_cache,
    resolve_hpke_public_key,
)
from src.sar.hpke_envelope import derive_key_id, generate_keypair

b64e = lambda b: base64.urlsafe_b64encode(b).decode("ascii")  # noqa: E731


def _mock_client(doc: dict | None, status: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if doc is None:
            return httpx.Response(status, text="not found")
        return httpx.Response(status, text=json.dumps(doc))

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _flush_cache():
    clear_discovery_cache()
    yield
    clear_discovery_cache()


@pytest.fixture()
def counterparty_doc() -> dict:
    _, pub = generate_keypair()
    return {
        "version": "0.3.0",
        "vasp": {"did": "did:web:beneficiary.example"},
        "clearproof": {
            "endpoint": "https://beneficiary.example/clearproof/v1",
            "hpkePublicKey": b64e(pub),
            "hpkeKeyId": derive_key_id(pub),
            "hpkeSuites": ["DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM"],
            "supportedChains": [1, 11155111],
            "proofFormat": "groth16",
        },
    }


class TestResolve:
    async def test_resolves_hpke_key(self, counterparty_doc: dict) -> None:
        client = _mock_client(counterparty_doc)
        key = await resolve_hpke_public_key("did:web:beneficiary.example", http_client=client)
        expected = base64.urlsafe_b64decode(counterparty_doc["clearproof"]["hpkePublicKey"])
        assert key == expected

    async def test_bare_domain_accepted(self, counterparty_doc: dict) -> None:
        client = _mock_client(counterparty_doc)
        key = await resolve_hpke_public_key("beneficiary.example", http_client=client)
        assert key is not None

    async def test_did_web_path_segments_ignored(self, counterparty_doc: dict) -> None:
        client = _mock_client(counterparty_doc)
        key = await resolve_hpke_public_key("did:web:beneficiary.example:vasps:eu", http_client=client)
        assert key is not None

    async def test_missing_hpke_key_returns_none(self) -> None:
        doc = {"version": "0.2.0", "clearproof": {"endpoint": "https://x", "publicKey": "age1..."}}
        client = _mock_client(doc)
        assert await resolve_hpke_public_key("legacy.example", http_client=client) is None

    async def test_404_raises_discovery_error(self) -> None:
        client = _mock_client(None, status=404)
        with pytest.raises(DiscoveryError, match="404"):
            await resolve_hpke_public_key("unknown.example", http_client=client)

    async def test_invalid_json_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="{not json")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with pytest.raises(DiscoveryError, match="valid JSON"):
            await resolve_hpke_public_key("broken.example", http_client=client)

    async def test_wrong_key_length_raises(self) -> None:
        doc = {"clearproof": {"hpkePublicKey": b64e(b"too-short")}}
        client = _mock_client(doc)
        with pytest.raises(DiscoveryError, match="32 bytes"):
            await resolve_hpke_public_key("badkey.example", http_client=client)

    async def test_cache_avoids_second_fetch(self, counterparty_doc: dict) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200, text=json.dumps(counterparty_doc))

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        await resolve_hpke_public_key("cached.example", http_client=client)
        await resolve_hpke_public_key("cached.example", http_client=client)
        assert calls == 1


class TestWellKnownServing:
    async def test_document_contains_hpke_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        priv, pub = generate_keypair()
        monkeypatch.setenv("VASP_DOMAIN", "originator.example")
        monkeypatch.setenv("VASP_HPKE_PRIVATE_KEY", b64e(priv))
        monkeypatch.delenv("VASP_HPKE_PUBLIC_KEY", raising=False)

        from src.api.routes.discovery import build_discovery_document

        doc = build_discovery_document()
        cp = doc["clearproof"]
        assert cp["hpkePublicKey"] == b64e(pub)  # derived from private key
        assert cp["hpkeKeyId"] == derive_key_id(pub)
        assert cp["hpkeSuites"] == ["DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM"]
        assert cp["supportedChains"] == [1, 11155111]

    async def test_explicit_public_key_preferred(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _, pub = generate_keypair()
        monkeypatch.setenv("VASP_DOMAIN", "originator.example")
        monkeypatch.setenv("VASP_HPKE_PUBLIC_KEY", b64e(pub))

        from src.api.routes.discovery import build_discovery_document

        doc = build_discovery_document()
        assert doc["clearproof"]["hpkePublicKey"] == b64e(pub)

    async def test_missing_domain_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VASP_DOMAIN", raising=False)
        from src.api.routes.discovery import build_discovery_document

        with pytest.raises(RuntimeError, match="VASP_DOMAIN"):
            build_discovery_document()

    async def test_document_without_hpke_key_omits_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VASP_DOMAIN", "originator.example")
        monkeypatch.delenv("VASP_HPKE_PUBLIC_KEY", raising=False)
        monkeypatch.delenv("VASP_HPKE_PRIVATE_KEY", raising=False)

        from src.api.routes.discovery import build_discovery_document

        doc = build_discovery_document()
        assert "hpkePublicKey" not in doc["clearproof"]


class TestRoundTripThroughDiscovery:
    async def test_seal_to_discovered_key(self, counterparty_doc: dict) -> None:
        """End-to-end: discover a counterparty key and seal an envelope to it."""
        from src.sar.hpke_envelope import open_envelope, seal_envelope

        # The private key behind the published document (held by "counterparty").
        # Regenerate to recover the pair: the doc fixture used a fresh pair, so
        # here we build our own doc from a known pair instead.
        priv, pub = generate_keypair()
        doc = dict(counterparty_doc)
        doc["clearproof"] = {**counterparty_doc["clearproof"], "hpkePublicKey": b64e(pub)}
        client = _mock_client(doc)

        key = await resolve_hpke_public_key("rt.example", http_client=client)
        envelope = seal_envelope(b"pii payload", key, "proof-rt-1")
        assert envelope["kid"] == derive_key_id(pub)
        assert open_envelope(envelope, priv) == b"pii payload"
