"""HTTP wiring for wallet-ownership routes without PostgreSQL."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI

from src.api.config import WalletOwnershipConfig
from src.api.routes import wallet_ownership as routes
from src.auth.principal import Principal, TenantPrincipalDependency
from src.services.wallet_ownership import WalletOwnershipService


@pytest.fixture
def principal():
    return Principal(
        tenant_id="tenant-a",
        actor_id="actor-a",
        roles=("credential:issue", "evidence:export"),
        issuer_dids=("did:web:issuer.example",),
    )


@pytest.fixture
async def api(monkeypatch, principal):
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "1" * 40)
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_URL", raising=False)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    app.state.db = SimpleNamespace(is_ready=True)
    app.state.wallet_ownership_config = WalletOwnershipConfig(chain_id=31337, registry_address="0x" + "1" * 40)
    service = MagicMock(spec=WalletOwnershipService)
    app.dependency_overrides[routes.wallet_service] = lambda: service
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield SimpleNamespace(client=client, service=service, app=app)


async def test_wallet_service_unavailable_without_database(principal, monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal
    app.state.db = SimpleNamespace(is_ready=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/wallet/ownership/challenge", json={"credential_id": "ab" * 32})).status_code == 503


async def test_evidence_export_omits_message_for_v1_format(api):
    api.service.delegation_evidence = AsyncMock(
        return_value={
            "attestation_record": {
                "schema_version": "clearproof-wallet-attestation-v1",
                "attestation_id": "cd" * 32,
                "challenge": {
                    "schema_version": "clearproof-wallet-challenge-v1",
                    "tenant_id": "tenant-a",
                    "actor_id": "actor-a",
                    "credential": {
                        "schema_version": "clearproof-credential-v1",
                        "tenant_id": "tenant-a",
                        "credential_nonce": "ab" * 32,
                        "issuer_did": "did:web:issuer.example",
                        "subject_wallet": "0x" + "11" * 20,
                        "holder_commitment": "1",
                        "jurisdiction": "DE",
                        "kyc_tier": 2,
                        "sanctions_clear": True,
                        "issued_at": 1,
                        "expires_at": 999,
                    },
                    "chain_id": 31337,
                    "registry_address": "0x" + "1" * 40,
                    "nonce": "cd" * 32,
                    "timestamp": 100,
                    "expires_at": 400,
                },
                "signature": "0x" + "45" * 65,
                "issued_at": 120,
                "expires_at": 86400,
            },
            "rechecks": [],
            "credential_nonce": "ab" * 32,
            "subject_wallet": "0x" + "11" * 20,
            "message_format": "clearproof-canonical-v1",
            "message": "Clearproof wallet ownership verification v1\n{}",
        }
    )
    response = await api.client.get("/wallet/ownership/evidence/" + "cd" * 32)
    assert response.status_code == 200
    assert "challenge_message" not in response.json()


async def test_delegation_check_and_evidence_export(api):
    api.service.recheck_delegation = AsyncMock(return_value={"delegated": False})
    api.service.delegation_evidence = AsyncMock(
        return_value={
            "attestation_record": {
                "schema_version": "clearproof-wallet-attestation-v2",
                "attestation_id": "cd" * 32,
                "challenge": {
                    "schema_version": "clearproof-wallet-challenge-v2",
                    "tenant_id": "tenant-a",
                    "actor_id": "actor-a",
                    "credential": {
                        "schema_version": "clearproof-credential-v1",
                        "tenant_id": "tenant-a",
                        "credential_nonce": "ab" * 32,
                        "issuer_did": "did:web:issuer.example",
                        "subject_wallet": "0x" + "11" * 20,
                        "holder_commitment": "1",
                        "jurisdiction": "DE",
                        "kyc_tier": 2,
                        "sanctions_clear": True,
                        "issued_at": 1,
                        "expires_at": 999,
                    },
                    "chain_id": 31337,
                    "registry_address": "0x" + "1" * 40,
                    "nonce": "cd" * 32,
                    "timestamp": 100,
                    "expires_at": 400,
                    "siwe_domain": "issuer.example",
                    "siwe_resource": "did:web:issuer.example/credentials/ab",
                },
                "signature": "0x" + "45" * 65,
                "issued_at": 120,
                "expires_at": 86400,
                "delegation": {
                    "checked": True,
                    "delegated": False,
                    "delegate": None,
                    "checked_at": 120,
                    "reason": None,
                },
                "method": "eoa",
            },
            "rechecks": [],
            "credential_nonce": "ab" * 32,
            "subject_wallet": "0x" + "11" * 20,
            "message_format": "eip-4361",
            "message": "example.com wants you to sign in with your Ethereum account:",
        }
    )
    check = await api.client.post("/wallet/ownership/delegation-check", json={"attestation_id": "cd" * 32})
    assert check.status_code == 200
    evidence = await api.client.get("/wallet/ownership/evidence/" + "cd" * 32)
    assert evidence.status_code == 200
    assert evidence.json()["challenge_message"].startswith("example.com")


def test_account_probe_and_chain_verifier_without_rpc(monkeypatch):
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_URL", raising=False)
    assert routes.account_probe() is None
    assert routes.chain_verifier() is None
    assert routes.wallet_chain(object()) is None


def test_wallet_chain_builds_web3_with_timeout_when_rpc_configured(monkeypatch):
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_TIMEOUT_SECONDS", raising=False)
    fake_module = SimpleNamespace(
        AsyncWeb3=lambda provider: SimpleNamespace(provider=provider),
        AsyncHTTPProvider=lambda url, request_kwargs=None: ("provider", url, request_kwargs),
    )
    client = routes.wallet_chain(fake_module)
    assert client.provider == ("provider", "http://127.0.0.1:8545", {"timeout": 10.0})


def test_account_probe_and_chain_verifier_read_app_state_wallet_web3():
    fake_w3 = SimpleNamespace()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(wallet_web3=fake_w3)))
    assert routes.account_probe(request) is not None
    assert routes.chain_verifier(request) is not None


@pytest.mark.asyncio
async def test_chain_verifier_calls_on_chain_helper(monkeypatch):
    fake_w3 = SimpleNamespace()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(wallet_web3=fake_w3)))

    async def fake_verify(w3, _address, _digest, _signature):
        assert w3 is fake_w3
        return True, "erc-1271"

    monkeypatch.setattr("src.chain.wallet_account.verify_signature", fake_verify)
    verify = routes.chain_verifier(request)
    valid, method = await verify("0x" + "11" * 20, "hello", "0x" + "ab" * 64)
    assert (valid, method) == (True, "erc-1271")


@pytest.mark.asyncio
async def test_account_probe_delegation_helper(monkeypatch):
    fake_w3 = SimpleNamespace()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(wallet_web3=fake_w3)))

    async def fake_account_code(w3, _address):
        assert w3 is fake_w3
        return "0xef0100" + "22" * 20

    monkeypatch.setattr("src.chain.wallet_account.account_code", fake_account_code)
    probe = routes.account_probe(request)
    result = await probe("0x" + "11" * 20)
    assert result["delegated"] is True
    assert result["delegate"] == "0x" + "22" * 20
    assert result["indicator_malformed"] is False
    assert result["has_code"] is True


def test_wallet_service_wires_startup_config_without_reading_environment(monkeypatch, principal):
    from src.storage.keyring import KeyRing, KeyVersion
    from src.storage.pilot_cipher import RecordCipher

    # Stale environment values prove the request path uses app.state only.
    monkeypatch.setenv("PILOT_CHAIN_ID", "1")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "9" * 40)
    monkeypatch.setenv("WALLET_OWNERSHIP_DELEGATION_RECHECK_SECONDS", "15")
    monkeypatch.delenv("WALLET_OWNERSHIP_RPC_URL", raising=False)

    state = SimpleNamespace(
        db=SimpleNamespace(is_ready=True),
        record_cipher=RecordCipher(KeyRing(KeyVersion("current", b"a" * 32, 0))),
        wallet_ownership_config=WalletOwnershipConfig(
            chain_id=31337, registry_address="0x" + "1" * 40, delegation_recheck_seconds=120
        ),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=state))
    service = routes.wallet_service(request, principal)
    assert service.chain_id == 31337
    assert service.registry_address == "0x" + "1" * 40
    assert service.delegation_recheck_seconds == 120

    for invalid in (
        WalletOwnershipConfig(chain_id=31337, registry_address="0x" + "1" * 40, delegation_recheck_seconds=0),
        WalletOwnershipConfig(chain_id=31337, registry_address="not-an-address"),
        WalletOwnershipConfig(chain_id="synthetic", registry_address="0x" + "1" * 40),
    ):
        state.wallet_ownership_config = invalid
        with pytest.raises(routes.HTTPException) as exc_info:
            routes.wallet_service(request, principal)
        assert exc_info.value.status_code == 503


async def test_challenge_uses_startup_siwe_domain(api, monkeypatch):
    # A conflicting environment value proves the request path uses app.state only.
    monkeypatch.setenv("PILOT_SIWE_DOMAIN", "stale.example")
    api.app.state.wallet_ownership_config = WalletOwnershipConfig(
        chain_id=31337, registry_address="0x" + "1" * 40, siwe_domain="configured.example"
    )
    value = SimpleNamespace(
        model_dump=lambda **_: {},
        message=lambda: "configured.example wants you to sign in",
        siwe_domain="configured.example",
        credential=SimpleNamespace(subject_wallet="0x" + "11" * 20, issuer_did="did:web:issuer.example"),
        timestamp=100,
        nonce="ab" * 32,
        expires_at=400,
    )
    api.service.challenge = AsyncMock(return_value=value)
    response = await api.client.post("/wallet/ownership/challenge", json={"credential_id": "ab" * 32})
    assert response.status_code == 200
    assert response.json()["message_format"] == "eip-4361"
    assert api.service.challenge.call_args.kwargs["siwe_domain"] == "configured.example"
