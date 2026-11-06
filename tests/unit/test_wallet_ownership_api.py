"""HTTP wiring for wallet-ownership routes without PostgreSQL."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI

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


def test_wallet_chain_builds_web3_when_rpc_configured(monkeypatch):
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    fake_module = SimpleNamespace(
        AsyncWeb3=lambda provider: SimpleNamespace(provider=provider),
        AsyncHTTPProvider=lambda url: ("provider", url),
    )
    client = routes.wallet_chain(fake_module)
    assert client.provider == ("provider", "http://127.0.0.1:8545")


def test_account_probe_with_rpc(monkeypatch):
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setattr(routes, "wallet_chain", lambda _module: SimpleNamespace())
    assert routes.account_probe() is not None
    assert routes.chain_verifier() is not None


@pytest.mark.asyncio
async def test_chain_verifier_calls_on_chain_helper(monkeypatch):
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setattr(routes, "wallet_chain", lambda _module: SimpleNamespace())

    async def fake_verify(_w3, _address, _digest, _signature):
        return True, "erc-1271"

    monkeypatch.setattr("src.chain.wallet_account.verify_signature", fake_verify)
    verify = routes.chain_verifier()
    valid, method = await verify("0x" + "11" * 20, "hello", "0x" + "ab" * 64)
    assert (valid, method) == (True, "erc-1271")


@pytest.mark.asyncio
async def test_account_probe_delegation_helper(monkeypatch):
    monkeypatch.setenv("WALLET_OWNERSHIP_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setattr(routes, "wallet_chain", lambda _module: SimpleNamespace())

    async def fake_account_code(_w3, _address):
        return "0xef0100" + "22" * 20 + "000000"

    monkeypatch.setattr("src.chain.wallet_account.account_code", fake_account_code)
    probe = routes.account_probe()
    result = await probe("0x" + "11" * 20)
    assert result["delegated"] is True
    assert result["has_code"] is True
