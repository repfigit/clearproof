"""Real PostgreSQL and HTTP wallet lifecycle, tenant isolation and atomic replay rejection."""

import asyncio
import os

import pytest
from eth_account.messages import encode_defunct
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.wallet_ownership import WalletOwnershipError
from src.services.enrollment import EnrollmentIneligible, EnrollmentService, RevocationRequest
from src.services.wallet_ownership import WalletChallengeLimit, WalletEvidenceNotFound, WalletOwnershipService
from src.storage.pilot import RecordConflict
from tests.integration.test_pilot_storage import cipher
from tests.integration.test_pilot_storage import db as database_fixture

db = database_fixture

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")


@pytest.fixture
async def enrolled(db, wallet_enrollment):
    wallet, consent, principal = wallet_enrollment
    service = EnrollmentService(
        db, cipher(), principal, chain_id=consent.chain_id, registry_address=consent.registry_address
    )
    signature = "0x" + wallet.sign_message(consent.signing_message()).signature.hex()
    await service.enroll(consent, signature, idempotency_key="enrollment", now=1050)
    return wallet, consent, principal, service


def wallet_service(db, principal, consent):
    return WalletOwnershipService(
        db, cipher(), principal, chain_id=consent.chain_id, registry_address=consent.registry_address
    )


def sign(wallet, challenge):
    return "0x" + wallet.sign_message(encode_defunct(text=challenge.message())).signature.hex()


async def test_atomic_single_use_restart_encryption_and_extension(db, enrolled):
    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    challenge = await service.challenge(consent.credential.credential_nonce, now=1100)
    signature = sign(wallet, challenge)
    assert challenge.expires_at == 1400
    results = await asyncio.gather(
        *(service.verify(challenge.nonce, signature, now=1200) for _ in range(6)), return_exceptions=True
    )
    assert sum(not isinstance(r, Exception) for r in results) == 1
    assert sum(isinstance(r, RecordConflict) for r in results) == 5
    await db.close()
    await db.connect()
    service = wallet_service(db, principal, consent)
    status = await service.status(challenge.nonce, now=1201)
    assert status["wallet_ownership_verified"] is True
    assert status["expires_at"] == 1200 + 86400
    extension = await service.issue_extension(challenge.nonce, now=1201)
    assert extension.fields()[5] == 1
    assert extension.credential_commitment == consent.credential.commitment
    assert await service.issue_extension(challenge.nonce, now=1202) == extension
    stored = await service.store.get("credential", consent.credential.credential_nonce)
    assert stored["credential_commitment"] == consent.credential.commitment
    assert "wallet_ownership_verified" not in stored["consent"]["credential"]
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT tenant_id,kind,record_id,ciphertext FROM pilot_records")).fetchall()
    physical = repr(rows)
    for private in [wallet.address.lower(), signature, consent.credential.issuer_did]:
        assert private not in physical
    with pytest.raises(RecordConflict):
        await service.verify(challenge.nonce, signature, now=1203)


async def test_exact_expiry_and_revocation_rechecked_on_extension_retry(db, enrolled):
    wallet, consent, principal, enrollment_service = enrolled
    service = wallet_service(db, principal, consent)
    c = await service.challenge(consent.credential.credential_nonce, now=1100)
    with pytest.raises(WalletOwnershipError):
        await service.verify(c.nonce, sign(wallet, c), now=1400)
    a = await service.verify(c.nonce, sign(wallet, c), now=1399)
    await service.issue_extension(a.attestation_id, now=1400)
    assert (await service.status(a.attestation_id, now=a.expires_at - 1))["wallet_ownership_verified"] is True
    assert (await service.status(a.attestation_id, now=a.expires_at))["wallet_ownership_verified"] is False
    with pytest.raises(WalletOwnershipError):
        await service.issue_extension(a.attestation_id, now=a.expires_at)
    await service.revoke(a.attestation_id, now=1500)
    assert (await service.revoke(a.attestation_id, now=1501))["revoked_at"] == 1500
    assert (await service.status(a.attestation_id, now=1501))["wallet_ownership_verified"] is False
    with pytest.raises(WalletOwnershipError):
        await service.issue_extension(a.attestation_id, now=1501)
    c2 = await service.challenge(consent.credential.credential_nonce, now=1502)
    a2 = await service.verify(c2.nonce, sign(wallet, c2), now=1503)
    await service.issue_extension(a2.attestation_id, now=1504)
    await enrollment_service.revoke(
        RevocationRequest(
            credential_id=consent.credential.credential_nonce, idempotency_key="revoke-parent", reason_code="test"
        ),
        now=1505,
    )
    with pytest.raises(EnrollmentIneligible):
        await service.issue_extension(a2.attestation_id, now=1506)
    assert (await service.status(a2.attestation_id, now=1506))["wallet_ownership_verified"] is False


async def test_tenant_actor_issuer_and_deployment_cannot_borrow_evidence(db, enrolled):
    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    challenge = await service.challenge(consent.credential.credential_nonce, now=1100)
    signature = sign(wallet, challenge)
    cases = [
        ({"tenant_id": "other-tenant"}, WalletEvidenceNotFound),
        ({"actor_id": "other-actor"}, WalletOwnershipError),
        ({"issuer_dids": ("did:web:other.example",)}, HTTPException),
        ({"roles": ("evidence:decrypt",)}, HTTPException),
    ]
    for change, error in cases:
        other = Principal.model_validate({**principal.model_dump(), **change})
        with pytest.raises(error):
            await wallet_service(db, other, consent).verify(challenge.nonce, signature, now=1200)
    for chain, registry in [(1, consent.registry_address), (consent.chain_id, "0x" + "2" * 40)]:
        other = WalletOwnershipService(db, cipher(), principal, chain_id=chain, registry_address=registry)
        with pytest.raises(WalletOwnershipError):
            await other.verify(challenge.nonce, signature, now=1200)
    a = await service.verify(challenge.nonce, signature, now=1200)
    other = Principal.model_validate({**principal.model_dump(), "issuer_dids": ("did:web:other.example",)})
    with pytest.raises(HTTPException):
        await wallet_service(db, other, consent).revoke(a.attestation_id, now=1201)
    assert (await service.status(a.attestation_id, now=1201))["wallet_ownership_verified"] is True


async def test_durable_challenge_quotas_and_failed_verification_do_not_consume(db, enrolled, monkeypatch):
    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    monkeypatch.setattr(WalletOwnershipService, "DAILY_CHALLENGE_LIMIT", 2)
    c = await service.challenge(consent.credential.credential_nonce, now=1100)
    with pytest.raises(RecordConflict):
        await service.challenge(consent.credential.credential_nonce, now=1101)
    with pytest.raises(WalletOwnershipError):
        await service.verify(c.nonce, "0x" + "00" * 65, now=1102)
    await service.verify(c.nonce, sign(wallet, c), now=1103)
    await service.challenge(consent.credential.credential_nonce, now=1500)
    await db.close()
    await db.connect()
    with pytest.raises(WalletChallengeLimit):
        await wallet_service(db, principal, consent).challenge(consent.credential.credential_nonce, now=1800)


async def test_real_http_lifecycle_and_auth_fail_closed(db, enrolled, monkeypatch, caplog):
    from src.api.main import app
    from src.api.routes import wallet_ownership as routes

    wallet, consent, principal, _ = enrolled
    monkeypatch.setattr(app.state, "db", db, raising=False)
    monkeypatch.setenv("PILOT_CHAIN_ID", str(consent.chain_id))
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", consent.registry_address)
    # Use the real cipher factory without exposing keyring internals in production.
    monkeypatch.setattr(routes, "RecordCipher", lambda _: cipher())
    monkeypatch.setattr(routes, "load_keyring", lambda: None)
    monkeypatch.setattr("src.services.wallet_ownership.time.time", lambda: 1100)
    overrides = app.dependency_overrides.copy()
    current = [principal]
    app.dependency_overrides[TenantPrincipalDependency] = lambda: current[0]
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/wallet/ownership/challenge", json={"credential_id": consent.credential.credential_nonce}
            )
            assert response.status_code == 200, response.text
            value = response.json()
            signature = "0x" + wallet.sign_message(encode_defunct(text=value["message"])).signature.hex()
            response = await client.post(
                "/wallet/ownership/verify", json={"nonce": value["nonce"], "signature": signature}
            )
            assert response.status_code == 200, response.text
            attestation_id = response.json()["attestation_id"]
            response = await client.post("/wallet/ownership/credential", json={"attestation_id": attestation_id})
            assert response.status_code == 200
            assert response.json()["extension"]["wallet_ownership_verified"] is True
            assert response.json()["proof_support"] == "staged-witness-only"
            response = await client.post(
                "/wallet/ownership/verify", json={"nonce": value["nonce"], "signature": signature}
            )
            assert response.status_code == 409
            current[0] = Principal.model_validate({**principal.model_dump(), "roles": ("evidence:decrypt",)})
            response = await client.post("/wallet/ownership/revoke", json={"attestation_id": attestation_id})
            assert response.status_code == 403
            current[0] = principal
            response = await client.post("/wallet/ownership/revoke", json={"attestation_id": attestation_id})
            assert response.status_code == 200
            response = await client.get("/wallet/ownership/attestations/" + attestation_id)
            assert response.status_code == 200 and response.json()["wallet_ownership_verified"] is False
            response = await client.post("/wallet/ownership/credential", json={"attestation_id": attestation_id})
            assert response.status_code == 422
            current[0] = Principal.model_validate({**principal.model_dump(), "tenant_id": "other-tenant"})
            response = await client.get("/wallet/ownership/attestations/" + attestation_id)
            assert response.status_code == 404
            response = await client.post(
                "/wallet/ownership/challenge",
                json={"credential_id": consent.credential.credential_nonce, "vasp_did": "did:web:other.example"},
            )
            assert response.status_code == 422
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(overrides)
    assert wallet.address.lower() not in caplog.text and signature not in caplog.text


async def test_parent_expiry_caps_extension_and_revocation_survives_restart(db, enrolled):
    from src.protocol.credential import PilotCredential
    from src.protocol.enrollment import EnrollmentConsent

    wallet, consent, principal, enrollment_service = enrolled
    short = PilotCredential.model_validate(
        {**consent.credential.model_dump(), "credential_nonce": "fe" * 32, "expires_at": 1350}
    )
    consent = EnrollmentConsent.model_validate(
        {**consent.model_dump(), "credential": short, "consent_expires_at": 1250}
    )
    signature = "0x" + wallet.sign_message(consent.signing_message()).signature.hex()
    await enrollment_service.enroll(consent, signature, idempotency_key="short-parent", now=1100)
    service = wallet_service(db, principal, consent)
    c = await service.challenge(short.credential_nonce, now=1150)
    a = await service.verify(c.nonce, sign(wallet, c), now=1200)
    e = await service.issue_extension(a.attestation_id, now=1201)
    assert e.expires_at == 1350 and a.expires_at == 87600
    with pytest.raises(EnrollmentIneligible):
        await service.issue_extension(a.attestation_id, now=1350)
    await service.revoke(a.attestation_id, now=1250)
    await db.close()
    await db.connect()
    service = wallet_service(db, principal, consent)
    assert (await service.status(a.attestation_id, now=1251))["wallet_ownership_verified"] is False
    with pytest.raises(WalletOwnershipError):
        await service.issue_extension(a.attestation_id, now=1251)


async def test_additive_wallet_migration_preserves_enrollment(db, enrolled):
    from src.storage.pilot_schema import OBSERVATION_MIGRATION

    _, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    before = await service.store.get("credential", consent.credential.credential_nonce)
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT max(version) FROM schema_migrations")).fetchone())[0] == 20
        await conn.execute(OBSERVATION_MIGRATION)
        await conn.execute("DELETE FROM schema_migrations WHERE version=20")
    await db.close()
    await db.connect()
    service = wallet_service(db, principal, consent)
    assert await service.store.get("credential", consent.credential.credential_nonce) == before
    c = await service.challenge(consent.credential.credential_nonce, now=1100)
    assert c.credential.commitment == consent.credential.commitment


async def test_verification_samples_time_after_waiting_for_database_lock(db, enrolled):
    wallet, consent, principal, _ = enrolled
    clock = [1100]
    service = WalletOwnershipService(
        db,
        cipher(),
        principal,
        chain_id=consent.chain_id,
        registry_address=consent.registry_address,
        clock=lambda: clock[0],
    )
    challenge = await service.challenge(consent.credential.credential_nonce)
    clock[0] = challenge.expires_at - 1
    pending = None
    try:
        async with service.store.transaction():
            pending = asyncio.create_task(service.verify(challenge.nonce, sign(wallet, challenge)))
            # Verify that this task actually reached the database lock before
            # advancing time; a scheduling sleep alone would not exercise the race.
            for _ in range(100):
                async with db.connection() as conn:
                    waiting = await (
                        await conn.execute(
                            "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                            "AND wait_event='advisory'"
                        )
                    ).fetchone()
                if waiting[0]:
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail("Verifier did not reach the held transaction lock")
            clock[0] = challenge.expires_at
        with pytest.raises(WalletOwnershipError):
            await pending
        assert await service.store.get("wallet-attestation", challenge.nonce) is None
    finally:
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("now", [True, "1100", -1, 2**53])
async def test_invalid_evaluation_clock_does_not_retain_challenge(db, enrolled, now):
    _, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    with pytest.raises(WalletOwnershipError, match="Invalid wallet evidence evaluation time"):
        await service.challenge(consent.credential.credential_nonce, now=now)
    async with service.store.transaction() as tx:
        assert await tx.record_ids("wallet-challenge") == []
        assert await tx.record_ids("wallet-quota") == []


async def test_challenge_expiring_during_real_signature_verification_is_not_consumed(db, enrolled):
    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    challenge = await service.challenge(consent.credential.credential_nonce, now=1100)
    clock = iter((1200, challenge.expires_at))
    service.clock = lambda: next(clock)
    signature = sign(wallet, challenge)
    with pytest.raises(WalletOwnershipError, match="expired during verification"):
        await service.verify(challenge.nonce, signature)
    assert await service.store.get("wallet-attestation", challenge.nonce) is None
    # A rejected verification did not create a consumption marker. This uses an
    # explicit synthetic review clock to inspect rollback, not wall-clock travel.
    assert (await service.verify(challenge.nonce, signature, now=1399)).attestation_id == challenge.nonce


@pytest.mark.parametrize("operation", ["verify", "status", "extension"])
async def test_retained_wallet_evidence_must_match_current_enrollment(db, enrolled, operation):
    from src.protocol.wallet_ownership import ATTESTATION_TTL, WalletAttestation, WalletChallenge

    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    original = await service.challenge(consent.credential.credential_nonce, now=1100)
    value = original.model_dump()
    value["nonce"] = "a" * 64
    value["credential"]["jurisdiction"] = "CA" if original.credential.jurisdiction != "CA" else "US"
    changed = WalletChallenge.model_validate(value)
    signature = sign(wallet, changed)
    # Retain correctly encrypted, correctly signed evidence for a different
    # credential value under the same credential nonce. No cryptography is mocked.
    async with service.store.transaction() as tx:
        await tx.put("wallet-challenge", changed.nonce, changed.model_dump(mode="json"))
        if operation != "verify":
            attestation = WalletAttestation(
                attestation_id=changed.nonce,
                challenge=changed,
                signature=signature,
                issued_at=1200,
                expires_at=1200 + ATTESTATION_TTL,
            )
            await tx.put("wallet-attestation", changed.nonce, attestation.model_dump(mode="json"))
    if operation == "verify":
        with pytest.raises(WalletOwnershipError, match="Challenge credential changed"):
            await service.verify(changed.nonce, signature, now=1201)
        assert await service.store.get("wallet-attestation", changed.nonce) is None
    elif operation == "status":
        result = await service.status(changed.nonce, now=1201)
        assert result["wallet_ownership_verified"] is False
        assert result["reason"] == "Wallet attestation credential changed"
    else:
        with pytest.raises(WalletOwnershipError, match="Wallet attestation credential changed"):
            await service.issue_extension(changed.nonce, now=1201)
        assert await service.store.get("wallet-extension", changed.nonce) is None


async def test_attestation_storage_key_must_match_signed_identifier(db, enrolled):
    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    challenge = await service.challenge(consent.credential.credential_nonce, now=1100)
    attestation = await service.verify(challenge.nonce, sign(wallet, challenge), now=1200)
    alias = "b" * 64
    async with service.store.transaction() as tx:
        await tx.put("wallet-attestation", alias, attestation.model_dump(mode="json"))
    with pytest.raises(WalletOwnershipError, match="attestation identifier mismatch"):
        await service.status(alias, now=1201)
    assert (await service.status(challenge.nonce, now=1201))["wallet_ownership_verified"] is True


async def test_revocation_cannot_precede_attestation_issuance(db, enrolled):
    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    challenge = await service.challenge(consent.credential.credential_nonce, now=1100)
    await service.verify(challenge.nonce, sign(wallet, challenge), now=1200)
    with pytest.raises(WalletOwnershipError, match="Revocation precedes attestation"):
        await service.revoke(challenge.nonce, now=1199)
    assert await service.store.get("wallet-revocation", challenge.nonce) is None
    assert (await service.revoke(challenge.nonce, now=1200))["revoked_at"] == 1200


async def test_extension_retry_rejects_conflicting_retained_fields(db, enrolled):
    from src.protocol.wallet_ownership import WalletCredentialExtension

    wallet, consent, principal, _ = enrolled
    service = wallet_service(db, principal, consent)
    challenge = await service.challenge(consent.credential.credential_nonce, now=1100)
    attestation = await service.verify(challenge.nonce, sign(wallet, challenge), now=1200)
    conflicting = WalletCredentialExtension(
        credential_commitment=consent.credential.commitment,
        attestation_digest=attestation.digest_scalar,
        issued_at=attestation.issued_at,
        expires_at=min(attestation.expires_at, consent.credential.expires_at),
        wallet_ownership_verified=False,
    ).model_dump(mode="json")
    async with service.store.transaction() as tx:
        await tx.put("wallet-extension", challenge.nonce, conflicting)
    with pytest.raises(RecordConflict, match="Stored wallet extension differs"):
        await service.issue_extension(challenge.nonce, now=1201)
    assert await service.store.get("wallet-extension", challenge.nonce) == conflicting
