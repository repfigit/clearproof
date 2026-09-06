"""Real PostgreSQL adversarial checks for encrypted tenant records."""

import asyncio
import os
import uuid

import psycopg
import pytest
from fastapi import HTTPException
from psycopg import sql
from psycopg.conninfo import make_conninfo

from src.auth.principal import Principal
from src.storage.database import Database
from src.storage.keyring import KeyRing, KeyVersion
from src.storage.pilot import PilotStore, RecordConflict, ReplayConflict
from src.storage.pilot_cipher import RecordCipher, RecordIntegrityError

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")
ROLES = (
    "credential:issue",
    "credential:revoke",
    "proof:generate",
    "proof:consume",
    "proof:inspect",
    "evidence:decrypt",
    "events:ingest",
    "policy:approve",
    "tenant:admin",
)


@pytest.fixture
async def db(monkeypatch):
    admin = os.environ["DATABASE_URL"]
    schema = "pilot_test_" + uuid.uuid4().hex
    async with await psycopg.AsyncConnection.connect(admin) as conn:
        await conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    monkeypatch.setenv("DATABASE_URL", make_conninfo(admin, options=f"-c search_path={schema}"))
    database = Database(pool_min=1, pool_max=4)
    try:
        await database.connect()
        yield database
    finally:
        await database.close()
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            await conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def cipher(key=b"a" * 32, old=None):
    return RecordCipher(KeyRing(KeyVersion("current", key, 0), [KeyVersion("old", old, 0)] if old else []))


def store(db, tenant="tenant-a", actor="actor-a", roles=ROLES, encryption=None):
    return PilotStore(db, encryption or cipher(), Principal(tenant_id=tenant, actor_id=actor, roles=roles))


async def test_private_records_survive_reconnect_and_preserve_history(db):
    a, b = store(db), store(db, "tenant-b")
    kinds = (
        "credential",
        "proof",
        "transfer",
        "receipt",
        "event",
        "policy",
        "revocation",
        "issuance-root",
        "issuer-root",
        "sanctions-root",
    )
    for target, marker in [(a, "PRIVATE-ALICE"), (b, "PRIVATE-BOB")]:
        async with target.transaction() as tx:
            for kind in kinds:
                await tx.put(kind, "same-id", {"private": marker})
    async with a.transaction() as tx:
        assert await tx.put("issuance-root", "same-id", {"root": "new"}, expected_revision=1) == 2
    await db.close()
    await db.connect()
    a, b = store(db), store(db, "tenant-b")
    for kind in kinds:
        assert await b.get(kind, "same-id") == {"private": "PRIVATE-BOB"}
    assert (await a.read("issuance-root", "same-id", revision=1)).value == {"private": "PRIVATE-ALICE"}
    assert (await a.read("issuance-root", "same-id")).revision == 2
    assert await a.read("issuance-root", "same-id", revision=3) is None
    assert "PRIVATE" not in repr(await a.read("credential", "same-id"))
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT row_to_json(r)::text FROM pilot_records r")).fetchall()
        assert all("PRIVATE" not in row[0] for row in rows)
    with pytest.raises(RecordConflict):
        async with a.transaction() as tx:
            await tx.put("issuance-root", "same-id", {}, expected_revision=1)
    with pytest.raises(RecordConflict):
        async with a.transaction() as tx:
            await tx.put("credential", "same-id", {}, expected_revision=1)


async def test_concurrent_idempotency_actor_binding_and_replay(db):
    a = store(db)
    calls = 0

    async def operation(tx):
        nonlocal calls
        calls += 1
        await tx.put("proof", "proof-1", {"proof": "synthetic-storage-only"})
        await tx.consume("a" * 64, "proof-1")
        return {"accepted": True}

    results = await asyncio.gather(
        *[a.run_idempotent("consume-proof", "request-1", {"input": 1}, operation) for _ in range(6)]
    )
    assert results == [{"accepted": True}] * 6 and calls == 1
    for target, request in [(a, {"input": 2}), (store(db, actor="actor-b"), {"input": 1})]:
        with pytest.raises(RecordConflict):
            await target.run_idempotent("consume-proof", "request-1", request, operation)
    with pytest.raises(ReplayConflict):
        async with a.transaction() as tx:
            await tx.consume("a" * 64, "proof-1")
    async with a.transaction() as tx:
        assert await tx.is_consumed("a" * 64)
    b = store(db, "tenant-b")
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        async with b.transaction() as tx:
            await tx.consume("a" * 64, "proof-1")
    assert await b.run_idempotent("consume-proof", "request-1", {"input": 1}, operation) == {"accepted": True}
    assert calls == 2


@pytest.mark.parametrize("cancel", [False, True])
async def test_failed_operation_rolls_back_records_consumption_and_retry_cache(db, cancel):
    a = store(db)
    entered = asyncio.Event()

    async def fail(tx):
        await tx.put("proof", "proof-1", {})
        await tx.consume("a" * 64, "proof-1")
        entered.set()
        if cancel:
            await asyncio.Event().wait()
        raise RuntimeError("abort")

    task = asyncio.create_task(a.run_idempotent("consume-proof", "request-1", {}, fail))
    await asyncio.wait_for(entered.wait(), 5)
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else RuntimeError):
        await task
    assert await a.get("proof", "proof-1") is None
    async with a.transaction() as tx:
        assert not await tx.is_consumed("a" * 64)

    async def succeed(tx):
        await tx.put("proof", "proof-1", {})
        await tx.consume("a" * 64, "proof-1")
        return {"ok": True}

    assert await a.run_idempotent("consume-proof", "request-1", {}, succeed) == {"ok": True}


async def test_ciphertext_substitution_and_key_rotation(db):
    a, b = store(db), store(db, "tenant-b")
    for target in (a, b):
        async with target.transaction() as tx:
            await tx.put("credential", "record-1", {"private": target.tenant_id})
    rotated = store(db, encryption=cipher(b"b" * 32, b"a" * 32))
    assert await rotated.get("credential", "record-1") == {"private": "tenant-a"}
    async with rotated.transaction() as tx:
        await tx.put("credential", "record-2", {"private": "new-key"})
    with pytest.raises(RecordIntegrityError):
        await a.get("credential", "record-2")
    with pytest.raises(RecordIntegrityError):
        await store(db, encryption=cipher(b"b" * 32)).get("credential", "record-1")
    async with db.connection() as conn:
        await conn.execute("""UPDATE pilot_records b SET nonce=a.nonce, ciphertext=a.ciphertext,
          key_id=a.key_id, content_tag=a.content_tag FROM pilot_records a
          WHERE a.tenant_id='tenant-a' AND b.tenant_id='tenant-b'
          AND a.record_id='record-1' AND b.record_id='record-1'""")
    with pytest.raises(RecordIntegrityError):
        await b.get("credential", "record-1")


async def test_roles_closed_transactions_and_independent_tenant_lock(db):
    restricted = store(db, roles=("proof:inspect",))
    with pytest.raises(HTTPException) as err:
        await restricted.get("proof", "missing")
    assert err.value.status_code == 403
    async with restricted.transaction() as tx:
        with pytest.raises(HTTPException):
            await tx.put("proof", "proof-1", {})
        with pytest.raises(HTTPException):
            await tx.consume("a" * 64, "proof-1")
    with pytest.raises(RuntimeError):
        await tx.is_consumed("a" * 64)
    async with store(db).transaction():
        async with asyncio.timeout(3):
            async with store(db, "tenant-b").transaction() as other:
                await other.put("proof", "proof-1", {})


async def test_enrollment_api_real_signatures_tenant_binding_and_reconnect(db, monkeypatch):
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from eth_account import Account
    from httpx import ASGITransport, AsyncClient

    from src.api.main import create_app
    from src.api.middleware import auth
    from src.protocol.credential import PilotCredential, holder_commitment
    from src.protocol.enrollment import EnrollmentConsent

    private = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    monkeypatch.setattr(
        auth,
        "JWT_PUBLIC_KEY",
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", "0x" + "1" * 40)
    monkeypatch.setenv("PII_MASTER_KEY", (b"a" * 32).hex())
    now = int(time.time())
    claims = dict(
        iss=auth.JWT_ISSUER,
        aud=auth.JWT_AUDIENCE,
        sub="operator",
        iat=now,
        exp=now + 300,
        tenant_id="tenant-a",
        actor_id="issuer-operator",
        roles=["credential:issue"],
        issuer_dids=["did:web:issuer.example"],
    )
    wallet = Account.create()
    credential = PilotCredential(
        tenant_id="tenant-a",
        credential_nonce="a" * 64,
        issuer_did="did:web:issuer.example",
        subject_wallet=wallet.address.lower(),
        holder_commitment=holder_commitment("123456"),
        jurisdiction="US",
        kyc_tier=2,
        sanctions_clear=True,
        issued_at=now,
        expires_at=now + 1000,
    )
    consent = EnrollmentConsent(
        credential=credential, chain_id=31337, registry_address="0x" + "1" * 40, consent_expires_at=now + 300
    )
    body = {
        "consent": consent.model_dump(mode="json"),
        "signature": "0x" + wallet.sign_message(consent.signing_message()).signature.hex(),
        "idempotency_key": "enroll-1",
    }
    headers = {"Authorization": "Bearer " + jwt.encode(claims, private, algorithm="ES256")}
    app = create_app()
    app.state.db = db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/pilot/credential/enroll", json=body, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json() == {"credential_id": "a" * 64, "status": "awaiting-root-publication"}
        for changed, status in [({"tenant_id": "tenant-b"}, 422), ({"issuer_dids": []}, 403)]:
            token = jwt.encode({**claims, **changed}, private, algorithm="ES256")
            denied = await client.post(
                "/pilot/credential/enroll", json=body, headers={"Authorization": "Bearer " + token}
            )
            assert denied.status_code == status
        duplicate = await client.post(
            "/pilot/credential/enroll", json={**body, "idempotency_key": "enroll-2"}, headers=headers
        )
        assert duplicate.status_code == 409
    await db.close()
    await db.connect()
    restarted = create_app()
    restarted.state.db = db
    async with AsyncClient(transport=ASGITransport(app=restarted), base_url="http://test") as client:
        retry = await client.post("/pilot/credential/enroll", json=body, headers=headers)
        assert retry.status_code == 200 and retry.json() == response.json()
    saved = await store(db).get("credential", "a" * 64)
    assert saved["consent"]["credential"]["subject_wallet"] == wallet.address.lower()
    assert await store(db, "tenant-b").get("credential", "a" * 64) is None
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT row_to_json(r)::text FROM pilot_records r")).fetchall()
        assert all(wallet.address.lower() not in row[0] and body["signature"] not in row[0] for row in rows)
