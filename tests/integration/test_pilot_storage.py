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
    revoke_token = jwt.encode(
        {**claims, "roles": ["credential:revoke", "evidence:decrypt"]}, private, algorithm="ES256"
    )
    revocation = {"credential_id": "a" * 64, "idempotency_key": "revoke-1", "reason_code": "issuer-withdrawal"}
    async with AsyncClient(transport=ASGITransport(app=restarted), base_url="http://test") as client:
        denied = await client.post("/pilot/credential/revoke", json=revocation, headers=headers)
        assert denied.status_code == 403
        revoked = await client.post(
            "/pilot/credential/revoke", json=revocation, headers={"Authorization": "Bearer " + revoke_token}
        )
        assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
        missing = await client.post(
            "/pilot/credential/revoke",
            json={**revocation, "credential_id": "b" * 64},
            headers={"Authorization": "Bearer " + revoke_token},
        )
        assert missing.status_code == 404


async def test_signed_root_publication_revision_chain_rotation_and_tenant_boundary(db):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.protocol.root_snapshot import RootAuthority, RootSnapshot, RootTrustError, RootTrustStore, sign_root
    from src.services.root_publication import RootPublicationService, root_record_id

    key = Ed25519PrivateKey.generate()
    authority = RootAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address="0x" + "1" * 40,
        kinds=("issuer-root",),
        not_before=1,
        not_after=1000,
    )
    trust = RootTrustStore([authority])
    principal = Principal(tenant_id="tenant-a", actor_id="registrar", roles=("tenant:admin", "evidence:decrypt"))
    service = RootPublicationService(db, cipher(), principal, trust)
    root = RootSnapshot(
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address="0x" + "1" * 40,
        kind="issuer-root",
        root="123",
        tree_depth=8,
        source_digest="a" * 64,
        revision=1,
        issued_at=100,
        expires_at=200,
        key_id=authority.key_id,
    )
    signed = sign_root(root, key)
    first = await service.publish(signed, idempotency_key="root-1", now=150)
    assert first["snapshot_digest"] == root.digest
    assert await service.publish(signed, idempotency_key="root-1", now=150) == first
    new = RootSnapshot.model_validate(
        {
            **root.model_dump(),
            "revision": 2,
            "previous_digest": root.digest,
            "root": "124",
            "issued_at": 150,
            "expires_at": 250,
        }
    )
    fork = RootSnapshot.model_validate({**new.model_dump(), "root": "125"})
    results = await asyncio.gather(
        service.publish(sign_root(new, key), idempotency_key="root-2", now=175),
        service.publish(sign_root(fork, key), idempotency_key="root-fork", now=175),
        return_exceptions=True,
    )
    assert sum(isinstance(result, RecordConflict) for result in results) == 1
    assert sum(type(result) is dict for result in results) == 1
    reader = store(db)
    current = await reader.read("issuer-root", root_record_id(root))
    assert current.revision == 2
    assert (await reader.read("issuer-root", root_record_id(root), revision=1)).value == signed.model_dump(mode="json")
    await db.close()
    await db.connect()
    assert (await store(db).read("issuer-root", root_record_id(root))).value == current.value
    other = RootPublicationService(
        db, cipher(), Principal(tenant_id="tenant-b", actor_id="registrar", roles=principal.roles), trust
    )
    with pytest.raises(RootTrustError):
        await other.publish(signed, idempotency_key="root-1", now=150)
    bad_previous = RootSnapshot.model_validate({**new.model_dump(), "revision": 3, "previous_digest": "b" * 64})
    with pytest.raises(RecordConflict):
        await service.publish(sign_root(bad_previous, key), idempotency_key="bad-predecessor", now=175)
    with pytest.raises(RootTrustError):
        await service.publish(signed, idempotency_key="expired", now=200)
    assert (await reader.read("issuer-root", root_record_id(root))).revision == 2


async def test_durable_revocation_scope_retry_and_proving_precondition(db):
    from eth_account import Account

    from src.protocol.credential import PilotCredential, holder_commitment
    from src.protocol.enrollment import EnrollmentConsent
    from src.services.enrollment import (
        EnrollmentIneligible,
        EnrollmentNotFound,
        EnrollmentService,
        RevocationRequest,
        load_unrevoked_enrollment,
    )
    from src.services.issuance_tree import build_issuance_tree

    principal = Principal(
        tenant_id="tenant-a",
        actor_id="issuer-operator",
        roles=("credential:issue", "credential:revoke", "evidence:decrypt"),
        issuer_dids=("did:web:issuer.example",),
    )

    def service(who=principal):
        return EnrollmentService(db, cipher(), who, chain_id=31337, registry_address="0x" + "1" * 40)

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
        issued_at=100,
        expires_at=1000,
    )
    consent = EnrollmentConsent(
        credential=credential, chain_id=31337, registry_address="0x" + "1" * 40, consent_expires_at=200
    )
    signature = "0x" + wallet.sign_message(consent.signing_message()).signature.hex()
    await service().enroll(consent, signature, idempotency_key="enroll-1", now=110)
    async with PilotStore(db, cipher(), principal).transaction() as tx:
        initial_tree = await build_issuance_tree(
            tx,
            issuer_did=credential.issuer_did,
            chain_id=31337,
            registry_address="0x" + "1" * 40,
            now=120,
        )
        assert initial_tree.tree.entries == ((credential.credential_nonce, credential.commitment),)
        assert initial_tree.tree.membership(credential.credential_nonce)["root"] == initial_tree.tree.root
        wrong_chain = await build_issuance_tree(
            tx,
            issuer_did=credential.issuer_did,
            chain_id=31338,
            registry_address="0x" + "1" * 40,
            now=120,
        )
        assert wrong_chain.tree.entries == ()
    async with store(db).transaction() as tx:
        assert await load_unrevoked_enrollment(tx, "a" * 64, now=120) == credential
        for invalid_time in (109, 1000):
            with pytest.raises(EnrollmentIneligible):
                await load_unrevoked_enrollment(tx, "a" * 64, now=invalid_time)
    request = RevocationRequest(credential_id="a" * 64, idempotency_key="revoke-1", reason_code="issuer-withdrawal")
    for changes in [{"issuer_dids": ("did:web:other.example",)}, {"roles": ("evidence:decrypt",)}]:
        unauthorized = Principal.model_validate({**principal.model_dump(), **changes})
        with pytest.raises(HTTPException) as err:
            await service(unauthorized).revoke(request, now=120)
        assert err.value.status_code == 403
    outsider = Principal.model_validate({**principal.model_dump(), "tenant_id": "tenant-b"})
    with pytest.raises(EnrollmentNotFound):
        await service(outsider).revoke(request, now=120)
    first = await service().revoke(request, now=120)
    assert first == {"credential_id": "a" * 64, "status": "revoked", "revoked_at": 120}
    assert await service().revoke(request, now=130) == first
    with pytest.raises(RecordConflict):
        await service().revoke(
            RevocationRequest.model_validate({**request.model_dump(), "reason_code": "other"}), now=130
        )
    lost_scope = Principal.model_validate({**principal.model_dump(), "issuer_dids": ()})
    with pytest.raises(HTTPException):
        await service(lost_scope).revoke(request, now=130)
    await db.close()
    await db.connect()
    assert await service().revoke(request, now=140) == first
    async with PilotStore(db, cipher(), principal).transaction() as tx:
        revoked_tree = await build_issuance_tree(
            tx,
            issuer_did=credential.issuer_did,
            chain_id=31337,
            registry_address="0x" + "1" * 40,
            now=140,
        )
        assert revoked_tree.tree.entries == ()
        assert revoked_tree.tree.root != initial_tree.tree.root
        assert revoked_tree.source_digest != initial_tree.source_digest
    async with store(db).transaction() as tx:
        with pytest.raises(EnrollmentIneligible, match="revoked"):
            await load_unrevoked_enrollment(tx, "a" * 64, now=140)
    assert (await store(db).get("credential", "a" * 64))["consent"]["credential"] == credential.model_dump(mode="json")
    assert (await store(db).get("revocation", "a" * 64))["reason_code"] == "issuer-withdrawal"
    # An encrypted row alone is not sufficient: tampered retained consent must
    # stop the registrar build even if its commitment was recomputed.
    from src.protocol.enrollment import EnrollmentError

    bad = await store(db).get("credential", "a" * 64)
    changed_credential = PilotCredential.model_validate({**credential.model_dump(), "credential_nonce": "b" * 64})
    changed_consent = EnrollmentConsent.model_validate({**consent.model_dump(), "credential": changed_credential})
    bad["consent"] = changed_consent.model_dump(mode="json")
    bad["credential_commitment"] = changed_credential.commitment
    async with PilotStore(db, cipher(), principal).transaction() as tx:
        await tx.put("credential", "b" * 64, bad)
        with pytest.raises(EnrollmentError):
            await build_issuance_tree(
                tx,
                issuer_did=credential.issuer_did,
                chain_id=31337,
                registry_address="0x" + "1" * 40,
                now=140,
            )


async def test_tenant_keyset_scan_and_issuance_capacity_fail_without_truncation(db):
    from src.services.issuance_tree import build_issuance_tree

    principal = Principal(
        tenant_id="tenant-a",
        actor_id="issuer",
        roles=("credential:issue", "evidence:decrypt"),
        issuer_dids=("did:web:issuer.example",),
    )
    a = PilotStore(db, cipher(), principal)
    async with a.transaction() as tx:
        for index in range(257):
            await tx.put("credential", f"id-{index:04}", {})
        ids = await tx.record_ids("credential")
        assert len(ids) == 256 and ids[0] == "id-0000" and ids[-1] == "id-0255"
        assert await tx.record_ids("credential", after=ids[-1]) == ["id-0256"]
        with pytest.raises(ValueError, match="capacity"):
            await build_issuance_tree(
                tx, issuer_did="did:web:issuer.example", chain_id=31337, registry_address="0x" + "1" * 40, now=120
            )
    async with store(db, "tenant-b").transaction() as tx:
        assert await tx.record_ids("credential") == []


async def test_atomic_registrar_refresh_and_rollback(db, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from eth_account import Account

    from src.protocol.credential import PilotCredential, holder_commitment
    from src.protocol.enrollment import EnrollmentConsent
    from src.protocol.root_snapshot import RootAuthority, RootTrustError, RootTrustStore, SignedRootSnapshot
    from src.services.enrollment import EnrollmentService, RevocationRequest
    from src.services.registrar import PilotRegistrar

    principal = Principal(
        tenant_id="tenant-a",
        actor_id="registrar",
        roles=("tenant:admin", "credential:issue", "credential:revoke", "evidence:decrypt"),
        issuer_dids=("did:web:issuer.example", "did:web:second.example"),
    )
    key = Ed25519PrivateKey.generate()
    authority = RootAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id="tenant-a",
        chain_id=31337,
        registry_address="0x" + "1" * 40,
        kinds=("issuance-root", "issuer-root"),
        issuer_dids=("did:web:issuer.example",),
        not_before=1,
        not_after=1000,
    )
    trust = RootTrustStore([authority])

    def registrar(issuers=("did:web:issuer.example",)):
        return PilotRegistrar(
            db, cipher(), principal, trust, key, issuers=issuers, chain_id=31337, registry_address="0x" + "1" * 40
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
        issued_at=100,
        expires_at=900,
    )
    consent = EnrollmentConsent(
        credential=credential, chain_id=31337, registry_address="0x" + "1" * 40, consent_expires_at=200
    )
    enrollment = EnrollmentService(db, cipher(), principal, chain_id=31337, registry_address="0x" + "1" * 40)
    await enrollment.enroll(
        consent,
        "0x" + wallet.sign_message(consent.signing_message()).signature.hex(),
        idempotency_key="enroll",
        now=110,
    )
    # The first issuer can be approved, but the signer lacks scope for the second.
    # Neither that first approval nor any source or retry result may survive.
    with pytest.raises(RootTrustError):
        await registrar(("did:web:issuer.example", "did:web:second.example")).refresh(
            expected_revision=0, idempotency_key="failed", now=120
        )
    reader = PilotStore(db, cipher(), principal)
    async with reader.transaction() as tx:
        assert await tx.record_ids("issuance-root") == []
        assert await tx.record_ids("issuer-root") == []
        assert await tx.record_ids("root-source") == []
    first = await registrar().refresh(expected_revision=0, idempotency_key="refresh-1", now=120)
    assert first["revision"] == 1
    assert await registrar().refresh(expected_revision=0, idempotency_key="refresh-1", now=125) == first
    async with reader.transaction() as tx:
        head_id = (await tx.record_ids("issuer-root"))[0]
        initial = SignedRootSnapshot.model_validate(await tx.get("issuer-root", head_id))
        assert (
            trust.verify_current(
                initial,
                now=125,
                expected_digest=first["snapshot_digest"],
                tenant_id="tenant-a",
                chain_id=31337,
                registry_address="0x" + "1" * 40,
                kind="issuer-root",
            ).root
            == first["root"]
        )
        issuance_id = (await tx.record_ids("issuance-root"))[0]
        issued = SignedRootSnapshot.model_validate(await tx.get("issuance-root", issuance_id))
        evidence = await tx.get("root-source", issued.snapshot.source_digest)
        assert evidence["entries"] == [{"credential_id": "a" * 64, "commitment": credential.commitment}]
    await enrollment.revoke(
        RevocationRequest(credential_id="a" * 64, idempotency_key="revoke", reason_code="withdrawn"), now=130
    )
    results = await asyncio.gather(
        registrar().refresh(expected_revision=1, idempotency_key="refresh-2", now=140),
        registrar().refresh(expected_revision=1, idempotency_key="refresh-fork", now=140),
        return_exceptions=True,
    )
    assert sum(isinstance(item, RecordConflict) for item in results) == 1
    second = next(item for item in results if type(item) is dict)
    assert second["revision"] == 2 and second["root"] != first["root"]
    await db.close()
    await db.connect()
    async with reader.transaction() as tx:
        updated = SignedRootSnapshot.model_validate(await tx.get("issuance-root", issuance_id))
        assert (await tx.get("root-source", updated.snapshot.source_digest))["entries"] == []
        assert (await tx.read("issuer-root", head_id)).revision == 2
        assert (await tx.read("issuer-root", head_id, revision=1)).value == initial.model_dump(mode="json")
    # Pause after constructing a candidate and observe the competing revocation
    # actually waiting on PostgreSQL's advisory lock, not merely an idle task.
    from src.services import registrar as registrar_module

    next_credential = PilotCredential.model_validate({**credential.model_dump(), "credential_nonce": "b" * 64})
    next_consent = EnrollmentConsent.model_validate({**consent.model_dump(), "credential": next_credential})
    await enrollment.enroll(
        next_consent,
        "0x" + wallet.sign_message(next_consent.signing_message()).signature.hex(),
        idempotency_key="enroll-next",
        now=150,
    )
    entered, release = asyncio.Event(), asyncio.Event()
    original_builder = registrar_module.build_issuance_tree

    async def paused_builder(*args, **kwargs):
        result = await original_builder(*args, **kwargs)
        entered.set()
        await release.wait()
        return result

    monkeypatch.setattr(registrar_module, "build_issuance_tree", paused_builder)
    refresh_task = asyncio.create_task(registrar().refresh(expected_revision=2, idempotency_key="refresh-3", now=160))
    await asyncio.wait_for(entered.wait(), 5)
    revoke_task = asyncio.create_task(
        enrollment.revoke(
            RevocationRequest(credential_id="b" * 64, idempotency_key="revoke-next", reason_code="withdrawn"),
            now=165,
        )
    )
    try:
        async with asyncio.timeout(5):
            while True:
                async with db.connection() as conn:
                    row = await (
                        await conn.execute("SELECT count(*) FROM pg_stat_activity WHERE wait_event='advisory'")
                    ).fetchone()
                if row[0]:
                    break
                await asyncio.sleep(0.01)
        assert not revoke_task.done()
    finally:
        release.set()
        await asyncio.gather(refresh_task, revoke_task)
    assert refresh_task.result()["revision"] == 3
    assert revoke_task.result()["status"] == "revoked"
    monkeypatch.setattr(registrar_module, "build_issuance_tree", original_builder)
    final = await registrar().refresh(expected_revision=3, idempotency_key="refresh-4", now=170)
    assert final["root"] == second["root"]


async def test_reviewed_policy_history_is_atomic_private_and_survives_restart(db):
    import runpy
    from pathlib import Path

    from src.policy.diff import PolicyCase
    from src.policy.model import PilotPolicy
    from src.services.policy_review import PolicyReviewRequest, PolicyReviewService, ReviewedCase

    policy, transfer, context, facts = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "unit/test_policy_evaluator.py")
    )["case"].__wrapped__()
    case = PolicyCase(
        case_id="review-001", transfer=transfer, context=context, facts=facts, evaluated_at=context.evaluated_at
    )
    request = PolicyReviewRequest(policy=policy, cases=(ReviewedCase(case=case, expected="ALLOW"),))
    principal = Principal(tenant_id="tenant-a", actor_id="reviewer-a", roles=("policy:approve", "evidence:decrypt"))
    service = PolicyReviewService(db, cipher(), principal)
    now = context.evaluated_at
    result = await service.approve(request, idempotency_key="approval-1", now=now)
    assert result == await service.approve(request, idempotency_key="approval-1", now=now + 1)
    await db.close()
    await db.connect()
    service = PolicyReviewService(db, cipher(), principal)
    saved = await service.store.get("policy", policy.digest)
    assert saved["actor_id"] == "reviewer-a" and saved["approved_at"] == now
    assert saved["reviews"][0]["expected"] == "ALLOW"
    case_digest = saved["reviews"][0]["case_digest"]
    assert (await service.store.get("policy", case_digest))["case"] == case.model_dump(mode="json")
    assert await store(db, "tenant-b").get("policy", policy.digest) is None
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT row_to_json(r)::text FROM pilot_records r")).fetchall()
        assert all(transfer.originator.wallet not in row[0] and "reviewer-a" not in row[0] for row in rows)
    next_policy = PilotPolicy.model_validate({**policy.model_dump(), "revision": 2, "previous_digest": policy.digest})
    next_request = PolicyReviewRequest(policy=next_policy, cases=request.cases)
    await service.approve(next_request, idempotency_key="approval-2", now=now)
    assert (await service.store.get("policy", next_policy.digest))["policy"]["previous_digest"] == policy.digest
    with pytest.raises(RecordConflict):
        await service.approve(request, idempotency_key="different-key", now=now)
    bad = PolicyReviewRequest(policy=policy, cases=(ReviewedCase(case=case, expected="DENY"),))
    with pytest.raises(ValueError, match="expected outcome"):
        await service.approve(bad, idempotency_key="bad-outcome", now=now)
    foreign = PolicyReviewService(
        db, cipher(), Principal(tenant_id="tenant-b", actor_id="reviewer-b", roles=principal.roles)
    )
    with pytest.raises(ValueError, match="tenant"):
        await foreign.approve(request, idempotency_key="foreign", now=now)
    missing = PilotPolicy.model_validate({**policy.model_dump(), "revision": 2, "previous_digest": "f" * 64})
    with pytest.raises(ValueError, match="predecessor"):
        await service.approve(
            PolicyReviewRequest(policy=missing, cases=request.cases), idempotency_key="missing", now=now
        )
    assert await service.store.get("policy", missing.digest) is None
