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


async def test_policy_http_approval_and_stored_comparison_real_jwt(db, monkeypatch):
    import runpy
    from pathlib import Path
    from types import SimpleNamespace

    from httpx import ASGITransport, AsyncClient

    from src.api.routes import policy as routes
    from src.protocol.canonical import record_digest
    from src.storage.keyring import load_keyring

    fixtures = runpy.run_path(str(Path(__file__).resolve().parents[1] / "unit/test_policy_diff.py"))
    comparison = fixtures["comparison"].__wrapped__()
    app, token = fixtures["authenticated_app"].__wrapped__(monkeypatch)
    app.state.db = db
    monkeypatch.setenv("PII_MASTER_KEY", "61" * 32)
    monkeypatch.setattr(routes, "time", SimpleNamespace(time=lambda: comparison.cases[0].evaluated_at))
    headers = {"Authorization": "Bearer " + token(roles=("policy:approve", "policy:read", "evidence:decrypt"))}
    snapshots = [{"case": case.model_dump(mode="json"), "expected": "ALLOW"} for case in comparison.cases]
    body = {
        "review": {"policy": comparison.before.model_dump(mode="json"), "cases": snapshots},
        "idempotency_key": "http-approval-1",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/pilot/policy/approve", json=body, headers=headers)
        assert first.status_code == 200, first.text
        assert first.json() == (await client.post("/pilot/policy/approve", json=body, headers=headers)).json()
        forged = {**body, "approved_at": 0, "actor_id": "forged-reviewer"}
        rejected = await client.post("/pilot/policy/approve", json=forged, headers=headers)
        assert rejected.status_code == 422 and "forged-reviewer" not in rejected.text
        assert (await client.post("/pilot/policy/approve", json=body)).status_code == 401
        readonly = {"Authorization": "Bearer " + token()}
        assert (await client.post("/pilot/policy/approve", json=body, headers=readonly)).status_code == 403
        foreign = {
            "Authorization": "Bearer "
            + token(tenant="tenant-b", roles=("policy:approve", "policy:read", "evidence:decrypt"))
        }
        assert (await client.post("/pilot/policy/approve", json=body, headers=foreign)).status_code == 403
        second = {
            "review": {
                "policy": comparison.after.model_dump(mode="json"),
                "cases": [{**item, "expected": "REVIEW"} for item in snapshots],
            },
            "idempotency_key": "http-approval-2",
        }
        assert (await client.post("/pilot/policy/approve", json=second, headers=headers)).status_code == 200
        await db.close()
        await db.connect()
        stored = {
            "before_digest": comparison.before.digest,
            "after_digest": comparison.after.digest,
            "case_digests": [record_digest("clearproof/review-case/v1", item["case"]) for item in snapshots],
        }
        async with db.connection() as conn:
            count_before = await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone()
        result = await client.post("/pilot/policy/diff/stored", json=stored, headers=readonly)
        assert result.status_code == 200 and result.json()["review_delta"] == 1
        assert comparison.cases[0].transfer.originator.wallet not in result.text
        repeated = await client.post("/pilot/policy/diff/stored", json=stored, headers=readonly)
        assert repeated.json() == result.json()
        assert (await client.post("/pilot/policy/diff/stored", json=stored, headers=foreign)).status_code == 404
        duplicate = {**stored, "case_digests": stored["case_digests"] * 2}
        assert (await client.post("/pilot/policy/diff/stored", json=duplicate, headers=readonly)).status_code == 422
        if os.getenv("CLEARPROOF_POLICY_CLI_TEST") == "1":
            await exercise_policy_cli(app, token, comparison, stored, result.json())
        async with db.connection() as conn:
            assert count_before == await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone()
            assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
        retained = store(db, encryption=RecordCipher(load_keyring()))
        approval = await retained.get("policy", comparison.before.digest)
        assert approval["actor_id"] == "actor-a" and approval["approved_at"] == comparison.cases[0].evaluated_at


async def exercise_policy_cli(app, token, comparison, stored, expected):
    """Actual Node stdin process -> loopback HTTP -> verified JWT -> PostgreSQL."""
    import json
    import shutil
    import socket
    from pathlib import Path

    import uvicorn

    node = shutil.which("node")
    cli = Path(__file__).resolve().parents[2] / "packages/cli/dist/index.js"
    assert node and cli.is_file(), "Build the CLI and install Node before enabling the integration gate"
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", access_log=False, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def invoke(payload, bearer, retained):
        process = await asyncio.create_subprocess_exec(
            node,
            str(cli),
            "policy",
            "diff",
            "--api-url",
            origin,
            *(["--stored"] if retained else []),
            env={"PATH": os.environ.get("PATH", ""), "CLEARPROOF_API_TOKEN": bearer},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(payload).encode()), 15)
            return process.returncode, stdout, stderr
        finally:
            if process.returncode is None:
                process.kill()
            await process.wait()

    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                    raise AssertionError("API server stopped before startup")
                await asyncio.sleep(0.01)
        for retained, payload in ((False, comparison.model_dump(mode="json")), (True, stored)):
            code, stdout, stderr = await invoke(payload, token(), retained)
            assert code == 0, stderr.decode()
            assert json.loads(stdout) == expected
            assert comparison.cases[0].transfer.originator.wallet.encode() not in stdout + stderr
        code, stdout, stderr = await invoke(stored, token(tenant="tenant-b"), True)
        assert code == 1 and stdout == b""
        assert b"Policy comparison failed" in stderr
        assert stored["before_digest"].encode() not in stderr
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 10)
        finally:
            sock.close()


async def test_event_ingestion_concurrent_retry_restart_conflict_rollback_and_scope(db):
    from src.reconciliation.events import SourceEvent, TransferScope
    from src.services.event_ingestion import EventAuthority, EventIngestionService

    scope = TransferScope(
        tenant_id="tenant-a", transfer_id="transfer-a", chain_id="1", registry_address="0x" + "12" * 20
    )
    principal = Principal(
        tenant_id="tenant-a", actor_id="ingester-a", roles=("events:ingest", "evidence:decrypt", "evidence:read")
    )
    authority = EventAuthority(
        tenant_id="tenant-a",
        chain_id="1",
        registry_address=scope.registry_address,
        source_id="custody-a",
        actors=("ingester-a",),
        dimensions=("custody",),
        valid_from=1,
        valid_until=300,
    )
    service = EventIngestionService(db, cipher(), principal, authorities=(authority,))
    source = SourceEvent(
        scope=scope,
        source_id="custody-a",
        source_event_id="event-2",
        source_sequence=2,
        dimension="custody",
        state="submitted",
        occurred_at=100,
        evidence_digest="ab" * 32,
    )
    results = await asyncio.gather(*(service.ingest(source, now=110) for _ in range(5)))
    assert sum(not item["duplicate"] for item in results) == 1
    assert len({item["event_id"] for item in results}) == 1
    older = SourceEvent.model_validate(
        {
            **source.model_dump(),
            "source_event_id": "event-1",
            "source_sequence": 1,
            "state": "created",
            "occurred_at": 90,
        }
    )
    await service.ingest(older, now=120)
    await db.close()
    await db.connect()
    service = EventIngestionService(db, cipher(), principal, authorities=(authority,))
    report = await service.investigate(scope, now=150)
    assert report.states["custody"] == "submitted" and len(report.timeline) == 2
    retry = await service.ingest(source, now=140)
    assert retry["duplicate"] and retry["ingested_at"] == 110
    assert (await service.investigate(scope, now=150)).model_dump_json() == report.model_dump_json()
    conflict = SourceEvent.model_validate({**source.model_dump(), "source_event_id": "different-id"})
    with pytest.raises(RecordConflict):
        await service.ingest(conflict, now=140)
    changed = SourceEvent.model_validate({**source.model_dump(), "state": "failed"})
    with pytest.raises(RecordConflict):
        await service.ingest(changed, now=140)
    # The sequence conflict occurs after the encrypted record insert; both must roll back.
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records WHERE kind='event'")).fetchone())[0] == 2
        assert (await (await conn.execute("SELECT count(*) FROM pilot_event_index")).fetchone())[0] == 2
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
        rows = await (await conn.execute("SELECT row_to_json(r)::text FROM pilot_records r")).fetchall()
        assert all("ingester-a" not in row[0] and "custody-a" not in row[0] for row in rows)
    impostor = EventIngestionService(
        db, cipher(), Principal(tenant_id="tenant-a", actor_id="other", roles=principal.roles), authorities=(authority,)
    )
    with pytest.raises(ValueError, match="authority"):
        await impostor.ingest(source, now=150)
    with pytest.raises(ValueError, match="authority"):
        await service.ingest(source, now=300)
    unsupported = SourceEvent.model_validate({**source.model_dump(), "dimension": "proof", "state": "valid"})
    with pytest.raises(ValueError, match="authority"):
        await service.ingest(unsupported, now=150)
    foreign_scope = TransferScope.model_validate({**scope.model_dump(), "tenant_id": "tenant-b"})
    with pytest.raises(ValueError, match="tenant"):
        await service.investigate(foreign_scope, now=150)
    foreign_authority = EventAuthority.model_validate({**authority.model_dump(), "tenant_id": "tenant-b"})
    foreign = EventIngestionService(
        db,
        cipher(),
        Principal(tenant_id="tenant-b", actor_id="ingester-a", roles=principal.roles),
        authorities=(foreign_authority,),
    )
    assert (await foreign.investigate(foreign_scope, now=150)).timeline == ()
    await foreign.ingest(SourceEvent.model_validate({**source.model_dump(), "scope": foreign_scope}), now=150)
    assert len((await foreign.investigate(foreign_scope, now=150)).timeline) == 1


@pytest.fixture
def event_case():
    from src.reconciliation.events import SourceEvent, TransferScope
    from src.services.event_ingestion import EventAuthority

    scope = TransferScope(
        tenant_id="tenant-a", transfer_id="transfer-a", chain_id="1", registry_address="0x" + "12" * 20
    )
    source = SourceEvent(
        scope=scope,
        source_id="custody-a",
        source_event_id="event-1",
        source_sequence=1,
        dimension="custody",
        state="submitted",
        occurred_at=100,
        evidence_digest="ab" * 32,
    )
    authority = EventAuthority(
        tenant_id="tenant-a",
        chain_id="1",
        registry_address=scope.registry_address,
        source_id="custody-a",
        actors=("actor-a",),
        dimensions=("custody",),
        valid_from=1,
        valid_until=300,
    )
    return source, authority


async def test_event_api_real_jwt_configuration_and_minimized_errors(db, monkeypatch, event_case):
    import json
    import runpy
    from pathlib import Path
    from types import SimpleNamespace

    from httpx import ASGITransport, AsyncClient

    from src.api.routes import events as routes

    source, authority = event_case
    fixture = runpy.run_path(str(Path(__file__).resolve().parents[1] / "unit/test_policy_diff.py"))
    app, token = fixture["authenticated_app"].__wrapped__(monkeypatch)
    app.include_router(routes.router)
    app.state.db = db
    monkeypatch.setenv("PII_MASTER_KEY", "61" * 32)
    monkeypatch.setenv("PILOT_EVENT_AUTHORITIES", json.dumps({"authorities": [authority.model_dump(mode="json")]}))
    monkeypatch.setattr(routes, "time", SimpleNamespace(time=lambda: 150))
    headers = {"Authorization": "Bearer " + token(roles=("events:ingest", "evidence:read", "evidence:decrypt"))}
    body = source.model_dump(mode="json")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/pilot/events/ingest", json=body, headers=headers)
        assert first.status_code == 200 and not first.json()["duplicate"]
        again = await client.post("/pilot/events/ingest", json=body, headers=headers)
        assert again.status_code == 200 and again.json()["duplicate"]
        assert (await client.post("/pilot/events/ingest", json=body)).status_code == 401
        missing_role = {"Authorization": "Bearer " + token()}
        assert (await client.post("/pilot/events/ingest", json=body, headers=missing_role)).status_code == 403
        spoofed = await client.post("/pilot/events/ingest", json={**body, "ingested_at": 1}, headers=headers)
        assert spoofed.status_code == 422 and "ingested_at" not in spoofed.text
        rejected = await client.post(
            "/pilot/events/ingest", json={**body, "customer": "secret-customer"}, headers=headers
        )
        assert rejected.status_code == 422 and "secret-customer" not in rejected.text
        unknown = await client.post("/pilot/events/ingest", json={**body, "source_id": "not-granted"}, headers=headers)
        assert unknown.status_code == 403
        conflict = await client.post("/pilot/events/ingest", json={**body, "state": "failed"}, headers=headers)
        assert conflict.status_code == 409
        assert (await client.post("/pilot/events/ingest", content=b"x" * 65537, headers=headers)).status_code == 413
        await db.close()
        await db.connect()
        scope = source.scope.model_dump(mode="json")
        report = await client.post("/pilot/events/investigate", json=scope, headers=headers)
        assert report.status_code == 200 and report.json()["states"]["custody"] == "submitted"
        assert report.json()["timeline"][0]["ingested_at"] == 150
        assert (
            await client.post("/pilot/events/investigate", json={**scope, "tenant_id": "tenant-b"}, headers=headers)
        ).status_code == 403
        monkeypatch.delenv("PILOT_EVENT_AUTHORITIES")
        assert (await client.post("/pilot/events/ingest", json=body, headers=headers)).status_code == 503
        assert (await client.post("/pilot/events/investigate", json=scope, headers=headers)).status_code == 200


async def test_process_death_between_event_and_index_rolls_back(db, event_case):
    import json
    import sys

    from src.services.event_ingestion import EventIngestionService

    source, authority = event_case
    principal = Principal(
        tenant_id="tenant-a", actor_id="actor-a", roles=("events:ingest", "evidence:decrypt", "evidence:read")
    )
    program = """
import asyncio,json,sys
from src.auth.principal import Principal
from src.reconciliation.events import SourceEvent
from src.services.event_ingestion import EventAuthority,EventIngestionService
from src.storage.database import Database
from src.storage.keyring import KeyRing,KeyVersion
from src.storage.pilot_cipher import RecordCipher
from src.storage.pilot import PilotTransaction
async def pause_after_insert(self,*args):
    print("INSERTED-UNCOMMITTED",flush=True)
    await asyncio.sleep(60)
async def main():
    data=json.loads(sys.stdin.read())
    db=Database(pool_min=1,pool_max=1)
    await db.connect()
    PilotTransaction.index_event=pause_after_insert
    principal=Principal.model_validate_json(json.dumps(data["principal"]))
    authority=EventAuthority.model_validate_json(json.dumps(data["authority"]))
    cipher=RecordCipher(KeyRing(KeyVersion("current",b"a"*32,0)))
    service=EventIngestionService(db,cipher,principal,authorities=(authority,))
    await service.ingest(SourceEvent.model_validate_json(json.dumps(data["source"])),now=150)
asyncio.run(main())
"""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        program,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        payload = {
            "principal": principal.model_dump(mode="json"),
            "authority": authority.model_dump(mode="json"),
            "source": source.model_dump(mode="json"),
        }
        process.stdin.write(json.dumps(payload).encode())
        await process.stdin.drain()
        process.stdin.close()
        assert await asyncio.wait_for(process.stdout.readline(), 15) == b"INSERTED-UNCOMMITTED\n"
        process.kill()
        await asyncio.wait_for(process.wait(), 10)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
    service = EventIngestionService(db, cipher(), principal, authorities=(authority,))
    # Taking the tenant lock waits for the dead backend's transaction rollback.
    assert (await service.investigate(source.scope, now=150)).timeline == ()
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records WHERE kind='event'")).fetchone())[0] == 0
    result = await service.ingest(source, now=151)
    assert not result["duplicate"]
    assert len((await service.investigate(source.scope, now=152)).timeline) == 1


async def test_fireblocks_verified_bytes_retained_atomically_and_private(db):
    import base64
    import hashlib
    import json
    import runpy
    from pathlib import Path

    from src.adapters.fireblocks import FireblocksError
    from src.protocol.canonical import record_digest
    from src.services.event_ingestion import EventAuthority, EventIngestionService
    from src.services.fireblocks_intake import FireblocksIntake

    fixture = runpy.run_path(str(Path(__file__).resolve().parents[1] / "unit/test_fireblocks.py"))
    verifier, key, binding, _ = fixture["setup"].__wrapped__()
    payload = json.loads(fixture["FIXTURE"].read_bytes())
    payload["data"]["note"] = "synthetic-private-marker" + "é" * 4000
    raw, now = json.dumps(payload, ensure_ascii=False).encode(), fixture["NOW"]
    principal = Principal(
        tenant_id="tenant-a", actor_id="adapter-a", roles=("events:ingest", "evidence:read", "evidence:decrypt")
    )
    authority = EventAuthority(
        tenant_id="tenant-a",
        chain_id=binding.scope.chain_id,
        registry_address=binding.scope.registry_address,
        source_id=binding.source_id,
        actors=("adapter-a",),
        dimensions=("custody",),
        valid_from=0,
        valid_until=now // 1000 + 1000,
    )
    events = EventIngestionService(db, cipher(), principal, authorities=(authority,))
    intake = FireblocksIntake(events, verifier)
    signature = fixture["sign"](raw, key)
    result = await intake.ingest(raw, signature, binding, now_ms=now)
    repeated = await intake.ingest(raw, signature, binding, now_ms=now + 1000)
    assert repeated["duplicate"] and repeated["ingested_at"] == result["ingested_at"]
    await db.close()
    await db.connect()
    persisted = await events.store.get("event", result["event_id"])
    records = [await events.store.get("provider-evidence", ref) for ref in persisted["evidence_records"]]
    manifest = records[-1]
    assert len(manifest["chunks"]) > 1
    restored = bytearray()
    for ref in manifest["chunks"]:
        chunk = await events.store.get("provider-evidence", ref)
        assert record_digest("clearproof/provider-evidence/v1", chunk) == ref
        restored.extend(base64.b64decode(chunk["base64"], validate=True))
    assert bytes(restored) == raw and hashlib.sha256(restored).hexdigest() == manifest["raw_sha256"]
    assert manifest["signature"] == signature
    assert verifier.verify(bytes(restored), signature, binding, now_ms=now).state == "completed"
    report = await events.investigate(binding.scope, now=now // 1000 + 2)
    assert report.states["custody"] == "completed" and report.states["chain"] == "unknown"
    assert "synthetic-private-marker" not in report.model_dump_json()
    async with db.connection() as conn:
        before = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
        rows = await (await conn.execute("SELECT row_to_json(r)::text FROM pilot_records r")).fetchall()
        assert all("synthetic-private-marker" not in row[0] and signature not in row[0] for row in rows)
    other = store(db, "tenant-b")
    assert all([await other.get("provider-evidence", ref) is None for ref in persisted["evidence_records"]])
    with pytest.raises(FireblocksError):
        await intake.ingest(raw + b" ", signature, binding, now_ms=now)
    # Same source timestamp but new identity: evidence is written first, then the
    # unique sequence index rejects. All new chunks/manifest must roll back.
    altered = json.loads(raw)
    altered["id"] = "44444444-4444-4444-8444-444444444444"
    conflict = json.dumps(altered).encode()
    with pytest.raises(RecordConflict):
        await intake.ingest(conflict, fixture["sign"](conflict, key), binding, now_ms=now)
    async with db.connection() as conn:
        assert before == (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]


async def test_fireblocks_relay_requires_jwt_signature_and_operator_binding(db, monkeypatch):
    import json
    import runpy
    from pathlib import Path
    from types import SimpleNamespace

    from httpx import ASGITransport, AsyncClient

    from src.api.routes import fireblocks as routes
    from src.services.event_ingestion import EventAuthority

    root = Path(__file__).resolve().parents[1]
    fixtures = runpy.run_path(str(root / "unit/test_fireblocks.py"))
    _, key, binding, jwks = fixtures["setup"].__wrapped__()
    auth_fixture = runpy.run_path(str(root / "unit/test_policy_diff.py"))
    app, token = auth_fixture["authenticated_app"].__wrapped__(monkeypatch)
    app.include_router(routes.router)
    app.state.db = db
    now, raw = fixtures["NOW"], fixtures["FIXTURE"].read_bytes()
    signature = fixtures["sign"](raw, key)
    config = {
        "integrations": [
            {
                "integration_id": "simulator-a",
                "binding": binding.model_dump(mode="json"),
                "jwks": json.loads(jwks),
                "key_valid_from_ms": now - 100000,
                "key_valid_until_ms": now + 100000,
                "max_age_ms": 86400000,
            }
        ]
    }
    authority = EventAuthority(
        tenant_id="tenant-a",
        chain_id=binding.scope.chain_id,
        registry_address=binding.scope.registry_address,
        source_id=binding.source_id,
        actors=("actor-a",),
        dimensions=("custody",),
        valid_from=0,
        valid_until=now // 1000 + 1000,
    )
    monkeypatch.setenv("PILOT_FIREBLOCKS_INTEGRATIONS", json.dumps(config))
    monkeypatch.setenv("PILOT_EVENT_AUTHORITIES", json.dumps({"authorities": [authority.model_dump(mode="json")]}))
    monkeypatch.setenv("PII_MASTER_KEY", "61" * 32)
    monkeypatch.setattr(routes, "time", SimpleNamespace(time_ns=lambda: now * 1000000))
    headers = {
        "Authorization": "Bearer " + token(roles=("events:ingest", "evidence:decrypt")),
        "Fireblocks-Webhook-Signature": signature,
    }
    url = "/pilot/fireblocks/simulator-a"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        good = await client.post(url, content=raw, headers=headers)
        assert good.status_code == 200 and not good.json()["duplicate"], good.text
        assert "synthetic-private-marker" not in good.text
        await db.close()
        await db.connect()
        retry = await client.post(url, content=raw, headers=headers)
        assert retry.status_code == 200 and retry.json()["duplicate"]
        async with db.connection() as conn:
            count = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
        no_jwt = {"Fireblocks-Webhook-Signature": signature}
        assert (await client.post(url, content=raw, headers=no_jwt)).status_code == 401
        read_only = {**headers, "Authorization": "Bearer " + token()}
        assert (await client.post(url, content=raw, headers=read_only)).status_code == 403
        foreign = {
            **headers,
            "Authorization": "Bearer " + token(tenant="tenant-b", roles=("events:ingest", "evidence:decrypt")),
        }
        assert (await client.post(url, content=raw, headers=foreign)).status_code == 404
        assert (await client.post("/pilot/fireblocks/unknown", content=raw, headers=headers)).status_code == 404
        legacy = {"Authorization": headers["Authorization"], "Fireblocks-Signature": signature}
        assert (await client.post(url, content=raw, headers=legacy)).status_code == 401
        duplicates = list(headers.items()) + [("Fireblocks-Webhook-Signature", signature)]
        assert (await client.post(url, content=raw, headers=duplicates)).status_code == 401
        tampered = await client.post(url, content=raw + b" ", headers=headers)
        assert tampered.status_code == 422 and "synthetic-private-marker" not in tampered.text
        assert (await client.post(url, content=b"x" * 65537, headers=headers)).status_code == 413
        payload = json.loads(raw)
        payload["workspaceId"] = "other-workspace"
        wrong_scope = json.dumps(payload).encode()
        assert (
            await client.post(
                url,
                content=wrong_scope,
                headers={**headers, "Fireblocks-Webhook-Signature": fixtures["sign"](wrong_scope, key)},
            )
        ).status_code == 422
        monkeypatch.setenv("PILOT_EVENT_AUTHORITIES", '{"authorities":[]}')
        assert (await client.post(url, content=raw, headers=headers)).status_code == 403
        monkeypatch.delenv("PILOT_FIREBLOCKS_INTEGRATIONS")
        assert (await client.post(url, content=raw, headers=headers)).status_code == 503
        async with db.connection() as conn:
            assert count == (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
            assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0


async def test_ageing_queue_paginates_without_omissions_or_cross_tenant_reads(db, monkeypatch, event_case):
    import runpy
    from pathlib import Path
    from types import SimpleNamespace

    from httpx import ASGITransport, AsyncClient

    from src.api.routes import events as routes
    from src.reconciliation.events import SourceEvent, TransferScope
    from src.reconciliation.queue import QueueRequest
    from src.services.event_ingestion import EventIngestionService

    source, authority = event_case
    principal = Principal(
        tenant_id="tenant-a", actor_id="actor-a", roles=("events:ingest", "evidence:read", "evidence:decrypt")
    )
    service = EventIngestionService(db, cipher(), principal, authorities=(authority,))
    scopes = []
    for index in range(4):
        scope = TransferScope.model_validate({**source.scope.model_dump(), "transfer_id": f"transfer-{index}"})
        scopes.append(scope)
        await service.ingest(
            SourceEvent.model_validate(
                {
                    **source.model_dump(),
                    "scope": scope,
                    "source_event_id": f"event-{index}",
                    "occurred_at": 100 + index,
                    "state": "submitted" if index == 3 else "failed",
                }
            ),
            now=150,
        )
    await db.close()
    await db.connect()
    full = await service.queue(QueueRequest(limit=16), now=200)
    assert full.scanned_transfers == 4 and full.next_cursor is None
    assert [item.oldest_age_seconds for item in full.items] == [100, 99, 98]
    assert all(item.findings[0].reason == "settlement-failed" for item in full.items)
    assert "timeline" not in full.model_dump_json() and source.evidence_digest not in full.model_dump_json()
    cursor, scanned, seen = None, 0, set()
    while True:
        page = await service.queue(QueueRequest(after=cursor, limit=1), now=200)
        scanned += page.scanned_transfers
        for item in page.items:
            assert item.scope_digest not in seen
            seen.add(item.scope_digest)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert scanned == 4 and seen == {item.scope_digest for item in full.items}
    filtered = await service.queue(QueueRequest(limit=1, minimum_age_seconds=1000), now=200)
    assert filtered.items == () and filtered.next_cursor is not None and filtered.scanned_transfers == 1
    assert (await service.queue(QueueRequest(minimum_age_seconds=100), now=200)).items == full.items[:1]
    foreign = EventIngestionService(
        db, cipher(), Principal(tenant_id="tenant-b", actor_id="actor-a", roles=principal.roles), authorities=()
    )
    assert (await foreign.queue(QueueRequest(), now=200)).items == ()
    fixture = runpy.run_path(str(Path(__file__).resolve().parents[1] / "unit/test_policy_diff.py"))
    app, token = fixture["authenticated_app"].__wrapped__(monkeypatch)
    app.include_router(routes.router)
    app.state.db = db
    monkeypatch.setenv("PII_MASTER_KEY", "61" * 32)
    monkeypatch.setattr(routes, "time", SimpleNamespace(time=lambda: 200))
    headers = {"Authorization": "Bearer " + token(roles=("evidence:read", "evidence:decrypt"))}
    async with db.connection() as conn:
        count = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/pilot/events/queue", json={"limit": 16}, headers=headers)
        assert response.status_code == 200 and response.json() == full.model_dump(mode="json")
        assert (await client.post("/pilot/events/queue", json={})).status_code == 401
        assert (
            await client.post("/pilot/events/queue", json={}, headers={"Authorization": "Bearer " + token()})
        ).status_code == 403
        for invalid in (
            {"tenant_id": "tenant-b"},
            {"limit": 17},
            {"after": "not-a-digest"},
            {"minimum_age_seconds": -1},
        ):
            assert (await client.post("/pilot/events/queue", json=invalid, headers=headers)).status_code == 422
    async with db.connection() as conn:
        assert count == (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
