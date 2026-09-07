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
from tests.integration.pilot_outputs import retain_output

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


@pytest.fixture
async def mirror_evm(request):
    url = os.getenv("CLEARPROOF_MIRROR_TEST_RPC")
    if not url or request.node.callspec.params.get("mutation") != "authorization":
        yield None
        return
    from pathlib import Path

    from tests.integration.pilot_mirror_evm import LocalAuthorizationEVM

    evm = LocalAuthorizationEVM(url)
    try:
        await evm.deploy(Path(os.environ["CLEARPROOF_PILOT_TEST_ARTIFACTS"]))
        yield evm
    finally:
        await evm.close()


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
        EnrollmentIntegrityError,
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
        assert (
            await load_unrevoked_enrollment(tx, "a" * 64, chain_id=31337, registry_address="0x" + "1" * 40, now=120)
            == credential
        )
        # Consent can expire after valid acceptance without expiring the credential.
        assert (
            await load_unrevoked_enrollment(tx, "a" * 64, chain_id=31337, registry_address="0x" + "1" * 40, now=201)
            == credential
        )
        for chain_id, address in [(31338, "0x" + "1" * 40), (31337, "0x" + "2" * 40), (True, "0x" + "1" * 40)]:
            with pytest.raises(EnrollmentIneligible, match="audience"):
                await load_unrevoked_enrollment(tx, "a" * 64, chain_id=chain_id, registry_address=address, now=120)
        for invalid_time in (109, 1000):
            with pytest.raises(EnrollmentIneligible):
                await load_unrevoked_enrollment(
                    tx, "a" * 64, chain_id=31337, registry_address="0x" + "1" * 40, now=invalid_time
                )
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
            await load_unrevoked_enrollment(tx, "a" * 64, chain_id=31337, registry_address="0x" + "1" * 40, now=140)
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
            await load_unrevoked_enrollment(tx, "b" * 64, chain_id=31337, registry_address="0x" + "1" * 40, now=140)
        with pytest.raises(EnrollmentError):
            await build_issuance_tree(
                tx,
                issuer_did=credential.issuer_did,
                chain_id=31337,
                registry_address="0x" + "1" * 40,
                now=140,
            )

    # Even authentic consent must have been accepted within its signed interval.
    for index, accepted_at in enumerate((True, 99, 200)):
        nonce = str(index + 3) * 64
        altered = PilotCredential.model_validate({**credential.model_dump(), "credential_nonce": nonce})
        valid_consent = EnrollmentConsent.model_validate({**consent.model_dump(), "credential": altered})
        record = {
            **bad,
            "consent": valid_consent.model_dump(mode="json"),
            "signature": "0x" + wallet.sign_message(valid_consent.signing_message()).signature.hex(),
            "credential_commitment": altered.commitment,
            "accepted_at": accepted_at,
        }
        async with PilotStore(db, cipher(), principal).transaction() as tx:
            await tx.put("credential", nonce, record)
            with pytest.raises(EnrollmentIntegrityError, match="acceptance"):
                await load_unrevoked_enrollment(tx, nonce, chain_id=31337, registry_address="0x" + "1" * 40, now=201)


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
        retain_output("policy-comparison.json", result.json())
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
        link = dict(
            tenant_id=source.scope.tenant_id,
            scope_digest=source.scope.digest,
            source_id=source.source_id,
            label="provider-console",
            url="https://console.example/tx/opaque",
        )
        excluded = [
            dict(link, tenant_id="tenant-b"),
            dict(link, scope_digest="ff" * 32),
            dict(link, source_id="other-source"),
        ]
        monkeypatch.setenv("PILOT_INVESTIGATION_LINKS", json.dumps({"links": [link, *excluded]}))
        linked = await client.post("/pilot/events/investigate", json=scope, headers=headers)
        expected_link = {k: v for k, v in link.items() if k not in ("tenant_id", "scope_digest")}
        assert linked.status_code == 200 and linked.json()["provider_links"] == [expected_link]
        failure_event = dict(
            body, state="failed", source_event_id="queue-failure", source_sequence=body["source_sequence"] + 1
        )
        assert (await client.post("/pilot/events/ingest", json=failure_event, headers=headers)).status_code == 200
        page = await client.post("/pilot/events/queue", json={}, headers=headers)
        assert page.status_code == 200 and page.json()["items"][0]["provider_links"] == [expected_link]
        unknown_scope = {**scope, "transfer_id": "unknown-transfer"}
        assert (await client.post("/pilot/events/investigate", json=unknown_scope, headers=headers)).json()[
            "provider_links"
        ] == []
        spoofed_link = await client.post(
            "/pilot/events/investigate", json={**scope, "provider_links": [link]}, headers=headers
        )
        assert spoofed_link.status_code == 422 and "console.example" not in spoofed_link.text
        monkeypatch.setenv(
            "PILOT_INVESTIGATION_LINKS", json.dumps({"links": [dict(link, url="javascript:PRIVATE-MARKER")]})
        )
        invalid = await client.post("/pilot/events/investigate", json=scope, headers=headers)
        assert invalid.status_code == 503 and "PRIVATE-MARKER" not in invalid.text
        monkeypatch.delenv("PILOT_INVESTIGATION_LINKS")
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
    if os.getenv("CLEARPROOF_POLICY_CLI_TEST") == "1":
        timeline = await service.investigate(scopes[0], now=200)
        await exercise_investigation_cli(app, token, scopes[0], full, timeline)
    async with db.connection() as conn:
        assert count == (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0


async def exercise_investigation_cli(app, token, scope, expected_queue, expected_timeline):
    import json
    import shutil
    import socket
    from pathlib import Path

    import uvicorn

    node = shutil.which("node")
    cli = Path(__file__).resolve().parents[2] / "packages/cli/dist/index.js"
    assert node and cli.is_file(), "Build CLI before enabling the integration gate"
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", access_log=False, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def invoke(
        command, payload, *, pages="1", output_json=True, roles=("evidence:read", "evidence:decrypt"), tenant="tenant-a"
    ):
        child = await asyncio.create_subprocess_exec(
            node,
            str(cli),
            "investigation",
            command,
            "--api-url",
            origin,
            "--pages",
            pages,
            *(["--json"] if output_json else []),
            env={"PATH": os.environ.get("PATH", ""), "CLEARPROOF_API_TOKEN": token(roles=roles, tenant=tenant)},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(child.communicate(json.dumps(payload).encode()), 15)
            return child.returncode, stdout, stderr
        finally:
            if child.returncode is None:
                child.kill()
            await child.wait()

    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                    raise AssertionError("API server exited before startup")
                await asyncio.sleep(0.01)
        code, stdout, stderr = await invoke("timeline", scope.model_dump(mode="json"))
        assert code == 0, stderr.decode()
        assert json.loads(stdout) == expected_timeline.model_dump(mode="json")
        code, stdout, stderr = await invoke("queue", {"limit": 1}, pages="4")
        assert code == 0, stderr.decode()
        report = json.loads(stdout)
        assert report["complete_from_start"] and report["pages_fetched"] == report["scanned_transfers"] == 4
        assert report["items"] == expected_queue.model_dump(mode="json")["items"]
        code, stdout, stderr = await invoke("queue", {"limit": 1})
        assert code == 0 and not json.loads(stdout)["complete_from_start"]
        assert json.loads(stdout)["next_cursor"] is not None
        code, stdout, stderr = await invoke("queue", {}, output_json=False)
        assert code == 0 and b"settlement-failed" in stdout and b"owner operations" in stdout
        code, stdout, stderr = await invoke("timeline", scope.model_dump(mode="json"), tenant="tenant-b")
        assert code == 1 and not stdout and scope.transfer_id.encode() not in stderr
        code, stdout, stderr = await invoke("queue", {}, roles=("evidence:decrypt",))
        assert code == 1 and not stdout
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 10)
        finally:
            sock.close()


@pytest.mark.skipif(not os.getenv("CLEARPROOF_PILOT_TEST_ARTIFACTS"), reason="requires fresh synthetic pilot artifacts")
async def test_durable_registrar_witness_real_proof(db, tmp_path, monkeypatch):
    """Enroll -> registrar -> reconnect -> private witness -> real proof -> current inspection."""
    import hashlib
    import json
    import runpy
    import shutil
    import subprocess
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from eth_account import Account

    from src.policy.diff import PolicyCase
    from src.policy.evaluator import PolicyFacts
    from src.protocol.credential import PilotCredential
    from src.protocol.enrollment import EnrollmentConsent
    from src.protocol.root_snapshot import RootTrustError, SignedRootSnapshot, root_scope_id
    from src.protocol.transfer import VerificationContext
    from src.prover.pilot_artifacts import inspect_artifacts
    from src.prover.pilot_roots import CurrentRootPins
    from src.prover.pilot_verifier import PilotPairingVerifier
    from src.registry.pilot_sanctions import PilotSanctionsTree
    from src.services.enrollment import EnrollmentIneligible, EnrollmentService, RevocationRequest
    from src.services.policy_activation import PolicyActivationRequest, PolicyActivationService
    from src.services.policy_review import PolicyReviewRequest, PolicyReviewService, ReviewedCase
    from src.services.proof_inspection import CurrentStatementConfiguration
    from src.services.proof_preparation import ProofPreparationService
    from src.services.registrar import PilotRegistrar
    from src.services.root_publication import RootPublicationService
    from src.storage.pilot import PilotTransaction

    root = Path(os.environ["CLEARPROOF_PILOT_TEST_ARTIFACTS"])
    artifacts = inspect_artifacts(root, trusted_digest=(root / "development-manifest-pin.txt").read_text().strip())
    helper = runpy.run_path(str(Path(__file__).parents[1] / "unit/test_pilot_compliance.py"))["synthetic_case"]
    # Discard the helper's unrelated witness and replace both issuance approvals.
    _, _, inputs = helper(artifact_manifest_digest=artifacts.manifest.digest, with_trust=True)
    credential, now = inputs.pop("credential"), inputs.pop("now")
    principal = Principal(
        tenant_id=credential.tenant_id,
        actor_id="durable-prover",
        roles=(*ROLES, "policy:activate", "policy:read"),
        issuer_dids=(credential.issuer_did,),
    )
    reader = PilotStore(db, cipher(), principal)
    pins = inputs["root_pins"]
    enrollment = EnrollmentService(
        db, cipher(), principal, chain_id=pins.chain_id, registry_address=pins.registry_address
    )
    wallet = Account.from_key(bytes([8]) * 32)

    async def enroll(value, key):
        consent = EnrollmentConsent(
            credential=value,
            chain_id=pins.chain_id,
            registry_address=pins.registry_address,
            consent_expires_at=min(value.issued_at + 600, value.expires_at),
        )
        await enrollment.enroll(
            consent,
            "0x" + wallet.sign_message(consent.signing_message()).signature.hex(),
            idempotency_key=key,
            now=value.issued_at,
        )

    await enroll(credential, "enroll")
    registrar = PilotRegistrar(
        db,
        cipher(),
        principal,
        inputs["root_trust"],
        Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32),
        issuers=(credential.issuer_did,),
        chain_id=pins.chain_id,
        registry_address=pins.registry_address,
    )
    await registrar.refresh(expected_revision=0, idempotency_key="registrar", now=now, ttl=credential.expires_at - now)
    async with reader.transaction() as tx:
        for name in ("issuance", "issuers"):
            snapshot = inputs[name].snapshot
            inputs[name] = SignedRootSnapshot.model_validate(await tx.get(snapshot.kind, root_scope_id(snapshot)))
    inputs["root_pins"] = CurrentRootPins.model_validate(
        {
            **pins.model_dump(),
            "issuance_digest": inputs["issuance"].snapshot.digest,
            "issuer_digest": inputs["issuers"].snapshot.digest,
        }
    )
    inputs["context"] = VerificationContext.model_validate(
        {
            **inputs["context"].model_dump(),
            "issuance_snapshot_digest": inputs["issuance"].snapshot.digest,
            "issuer_snapshot_digest": inputs["issuers"].snapshot.digest,
        }
    )
    await RootPublicationService(db, cipher(), principal, inputs["root_trust"]).publish(
        inputs["sanctions"], idempotency_key="sanctions", now=now
    )
    policy = inputs["policy_trust"].for_transfer(
        inputs["transfer"], inputs["context"], tenant_id=principal.tenant_id, now=now
    )
    case = PolicyCase(
        case_id="durable-witness",
        transfer=inputs["transfer"],
        context=inputs["context"],
        facts=PolicyFacts(tenant_id=principal.tenant_id, transfer_digest=inputs["transfer"].digest, facts=()),
        evaluated_at=now,
    )
    await PolicyReviewService(db, cipher(), principal).approve(
        PolicyReviewRequest(policy=policy, cases=(ReviewedCase(case=case, expected="INDETERMINATE"),)),
        idempotency_key="review",
        now=now,
    )
    await PolicyActivationService(db, cipher(), principal).activate(
        PolicyActivationRequest(policy_digest=policy.digest), idempotency_key="activate", now=now
    )
    runtime = Path(__file__).parents[2] / "node_modules/snarkjs/build/snarkjs.min.js"
    verifier = PilotPairingVerifier.load(
        artifacts,
        bundle_path=runtime,
        bundle_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
        node=Path(shutil.which("node")),
    )

    def service(who=principal):
        return ProofPreparationService(db, cipher(), who, verifier, CurrentStatementConfiguration(**inputs))

    async def prepare():
        return await service().prepare_witness(
            credential.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now
        )

    witness = await prepare()
    assert witness["credential_commitment"] == credential.commitment
    await db.close()
    await db.connect()
    assert await prepare() == witness
    with pytest.raises(ValueError, match="holder"):
        await service().prepare_witness(
            credential.credential_nonce, secret="654321", sanctions_tree=PilotSanctionsTree([]), now=now
        )
    with pytest.raises(RootTrustError, match="inventory roots"):
        await service().prepare_witness(
            credential.credential_nonce,
            secret="123456",
            sanctions_tree=PilotSanctionsTree(["0x" + "9" * 40]),
            now=now,
        )
    with pytest.raises(ValueError, match="tenant"):
        service(Principal.model_validate({**principal.model_dump(), "tenant_id": "foreign"}))
    with pytest.raises(HTTPException) as denied:
        await service(
            Principal.model_validate({**principal.model_dump(), "roles": ("evidence:decrypt",)})
        ).prepare_witness(credential.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now)
    assert denied.value.status_code == 403
    original_get = PilotTransaction.get

    async def missing_source(tx, kind, record_id):
        return None if kind == "root-source" else await original_get(tx, kind, record_id)

    with monkeypatch.context() as patch:
        patch.setattr(PilotTransaction, "get", missing_source)
        with pytest.raises(RootTrustError, match="source is missing"):
            await prepare()

    async def altered_source(tx, kind, record_id):
        value = await original_get(tx, kind, record_id)
        return {**value, "tenant_id": "foreign"} if kind == "root-source" else value

    with monkeypatch.context() as patch:
        patch.setattr(PilotTransaction, "get", altered_source)
        with pytest.raises(RootTrustError, match="inconsistent"):
            await prepare()
    alternate = PilotCredential.model_validate({**credential.model_dump(), "credential_nonce": "cd" * 32})
    await enroll(alternate, "enroll-after-publication")
    with pytest.raises(RootTrustError, match="absent"):
        await service().prepare_witness(
            alternate.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now
        )
    # Only public synthetic fixture data is written for snarkjs. No production holder data.
    (tmp_path / "synthetic.json").write_text(json.dumps(witness))
    subprocess.run(
        [
            str(verifier.node),
            str(Path(__file__).parents[2] / "node_modules/snarkjs/cli.js"),
            "groth16",
            "fullprove",
            str(tmp_path / "synthetic.json"),
            str(root / "pilot_compliance_js/pilot_compliance.wasm"),
            str(root / "UNAPPROVED-development.zkey"),
            str(tmp_path / "proof.json"),
            str(tmp_path / "public.json"),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    proof, signals = (tmp_path / "proof.json").read_bytes(), json.loads((tmp_path / "public.json").read_text())
    assert (await service().inspect(credential.credential_nonce, proof, signals, now=now)).cryptographic_valid
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
    await enrollment.revoke(
        RevocationRequest(credential_id=credential.credential_nonce, idempotency_key="revoke", reason_code="withdrawn"),
        now=now,
    )
    with pytest.raises(EnrollmentIneligible, match="revoked"):
        await prepare()
    with pytest.raises(EnrollmentIneligible, match="revoked"):
        await service().inspect(credential.credential_nonce, proof, signals, now=now)
    await registrar.refresh(
        expected_revision=1, idempotency_key="advance", now=now + 1, ttl=credential.expires_at - now - 1
    )
    with pytest.raises(RootTrustError, match="head differs"):
        await service().prepare_witness(
            alternate.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now + 1
        )


@pytest.mark.skipif(not os.getenv("CLEARPROOF_PILOT_TEST_ARTIFACTS"), reason="requires fresh synthetic pilot artifacts")
@pytest.mark.parametrize("mutation", ["root", "revocation", "cancel", "policy", "activation", "authorization"])
async def test_durable_current_inspection_real_pairing_and_revocation(db, monkeypatch, mutation, tmp_path, mirror_evm):
    import hashlib
    import json
    import runpy
    import shutil
    import subprocess
    from pathlib import Path

    from eth_account import Account

    from src.policy.diff import PolicyCase
    from src.policy.evaluator import PolicyFacts
    from src.policy.model import PilotPolicy, PolicyTrustError
    from src.protocol.enrollment import EnrollmentConsent
    from src.protocol.root_snapshot import RootSnapshot, RootTrustError, sign_root
    from src.prover.pilot_artifacts import inspect_artifacts
    from src.prover.pilot_verifier import PilotPairingVerifier, ProofInspectionError
    from src.services.enrollment import EnrollmentIneligible, EnrollmentService, RevocationRequest
    from src.services.policy_activation import PolicyActivationRequest, PolicyActivationService
    from src.services.policy_review import PolicyReviewRequest, PolicyReviewService, ReviewedCase
    from src.services.proof_inspection import CurrentStatementConfiguration, ProofInspectionService
    from src.services.root_publication import RootPublicationService

    root = Path(os.environ["CLEARPROOF_PILOT_TEST_ARTIFACTS"])
    artifacts = inspect_artifacts(root, trusted_digest=(root / "development-manifest-pin.txt").read_text().strip())
    helper = runpy.run_path(str(Path(__file__).parents[1] / "unit/test_pilot_compliance.py"))["synthetic_case"]
    import time

    witness, _, inputs = helper(
        artifact_manifest_digest=artifacts.manifest.digest,
        with_trust=True,
        authorization=mutation == "authorization",
        evaluated_at=int(time.time()) - 2 if mutation == "authorization" else None,
        deployment_address=mirror_evm.address if mirror_evm else None,
    )
    credential, now = inputs.pop("credential"), inputs.pop("now")
    configuration = CurrentStatementConfiguration(**inputs)
    principal = Principal(
        tenant_id=credential.tenant_id,
        actor_id="simulator",
        roles=(*ROLES, "policy:activate", "policy:read", "facts:ingest"),
        issuer_dids=(credential.issuer_did,),
    )
    wallet = Account.from_key(bytes([8]) * 32)  # Public synthetic-only signer.
    consent = EnrollmentConsent(
        credential=credential,
        chain_id=configuration.root_pins.chain_id,
        registry_address=configuration.root_pins.registry_address,
        consent_expires_at=min(credential.issued_at + 600, credential.expires_at),
    )
    enrollment = EnrollmentService(
        db, cipher(), principal, chain_id=consent.chain_id, registry_address=consent.registry_address
    )
    await enrollment.enroll(
        consent,
        "0x" + wallet.sign_message(consent.signing_message()).signature.hex(),
        idempotency_key="synthetic-enroll",
        now=credential.issued_at,
    )
    publication = RootPublicationService(db, cipher(), principal, configuration.root_trust)
    for name in ("issuance", "issuers", "sanctions"):
        await publication.publish(getattr(configuration, name), idempotency_key="root-" + name, now=now)
    runtime = Path(__file__).parents[2] / "node_modules/snarkjs/build/snarkjs.min.js"
    verifier = PilotPairingVerifier.load(
        artifacts,
        bundle_path=runtime,
        bundle_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
        node=Path(shutil.which("node")),
    )
    proof_root = root
    if mutation == "authorization":
        # A different policy needs a different real proof, using the same inspected development artifacts.
        (tmp_path / "synthetic.json").write_text(json.dumps(witness))
        subprocess.run(
            [
                str(verifier.node),
                str(Path(__file__).parents[2] / "node_modules/snarkjs/cli.js"),
                "groth16",
                "fullprove",
                str(tmp_path / "synthetic.json"),
                str(root / "pilot_compliance_js/pilot_compliance.wasm"),
                str(root / "UNAPPROVED-development.zkey"),
                str(tmp_path / "proof.json"),
                str(tmp_path / "public.json"),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        proof_root = tmp_path
    proof = (proof_root / "proof.json").read_bytes()
    signals = json.loads((proof_root / "public.json").read_text())

    def service(who=principal):
        return ProofInspectionService(db, cipher(), who, verifier, configuration)

    policy = configuration.policy_trust.for_transfer(
        configuration.transfer, configuration.context, tenant_id=principal.tenant_id, now=now
    )
    case = PolicyCase(
        case_id="synthetic-proof-review",
        transfer=configuration.transfer,
        context=configuration.context,
        facts=PolicyFacts(tenant_id=principal.tenant_id, transfer_digest=configuration.transfer.digest, facts=()),
        evaluated_at=now,
    )
    reviewed = (ReviewedCase(case=case, expected="INDETERMINATE"),)
    review_service = PolicyReviewService(db, cipher(), principal)
    await review_service.approve(
        PolicyReviewRequest(policy=policy, cases=reviewed), idempotency_key="review-proof-policy", now=now
    )
    with pytest.raises(ValueError, match="No active policy"):
        await service().inspect(credential.credential_nonce, proof, signals, now=now)
    activation = PolicyActivationService(db, cipher(), principal)
    await activation.activate(
        PolicyActivationRequest(policy_digest=policy.digest), idempotency_key="activate-proof-policy", now=now
    )

    async with db.connection() as conn:
        before = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
    assert (await service().inspect(credential.credential_nonce, proof, signals, now=now)).cryptographic_valid
    await db.close()
    await db.connect()
    assert (await service().inspect(credential.credential_nonce, proof, signals, now=now)).cryptographic_valid
    with pytest.raises(ValueError, match="tenant"):
        service(Principal.model_validate({**principal.model_dump(), "tenant_id": "foreign"}))
    reader = Principal.model_validate({**principal.model_dump(), "roles": ("evidence:decrypt",)})
    with pytest.raises(HTTPException) as error:
        await service(reader).inspect(credential.credential_nonce, proof, signals, now=now)
    assert error.value.status_code == 403
    if mutation == "authorization":
        await check_current_inspection_http(
            db, monkeypatch, principal, configuration, verifier, proof, signals, credential.credential_nonce
        )
    wrong = [str(int(signals[0]) + 1), *signals[1:]]
    with pytest.raises(ProofInspectionError, match="public_signal_context_mismatch"):
        await service().inspect(credential.credential_nonce, proof, wrong, now=now)
    async with db.connection() as conn:
        assert before == (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0

    if mutation == "activation":
        successor = PilotPolicy.model_validate({**policy.model_dump(), "revision": 2, "previous_digest": policy.digest})
        await review_service.approve(
            PolicyReviewRequest(policy=successor, cases=reviewed), idempotency_key="review-successor", now=now
        )
        # Review alone leaves the original proof valid; selection changes acceptance.
        assert (await service().inspect(credential.credential_nonce, proof, signals, now=now)).cryptographic_valid
        await activation.activate(
            PolicyActivationRequest(policy_digest=successor.digest, expected_revision=1),
            idempotency_key="activate-successor",
            now=now,
        )
        with pytest.raises(PolicyTrustError, match="not the active tenant selection"):
            await service().inspect(credential.credential_nonce, proof, signals, now=now)
        # Restoring the same digest later cannot backdate the proof's evaluation.
        await activation.activate(
            PolicyActivationRequest(policy_digest=policy.digest, expected_revision=2),
            idempotency_key="rollback-original",
            now=now + 1,
        )
        await db.close()
        await db.connect()
        async with db.connection() as conn:
            count = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
        with pytest.raises(ValueError, match="does not cover proof evaluation time"):
            await service().inspect(credential.credential_nonce, proof, signals, now=now + 1)
        async with db.connection() as conn:
            assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == count
            assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
        return

    if mutation in ("policy", "authorization"):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from src.policy.evaluator import PolicyFact
        from src.policy.fact_approval import FactApproval, FactAuthority, FactTrustStore, sign_fact
        from src.services.fact_evidence import FactEvidenceService

        key = Ed25519PrivateKey.generate()
        authority = FactAuthority(
            public_key=key.public_key().public_bytes_raw().hex(),
            tenant_id=principal.tenant_id,
            chain_id=configuration.root_pins.chain_id,
            registry_address=configuration.root_pins.registry_address,
            source_ids=("business",),
            predicates=("applicability_resolved", "counterparty_trusted", "required_information_complete"),
            not_before=now,
            not_after=credential.expires_at,
            max_lifetime_seconds=86400,
            max_observation_age_seconds=86400,
        )
        trust = FactTrustStore([authority])
        evidence = FactEvidenceService(db, cipher(), principal, trust)

        async def retain(counterparty, *, information=True):
            approvals = tuple(
                sign_fact(
                    FactApproval(
                        tenant_id=principal.tenant_id,
                        transfer_digest=configuration.transfer.digest,
                        context_digest=configuration.context.digest,
                        source_id="business",
                        signed_at=now,
                        key_id=authority.key_id,
                        fact=PolicyFact(
                            predicate=p,
                            value=counterparty
                            if p == "counterparty_trusted"
                            else (information if p == "required_information_complete" else True),
                            observed_at=now,
                            expires_at=credential.expires_at,
                            evidence_digest="ab" * 32,
                        ),
                    ),
                    key,
                )
                for p in authority.predicates
            )
            return await evidence.retain(
                approvals, transfer=configuration.transfer, context=configuration.context, now=now
            )

        args = dict(fact_trust=trust, now=now)
        valid, missing = await service().evaluate(credential.credential_nonce, proof, signals, (), **args)
        assert valid.cryptographic_valid and missing.outcome == "INDETERMINATE"
        assert set(missing.missing_predicates) == set(authority.predicates)
        refs = await retain(True)
        valid, complete = await service().evaluate(credential.credential_nonce, proof, signals, refs, **args)
        assert valid.cryptographic_valid and complete.missing_predicates == ()
        if mutation == "authorization":
            await check_current_evaluation_http(
                db,
                monkeypatch,
                principal,
                configuration,
                verifier,
                proof,
                signals,
                credential.credential_nonce,
                trust,
                authority,
                {
                    "ALLOW": refs,
                    "DENY": await retain(False),
                    "REVIEW": await retain(True, information=False),
                    "INDETERMINATE": (),
                },
            )
            import base64

            from src.protocol.canonical import record_digest
            from src.protocol.information_approval import (
                InformationApproval,
                InformationAuthority,
                InformationTrustStore,
                SignedInformationApproval,
                sign_information,
            )
            from src.sar.hpke_envelope import generate_keypair
            from src.sar.pilot_envelope import RecipientAuthority, RecipientTrustStore, open_pilot_envelope
            from src.services.proof_authorization import AuthorizationRejected, ProofAuthorizationService
            from src.storage.pilot import PilotTransaction

            assert complete.outcome == "ALLOW"
            authorizer = ProofAuthorizationService(db, cipher(), principal, verifier, configuration)
            private, public = generate_keypair()
            recipient = RecipientAuthority(
                tenant_id=principal.tenant_id,
                chain_id=int(configuration.context.deployment_chain_id),
                registry_address=configuration.context.deployment_address,
                recipient_did=configuration.transfer.beneficiary.vasp_did,
                public_key=public.hex(),
                not_before=now,
                not_after=credential.expires_at,
            )
            make_information = runpy.run_path(str(Path(__file__).parents[1] / "unit/test_transfer_information.py"))[
                "synthetic_information"
            ]
            information = make_information(configuration.transfer, configuration.context)
            raw_information = json.dumps(information, ensure_ascii=False).encode()
            payload_args = dict(
                pii=raw_information + b" " * (32768 - len(raw_information)),
                recipient_key_id=recipient.key_id,
                recipient_trust=RecipientTrustStore([recipient]),
            )
            information_key = Ed25519PrivateKey.generate()
            information_authority = InformationAuthority(
                public_key=information_key.public_key().public_bytes_raw().hex(),
                tenant_id=principal.tenant_id,
                chain_id=int(configuration.context.deployment_chain_id),
                registry_address=configuration.context.deployment_address,
                source_ids=("synthetic-kyc",),
                not_before=now,
                not_after=credential.expires_at,
                max_lifetime_seconds=86400,
            )
            signed_information = sign_information(
                InformationApproval(
                    tenant_id=principal.tenant_id,
                    transfer_digest=configuration.transfer.digest,
                    context_digest=configuration.context.digest,
                    credential_id=credential.credential_nonce,
                    payload_digest=hashlib.sha256(payload_args["pii"]).hexdigest(),
                    source_id="synthetic-kyc",
                    source_evidence_digest="cd" * 32,
                    signed_at=now,
                    expires_at=credential.expires_at,
                    key_id=information_authority.key_id,
                ),
                information_key,
            )
            payload_args.update(
                information_approval=signed_information,
                information_trust=InformationTrustStore([information_authority]),
            )

            from src.protocol.decision_attestation import DecisionAuthority, DecisionSigner, DecisionTrustStore

            decision_key = Ed25519PrivateKey.generate()
            decision_authority = DecisionAuthority(
                tenant_id=principal.tenant_id,
                chain_id=int(configuration.context.deployment_chain_id),
                registry_address=configuration.context.deployment_address,
                public_key=decision_key.public_key().public_bytes_raw().hex(),
                not_before=now,
                not_after=credential.expires_at,
            )
            payload_args["decision_signer"] = DecisionSigner(decision_authority, decision_key)

            async def authorize(key="consume-once", references=refs, who=authorizer, body=proof, **changes):
                return await who.authorize(
                    credential.credential_nonce,
                    body,
                    signals,
                    references,
                    idempotency_key=key,
                    **args,
                    **{**payload_args, **changes},
                )

            for references in ((), await retain(False)):
                with pytest.raises(AuthorizationRejected):
                    await authorize(references=references)
            changed = json.loads(proof)
            changed["pi_c"][0] = str(int(changed["pi_c"][0]) + 1)
            with pytest.raises(AuthorizationRejected):
                await authorize(body=json.dumps(changed).encode())
            restricted = Principal.model_validate({**principal.model_dump(), "roles": ("proof:inspect",)})
            with pytest.raises(HTTPException):
                await authorize(who=ProofAuthorizationService(db, cipher(), restricted, verifier, configuration))
            async with db.connection() as conn:
                baseline = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
            for invalid_information in (b"opaque-unvalidated-information", b"{}"):
                with pytest.raises(ValueError, match="transfer information"):
                    await authorize(pii=invalid_information)
            mismatched_information = {**information, "amount_base_units": "1"}
            with pytest.raises(ValueError, match="transfer information"):
                await authorize(pii=json.dumps(mismatched_information).encode())
            valid_but_unapproved = json.loads(raw_information)
            valid_but_unapproved["originator"]["person"]["name"] = "Unapproved synthetic name"
            with pytest.raises(ValueError, match="payload authority"):
                await authorize(pii=json.dumps(valid_but_unapproved).encode())
            invalid_approval = SignedInformationApproval(
                approval=signed_information.approval,
                signature="00" * 64,
            )
            with pytest.raises(ValueError, match="signature"):
                await authorize(information_approval=invalid_approval)
            with pytest.raises(ValueError, match="Recipient key"):
                await authorize(recipient_key_id="unknown")
            from src.services import proof_authorization as authorization_module

            def fail_encryption(*values, **options):
                raise RuntimeError("synthetic encryption failure")

            with monkeypatch.context() as patch:
                patch.setattr(authorization_module, "seal_pilot_envelope", fail_encryption)
                with pytest.raises(RuntimeError, match="synthetic encryption"):
                    await authorize()
            foreign_authority = DecisionAuthority.model_validate(
                {**decision_authority.model_dump(), "tenant_id": "foreign"}
            )
            with pytest.raises(ValueError, match="Decision signer"):
                await authorize(decision_signer=DecisionSigner(foreign_authority, decision_key))
            original_consume = PilotTransaction.consume

            async def fail_after_consume(tx, *values):
                await original_consume(tx, *values)
                raise RuntimeError("synthetic failure after consumption")

            with monkeypatch.context() as patch:
                patch.setattr(PilotTransaction, "consume", fail_after_consume)
                with pytest.raises(RuntimeError, match="synthetic failure"):
                    await authorize()
            async with db.connection() as conn:
                assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == baseline
                assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
            (
                invoke_authorization,
                authorization_app,
                authorization_headers,
                authorization_body,
            ) = await prepare_authorization_http(
                db,
                monkeypatch,
                principal,
                configuration,
                verifier,
                proof,
                signals,
                credential.credential_nonce,
                refs,
                trust,
                payload_args,
                now,
            )

            async def authorize_http(key):
                response = await invoke_authorization({"idempotency_key": key})
                if response.status_code == 409:
                    raise ReplayConflict("Competing HTTP consumption")
                assert response.status_code == 200, response.text
                report = response.json()
                assert report["schema_version"] == "clearproof-authorization-response-v1"
                assert report["scope"] == "recorded-local-authorization"
                assert report["assurance"] == "development-unapproved"
                assert set(report) == {"schema_version", "scope", "assurance", "receipt"}
                return report["receipt"]

            # Different request keys compete for the same real proof nullifier.
            contenders = ("consume-once", "competing-spend")
            results = await asyncio.gather(
                authorize_http(contenders[0]), authorize_http(contenders[1]), return_exceptions=True
            )
            assert sum(isinstance(result, ReplayConflict) for result in results) == 1
            assert sum(isinstance(result, dict) for result in results) == 1
            winning_key = contenders[next(i for i, result in enumerate(results) if isinstance(result, dict))]
            receipts = await asyncio.gather(authorize(key=winning_key), authorize(key=winning_key))
            assert receipts[0] == receipts[1]
            receipt = receipts[0]
            await check_authorization_mirror(
                db,
                principal,
                configuration,
                verifier,
                receipt,
                trust,
                decision_authority,
                payload_args,
                now,
                mirror_evm=mirror_evm,
            )
            assert await authorize_http(winning_key) == receipt
            assert (await invoke_authorization({"idempotency_key": "http-second-spend"})).status_code == 409
            assert (await invoke_authorization({"idempotency_key": winning_key, "fact_ids": []})).status_code == 409
            assert (
                await invoke_authorization({"idempotency_key": winning_key}, {"actor_id": "other-actor"})
            ).status_code == 409
            assert receipt["execution"] == "not-requested" and receipt["outcome"] == "ALLOW"
            with pytest.raises(ReplayConflict):
                await authorize(key="second-spend")
            with pytest.raises(RecordConflict):
                await authorize(key=winning_key, references=())
            with pytest.raises(RecordConflict):
                changed_information = json.loads(raw_information)
                changed_information["originator"]["person"]["name"] = "Changed synthetic name"
                await authorize(key=winning_key, pii=json.dumps(changed_information).encode())
            await db.close()
            await db.connect()
            assert (
                await authorizer.authorize(
                    credential.credential_nonce,
                    proof,
                    signals,
                    refs,
                    fact_trust=trust,
                    idempotency_key=winning_key,
                    now=credential.expires_at + 1,
                    **payload_args,
                )
                == receipt
            )
            from src.api.routes import authorization as authorization_route

            monkeypatch.setattr(authorization_route, "inspection_time", lambda: credential.expires_at + 1)
            assert await authorize_http(winning_key) == receipt
            if os.getenv("CLEARPROOF_POLICY_CLI_TEST") == "1":
                await exercise_authorization_cli(
                    authorization_app,
                    authorization_headers,
                    {**authorization_body, "idempotency_key": winning_key},
                    receipt,
                )
            retained = PilotStore(db, cipher(), principal)
            record = await retained.get("proof", receipt["proof_id"])
            assert base64.b64decode(record["proof_base64"], validate=True) == proof
            assert hashlib.sha256(proof).hexdigest() == record["proof_digest"]
            assert record["policy_evaluation"]["outcome"] == "ALLOW"
            assert record["context"] == configuration.context.model_dump(mode="json")
            envelope = record["recipient_envelope"]
            expected_binding = {
                "tenant_id": principal.tenant_id,
                "transfer_digest": configuration.transfer.digest,
                "context_digest": configuration.context.digest,
                "proof_digest": hashlib.sha256(proof).hexdigest(),
                "recipient_did": recipient.recipient_did,
                "recipient_key_id": recipient.key_id,
                "sealed_at": now,
            }
            assert open_pilot_envelope(envelope, private, expected_binding=expected_binding) == payload_args["pii"]
            assert record_digest("clearproof/pilot-envelope/v1", envelope) == receipt["envelope_digest"]
            assert payload_args["pii"].decode() not in json.dumps(record)
            assert "Synthetic José Originator" not in json.dumps(record, ensure_ascii=False)
            assert "Synthetic Recipient Ltd" not in json.dumps(record)
            assert "payload_digest" not in record and "payload_digest" not in receipt
            assert record["information_approval"] == signed_information.model_dump(mode="json")
            assert (
                receipt["information_signature_digest"]
                == hashlib.sha256(bytes.fromhex(signed_information.signature)).hexdigest()
            )
            assert (await retained.get("receipt", receipt["receipt_id"]))["authorized_at"] == now
            check_bilateral_scenarios(
                record, receipt, configuration, decision_authority, payload_args, private, now, tmp_path
            )
            assert (await service().inspect(credential.credential_nonce, proof, signals, now=now)).cryptographic_valid
            async with db.connection() as conn:
                assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == baseline + 9
                assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 1
            from cryptography.hazmat.primitives.serialization import Encoding

            from src.protocol.decision_attestation import SignedDecision
            from src.prover.history_timing import TimestampTrust, timestamp_request
            from src.services.timestamp_evidence import TimestampEvidenceService, timestamp_record_bytes
            from tests.timestamp_fixture import timestamp_authority

            tsa_root, tsa_leaf, issue_timestamp = timestamp_authority(tmp_path / "tsa")
            timing_config = dict(policy_oid="1.2.3.4", not_before=now - 100, not_after=now + 86400)
            timing_trust = TimestampTrust(certificate=tsa_leaf, roots=(tsa_root,), **timing_config)
            signed_decision = SignedDecision.model_validate(record["decision_attestation"])
            timestamp_response = issue_timestamp(timestamp_request(signed_decision))
            timestamp_at = int(time.time()) + 2  # Includes the synthetic TSA's one-second accuracy.
            timestamp_service = TimestampEvidenceService(
                db,
                cipher(),
                principal,
                timing_trust=timing_trust,
                decision_trust=DecisionTrustStore([decision_authority]),
            )
            with pytest.raises(ValueError):
                await timestamp_service.attach(receipt["receipt_id"], b"invalid", now=timestamp_at)
            denied_timestamp = TimestampEvidenceService(
                db,
                cipher(),
                restricted,
                timing_trust=timing_trust,
                decision_trust=DecisionTrustStore([decision_authority]),
            )
            with pytest.raises(HTTPException):
                await denied_timestamp.attach(receipt["receipt_id"], timestamp_response, now=timestamp_at)
            timestamp_id = await timestamp_service.attach(receipt["receipt_id"], timestamp_response, now=timestamp_at)
            assert (
                await timestamp_service.attach(receipt["receipt_id"], timestamp_response, now=timestamp_at)
                == timestamp_id
            )
            await db.close()
            await db.connect()
            timestamp_record = await retained.get("authorization-evidence", timestamp_id)
            assert (
                timestamp_record_bytes(
                    timestamp_record,
                    tenant_id=principal.tenant_id,
                    receipt_id=receipt["receipt_id"],
                )
                == timestamp_response
            )
            async with db.connection() as conn:
                assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == baseline + 10
                assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 1
            evidence_manifest = await retained.get("authorization-evidence", receipt["evidence_id"])
            assert record_digest("clearproof/authorization-evidence/v1", evidence_manifest) == receipt["evidence_id"]
            assert evidence_manifest["timing_authority"] == "operator-clock-only"
            assert evidence_manifest["credential_status"]["revocation"] == "not-present-in-local-store"
            from src.protocol.canonical import canonical_bytes

            for reference in evidence_manifest["records"]:
                original = await retained.read(
                    reference["kind"], reference["record_id"], revision=reference["revision"]
                )
                assert hashlib.sha256(canonical_bytes(original.value)).hexdigest() == reference["sha256"]
            expected_config = {
                "artifact_manifest": canonical_bytes(artifacts.manifest.model_dump(mode="json")),
                "verification_key": artifacts.verification_key_bytes,
                "asset_registry": canonical_bytes(
                    [a.model_dump(mode="json") for a in configuration.registry.definitions]
                ),
                "valuation_approval": canonical_bytes(configuration.valuation_approval.model_dump(mode="json")),
                "root_pins": canonical_bytes(configuration.root_pins.model_dump(mode="json")),
            }
            for name, descriptor in evidence_manifest["configuration"].items():
                content = b""
                for chunk_id in descriptor["chunks"]:
                    chunk = await retained.get("authorization-evidence", chunk_id)
                    assert record_digest("clearproof/evidence-chunk/v1", chunk) == chunk_id
                    content += base64.b64decode("".join(chunk["data"]), validate=True)
                assert content == expected_config[name]
                assert len(content) == descriptor["size"]
                assert hashlib.sha256(content).hexdigest() == descriptor["sha256"]
            # Later activation and revocation must not rewrite the captured observation.
            successor = PilotPolicy.model_validate(
                {**policy.model_dump(), "revision": 2, "previous_digest": policy.digest}
            )
            await review_service.approve(
                PolicyReviewRequest(policy=successor, cases=reviewed), idempotency_key="later-review", now=now + 1
            )
            await activation.activate(
                PolicyActivationRequest(policy_digest=successor.digest, expected_revision=1),
                idempotency_key="later-activation",
                now=now + 1,
            )
            await enrollment.revoke(
                RevocationRequest(
                    credential_id=credential.credential_nonce,
                    idempotency_key="later-revocation",
                    reason_code="superseded",
                ),
                now=now + 1,
            )
            await db.close()
            await db.connect()
            assert await retained.get("authorization-evidence", receipt["evidence_id"]) == evidence_manifest
            selection = next(r for r in evidence_manifest["records"] if r["kind"] == "policy-activation")
            assert (await retained.read("policy-activation", selection["record_id"])).revision == 2
            assert (
                await retained.read("policy-activation", selection["record_id"], revision=selection["revision"])
            ).value["policy_digest"] == policy.digest
            foreign = PilotStore(
                db, cipher(), Principal.model_validate({**principal.model_dump(), "tenant_id": "foreign"})
            )
            assert await foreign.get("authorization-evidence", receipt["evidence_id"]) is None
            with pytest.raises(RecordConflict):
                async with retained.transaction() as tx:
                    await tx.put(
                        "authorization-evidence", receipt["evidence_id"], evidence_manifest, expected_revision=1
                    )
            from src.sar.hpke_envelope import derive_key_id
            from src.services.evidence_export import EvidenceExportService, EvidenceRecipient, open_evidence_bundle

            reviewer_private, reviewer_public = generate_keypair()
            reviewer = EvidenceRecipient(
                tenant_id=principal.tenant_id,
                reviewer_id="synthetic-reviewer",
                public_key=reviewer_public.hex(),
                not_before=now,
                not_after=now + 120,
            )
            export_principal = Principal(
                tenant_id=principal.tenant_id, actor_id="exporter", roles=("evidence:export", "evidence:decrypt")
            )
            exporter = EvidenceExportService(db, cipher(), export_principal, reviewer)
            async with db.connection() as conn:
                before_export = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
            with pytest.raises(HTTPException):
                await EvidenceExportService(db, cipher(), principal, reviewer).export(
                    receipt["receipt_id"], now=now + 2
                )
            with pytest.raises(ValueError, match="currently approved"):
                await exporter.export(receipt["receipt_id"], now=now + 120)
            with pytest.raises(ValueError, match="tenant mismatch"):
                EvidenceExportService(
                    db,
                    cipher(),
                    export_principal,
                    EvidenceRecipient.model_validate({**reviewer.model_dump(), "tenant_id": "foreign"}),
                )
            encrypted = await exporter.export(receipt["receipt_id"], now=timestamp_at + 1)
            expected_export_binding = {
                "tenant_id": principal.tenant_id,
                "receipt_id": receipt["receipt_id"],
                "reviewer_id": reviewer.reviewer_id,
                "key_id": derive_key_id(reviewer_public),
                "exported_at": timestamp_at + 1,
            }
            bundle = open_evidence_bundle(encrypted, reviewer_private, expected_binding=expected_export_binding)
            assert bundle["decision_timestamp"] == timestamp_record
            assert bundle["evidence_manifest"] == evidence_manifest
            assert bundle["proof"] == record
            assert bundle["receipt"] == {k: v for k, v in receipt.items() if k != "receipt_id"}
            assert b"Synthetic" not in encrypted and b"proof_base64" not in encrypted
            captured_selection = next(r for r in bundle["records"] if r["kind"] == "policy-activation")
            assert captured_selection["revision"] == 1 and captured_selection["value"]["policy_digest"] == policy.digest
            for name, encoded in bundle["configuration_base64"].items():
                assert base64.b64decode(encoded, validate=True) == expected_config[name]
            from copy import deepcopy

            from src.prover.history import inspect_history_bundle

            history_args = dict(
                expected_receipt_id=receipt["receipt_id"],
                expected_tenant=principal.tenant_id,
                verified_at=credential.expires_at + 100,
            )
            historical = await inspect_history_bundle(bundle, verifier, **history_args)
            assert historical.integrity_valid and historical.cryptographic_valid
            assert historical.outcome == "indeterminate"
            assert "independent_timing_evidence_missing" in historical.reasons
            assert "historical_revocation_evidence_missing" in historical.reasons
            from dataclasses import replace

            from src.policy.model import PolicyTrustStore
            from src.prover.history_statement import HistoryStatementTrust
            from src.prover.pilot_roots import CurrentRootPins

            historical_trust = HistoryStatementTrust(
                policy_trust=configuration.policy_trust,
                valuation_trust=configuration.valuation_trust,
                root_trust=configuration.root_trust,
                root_pins=configuration.root_pins,
            )
            reconstructed = await inspect_history_bundle(
                bundle, verifier, statement_trust=historical_trust, **history_args
            )
            assert reconstructed.integrity_valid and reconstructed.cryptographic_valid and reconstructed.statement_valid
            assert (
                reconstructed.outcome == "indeterminate"
                and "statement_semantics_unverified" not in reconstructed.reasons
            )
            replayed = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=historical_trust,
                fact_trust=trust,
                **history_args,
            )
            assert replayed.statement_valid and replayed.cryptographic_valid and replayed.policy_reproduced
            assert replayed.outcome == "indeterminate" and "policy_replay_unverified" not in replayed.reasons
            assert "historical_revocation_evidence_missing" in replayed.reasons
            decision_trust = DecisionTrustStore([decision_authority])
            attested = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=historical_trust,
                fact_trust=trust,
                decision_trust=decision_trust,
                **history_args,
            )
            assert attested.decision_authenticated and attested.policy_reproduced and attested.statement_valid
            assert attested.outcome == "indeterminate" and "decision_authority_unverified" not in attested.reasons
            from src.prover.history_status import HistoryStatusAuthority, HistoryStatusTrust, status_registry_id

            status_authority = HistoryStatusAuthority.model_validate(
                {
                    **decision_authority.model_dump(),
                    "registry_id": status_registry_id(configuration.context),
                    "issuer_did": credential.issuer_did,
                }
            )
            status_trust = HistoryStatusTrust([status_authority])
            with_status = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=historical_trust,
                fact_trust=trust,
                decision_trust=decision_trust,
                status_trust=status_trust,
                **history_args,
            )
            assert with_status.status_authenticated and with_status.decision_authenticated
            assert with_status.outcome == "indeterminate"
            assert with_status.reasons == (
                "independent_timing_evidence_missing",
                "information_authority_unverified",
            )
            timed = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=historical_trust,
                fact_trust=trust,
                decision_trust=decision_trust,
                status_trust=status_trust,
                timing_trust=timing_trust,
                **history_args,
            )
            assert timed.timing_authenticated and timed.status_authenticated and timed.policy_reproduced
            assert timed.timestamp_observation.accuracy_us == 1000000
            assert timed.reasons == ("information_authority_unverified",)
            historical_information = InformationTrustStore([information_authority])
            informed = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=historical_trust,
                fact_trust=trust,
                decision_trust=decision_trust,
                status_trust=status_trust,
                timing_trust=timing_trust,
                information_trust=historical_information,
                **history_args,
            )
            assert informed.information_authenticated and informed.timing_authenticated
            assert informed.outcome == "supported" and informed.reasons == ()
            full_review_trust = dict(
                statement_trust=historical_trust,
                fact_trust=trust,
                decision_trust=decision_trust,
                status_trust=status_trust,
                timing_trust=timing_trust,
                information_trust=historical_information,
            )
            for omitted in full_review_trust:
                incomplete = await inspect_history_bundle(
                    bundle,
                    verifier,
                    **{k: v for k, v in full_review_trust.items() if k != omitted},
                    **history_args,
                )
                assert incomplete.outcome == "indeterminate" and incomplete.reasons
            from src.protocol.root_snapshot import RootAuthority, RootTrustStore
            from src.protocol.valuation_approval import ValuationAuthority, ValuationTrustStore

            compromised_roots = RootTrustStore(
                [
                    RootAuthority.model_validate({**a.model_dump(), "compromised_at": now + 1})
                    for a in configuration.root_trust._authorities
                ]
            )
            compromised_quotes = ValuationTrustStore(
                [
                    ValuationAuthority.model_validate({**a.model_dump(), "compromised_at": now + 1})
                    for a in configuration.valuation_trust._authorities
                ]
            )
            compromised_facts = FactTrustStore(
                [FactAuthority.model_validate({**authority.model_dump(), "compromised_at": now + 1})]
            )
            for changes in (
                {"statement_trust": replace(historical_trust, root_trust=compromised_roots)},
                {"statement_trust": replace(historical_trust, valuation_trust=compromised_quotes)},
                {"fact_trust": compromised_facts},
            ):
                uncertain_source = await inspect_history_bundle(
                    bundle,
                    verifier,
                    **{**full_review_trust, **changes},
                    **history_args,
                )
                assert uncertain_source.outcome == "indeterminate" and uncertain_source.reasons
            changed_information_claim = deepcopy(bundle)
            changed_information_claim["proof"]["information_approval"]["approval"]["source_evidence_digest"] = "ef" * 32
            invalid_information = await inspect_history_bundle(
                changed_information_claim,
                verifier,
                information_trust=historical_information,
                **history_args,
            )
            assert invalid_information.outcome == "contradicted"
            assert invalid_information.reasons == ("information_signature_invalid",)
            for field, value in (("source_ids", ("another-source",)), ("compromised_at", now + 1)):
                excluded = InformationTrustStore(
                    [InformationAuthority.model_validate({**information_authority.model_dump(), field: value})]
                )
                unavailable_information = await inspect_history_bundle(
                    bundle,
                    verifier,
                    information_trust=excluded,
                    **history_args,
                )
                assert unavailable_information.outcome == "indeterminate"
                assert unavailable_information.reasons == ("information_authority_unavailable",)
            no_timestamp = deepcopy(bundle)
            del no_timestamp["decision_timestamp"]
            missing_timing = await inspect_history_bundle(
                no_timestamp, verifier, timing_trust=timing_trust, **history_args
            )
            assert missing_timing.outcome == "indeterminate" and not missing_timing.timing_authenticated
            swapped_timestamp = deepcopy(bundle)
            swapped_timestamp["decision_timestamp"]["response"] = [base64.b64encode(b"invalid").decode()]
            invalid_timing = await inspect_history_bundle(
                swapped_timestamp, verifier, timing_trust=timing_trust, **history_args
            )
            assert invalid_timing.outcome == "indeterminate" and not invalid_timing.timing_authenticated
            # Original signed observation survives a later real revocation. Its
            # authority must be independently delegated for this issuer/registry.
            for field, value in (
                ("issuer_did", "did:web:other.example"),
                ("registry_id", "ef" * 32),
                ("tenant_id", "foreign"),
                ("compromised_at", now + 1),
            ):
                restricted_status = HistoryStatusTrust(
                    [HistoryStatusAuthority.model_validate({**status_authority.model_dump(), field: value})]
                )
                with pytest.raises(ValueError):
                    restricted_status.verify(bundle, verified_at=history_args["verified_at"])
            missing_delegation = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=historical_trust,
                status_trust=restricted_status,
                **history_args,
            )
            assert missing_delegation.outcome == "indeterminate" and not missing_delegation.status_authenticated
            for field, value in (
                ("observed_at", now - 1),
                ("credential_id", "ee" * 32),
                ("revocation", "revoked"),
                ("registry_id", "ff" * 32),
            ):
                altered_status = deepcopy(bundle)
                altered_status["evidence_manifest"]["credential_status"][field] = value
                with pytest.raises(ValueError):
                    status_trust.verify(altered_status, verified_at=history_args["verified_at"])
            unsigned_status = deepcopy(bundle)
            del unsigned_status["proof"]["decision_attestation"]
            with pytest.raises(KeyError):
                status_trust.verify(unsigned_status, verified_at=history_args["verified_at"])
            bad_decision_signature = deepcopy(bundle)
            bad_decision_signature["proof"]["decision_attestation"]["signature"] = "00" * 64
            bad_attestation = await inspect_history_bundle(
                bad_decision_signature, verifier, decision_trust=decision_trust, **history_args
            )
            assert bad_attestation.outcome == "contradicted" and bad_attestation.reasons == (
                "decision_signature_invalid",
            )
            compromised = DecisionTrustStore(
                [DecisionAuthority.model_validate({**decision_authority.model_dump(), "compromised_at": now + 1})]
            )
            uncertain = await inspect_history_bundle(bundle, verifier, decision_trust=compromised, **history_args)
            assert uncertain.outcome == "indeterminate" and not uncertain.decision_authenticated
            forged_decision = deepcopy(bundle)
            forged_decision["proof"]["policy_evaluation"]["reasons"] = ["fabricated_reason"]
            disagreement = await inspect_history_bundle(
                forged_decision,
                verifier,
                statement_trust=historical_trust,
                fact_trust=trust,
                **history_args,
            )
            assert disagreement.outcome == "contradicted" and disagreement.reasons == ("policy_decision_mismatch",)
            assert disagreement.cryptographic_valid and not disagreement.policy_reproduced
            restricted_facts = FactTrustStore(
                [FactAuthority.model_validate({**authority.model_dump(), "source_ids": ("other-source",)})]
            )
            untrusted_policy = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=historical_trust,
                fact_trust=restricted_facts,
                **history_args,
            )
            assert untrusted_policy.outcome == "indeterminate" and not untrusted_policy.policy_reproduced
            assert untrusted_policy.reasons == ("policy_evidence_untrusted",)
            wrong_pins = CurrentRootPins.model_validate(
                {**configuration.root_pins.model_dump(), "issuer_digest": "ef" * 32}
            )
            untrusted = await inspect_history_bundle(
                bundle, verifier, statement_trust=replace(historical_trust, root_pins=wrong_pins), **history_args
            )
            assert untrusted.outcome == "indeterminate" and not untrusted.statement_valid
            assert untrusted.reasons == ("statement_trust_unavailable",)
            latest_policy = PolicyTrustStore([policy, successor], current_digests=(successor.digest,))
            changed_selection = await inspect_history_bundle(
                bundle,
                verifier,
                statement_trust=replace(historical_trust, policy_trust=latest_policy),
                **history_args,
            )
            assert changed_selection.outcome == "indeterminate" and not changed_selection.statement_valid

            async def unavailable_pairing(*values, **options):
                raise ValueError("synthetic runtime unavailable")

            with monkeypatch.context() as patch:
                patch.setattr(PilotPairingVerifier, "inspect", unavailable_pairing)
                unavailable = await inspect_history_bundle(
                    bundle,
                    verifier,
                    statement_trust=historical_trust,
                    **history_args,
                )
            assert unavailable.statement_valid and unavailable.cryptographic_valid is None
            assert unavailable.outcome == "indeterminate" and unavailable.reasons == ("pairing_unavailable",)
            for mutation_kind in ("receipt", "root", "key", "policy", "envelope", "signal", "extra_record"):
                changed_bundle = deepcopy(bundle)
                if mutation_kind == "receipt":
                    changed_bundle["receipt"]["authorized_at"] += 1
                elif mutation_kind in ("root", "policy"):
                    kind = "issuer-root" if mutation_kind == "root" else "policy"
                    item = next(r for r in changed_bundle["records"] if r["kind"] == kind)
                    item["value"]["injected"] = True
                elif mutation_kind == "key":
                    changed_bundle["configuration_base64"]["verification_key"] = base64.b64encode(b"{}").decode()
                elif mutation_kind == "envelope":
                    changed_bundle["proof"]["recipient_envelope"]["binding"]["sealed_at"] += 1
                elif mutation_kind == "signal":
                    changed_bundle["proof"]["signals"][0] = str(int(signals[0]) + 1)
                else:
                    changed_bundle["records"].append(changed_bundle["records"][0])
                contradicted = await inspect_history_bundle(changed_bundle, verifier, **history_args)
                assert contradicted.outcome == "contradicted" and not contradicted.integrity_valid
            incomplete_bundle = deepcopy(bundle)
            incomplete_bundle["records"].pop()
            missing = await inspect_history_bundle(incomplete_bundle, verifier, **history_args)
            assert missing.outcome == "indeterminate" and missing.reasons == ("missing_evidence",)
            wrong_tenant = await inspect_history_bundle(
                bundle, verifier, **{**history_args, "expected_tenant": "foreign"}
            )
            assert wrong_tenant.outcome == "contradicted"
            with pytest.raises(ValueError):
                open_evidence_bundle(encrypted, generate_keypair()[0], expected_binding=expected_export_binding)
            with pytest.raises(ValueError):
                open_evidence_bundle(
                    encrypted, reviewer_private, expected_binding={**expected_export_binding, "receipt_id": "00" * 32}
                )
            corrupted = json.loads(encrypted)
            text = corrupted["hpke"]["ct"]
            corrupted["hpke"]["ct"] = ("A" if text[0] != "A" else "B") + text[1:]
            with pytest.raises(ValueError):
                open_evidence_bundle(
                    json.dumps(corrupted).encode(), reviewer_private, expected_binding=expected_export_binding
                )
            # A fresh process decrypts and pairs with independent pins and no database.
            await db.close()
            offline = subprocess.run(
                [
                    str(Path(__file__).parents[2] / ".venv/bin/python"),
                    "-m",
                    "tests.offline_history_fixture",
                ],
                input=json.dumps(
                    {
                        "encrypted": encrypted.decode(),
                        "key": reviewer_private.hex(),
                        "binding": expected_export_binding,
                        "artifacts": str(root),
                        "pin": artifacts.manifest.digest,
                        "runtime": str(runtime),
                        "runtime_pin": hashlib.sha256(verifier.bundle).hexdigest(),
                        "node": str(verifier.node),
                        "history_args": history_args,
                        "tsa_leaf": tsa_leaf.public_bytes(Encoding.DER).hex(),
                        "tsa_root": tsa_root.public_bytes(Encoding.DER).hex(),
                        "timing_config": timing_config,
                        "trust": {
                            "policy": policy.model_dump(mode="json"),
                            "root_pins": configuration.root_pins.model_dump(mode="json"),
                            "roots": [a.model_dump(mode="json") for a in configuration.root_trust._authorities],
                            "valuations": [
                                a.model_dump(mode="json") for a in configuration.valuation_trust._authorities
                            ],
                            "facts": authority.model_dump(mode="json"),
                            "decision": decision_authority.model_dump(mode="json"),
                            "status": status_authority.model_dump(mode="json"),
                            "information": information_authority.model_dump(mode="json"),
                        },
                    }
                ),
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert offline.returncode == 0, "Offline export decryption failed"
            assert json.loads(offline.stdout) == {
                "receipt_id": receipt["receipt_id"],
                "records": len(bundle["records"]),
                "integrity": True,
                "pairing": True,
                "timing": True,
                "outcome": "supported",
            }
            from src.prover.history_cli import HistoryReviewerConfiguration

            reviewer_configuration = {
                "schema_version": "clearproof-history-reviewer-v1",
                "binding": expected_export_binding,
                "artifact_manifest_digest": artifacts.manifest.digest,
                "runtime_sha256": hashlib.sha256(verifier.bundle).hexdigest(),
                "statement": {
                    "policies": [policy.model_dump(mode="json")],
                    "policy_pins": [policy.digest],
                    "root_pins": configuration.root_pins.model_dump(mode="json"),
                    "roots": [a.model_dump(mode="json") for a in configuration.root_trust._authorities],
                    "valuations": [a.model_dump(mode="json") for a in configuration.valuation_trust._authorities],
                },
                "facts": [authority.model_dump(mode="json")],
                "decisions": [decision_authority.model_dump(mode="json")],
                "statuses": [status_authority.model_dump(mode="json")],
                "information": [information_authority.model_dump(mode="json")],
                "timing": {
                    **timing_config,
                    "certificate_der_base64": base64.b64encode(tsa_leaf.public_bytes(Encoding.DER)).decode(),
                    "roots_der_base64": [base64.b64encode(tsa_root.public_bytes(Encoding.DER)).decode()],
                },
            }
            HistoryReviewerConfiguration.model_validate_json(json.dumps(reviewer_configuration))
            bundle_path, trust_path = tmp_path / "history.encrypted.json", tmp_path / "reviewer-trust.json"
            bundle_path.write_bytes(encrypted)
            trust_path.write_text(json.dumps(reviewer_configuration))
            cli_args = [
                "--bundle",
                str(bundle_path),
                "--trust",
                str(trust_path),
                "--artifacts",
                str(root),
                "--runtime",
                str(runtime),
                "--node",
                str(verifier.node),
                "--verified-at",
                str(history_args["verified_at"]),
            ]
            python = str(Path(__file__).parents[2] / ".venv/bin/python")

            def run_history_cli(prefix, key=reviewer_private.hex()):
                return subprocess.run(prefix + cli_args, input=key + "\n", capture_output=True, text=True, timeout=30)

            # The real user command runs with database access closed; the direct
            # Python process also disables sockets before importing the command.
            prefix = [
                python,
                "-c",
                "import runpy,socket; "
                "socket.socket.connect=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('network forbidden')); "
                "runpy.run_module('src.prover.history_cli',run_name='__main__')",
            ]
            command_result = run_history_cli(prefix)
            assert command_result.returncode == 0, "History command failed"
            command_report = json.loads(command_result.stdout)
            assert command_report["outcome"] == "supported" and command_report["assurance"] == "development-unapproved"
            assert command_report["scope"] == "recorded-local-policy-decision"
            assert "Synthetic" not in command_result.stdout and reviewer_private.hex() not in command_result.stdout
            if os.environ.get("CLEARPROOF_POLICY_CLI_TEST") == "1":
                wrapped = run_history_cli(
                    [
                        str(verifier.node),
                        str(Path(__file__).parents[2] / "packages/cli/dist/index.js"),
                        "verify-history",
                        "--python",
                        python,
                    ]
                )
                assert wrapped.returncode == 0 and json.loads(wrapped.stdout) == command_report
            retain_output("history.encrypted.json", encrypted)
            retain_output("reviewer-trust.json", reviewer_configuration)
            retain_output("history-report.json", command_report)
            retain_output("history-clock.json", {"verified_at": history_args["verified_at"]})
            retain_output("reviewer-key.json", {"key": reviewer_private.hex()}, private=True)
            wrong_key = run_history_cli(prefix, generate_keypair()[0].hex())
            assert wrong_key.returncode == 2 and json.loads(wrong_key.stdout)["outcome"] == "indeterminate"
            partial_configuration = {k: v for k, v in reviewer_configuration.items() if k != "information"}
            trust_path.write_text(json.dumps(partial_configuration))
            partial = run_history_cli(prefix)
            assert partial.returncode == 2 and json.loads(partial.stdout)["outcome"] == "indeterminate"
            trust_path.write_text(json.dumps(reviewer_configuration))
            # A decrypted/resealed synthetic bundle has valid recipient encryption
            # but contradicts the independent receipt pin.
            from src.sar.hpke_envelope import seal_envelope

            changed = deepcopy(bundle)
            changed["receipt"]["authorized_at"] += 1
            sealed = json.loads(encrypted)
            sealed["hpke"] = seal_envelope(
                json.dumps(changed).encode(),
                reviewer_public,
                record_digest("clearproof/history-export-binding/v1", expected_export_binding),
            )
            bundle_path.write_text(json.dumps(sealed))
            contradicted_cli = run_history_cli(prefix)
            assert contradicted_cli.returncode == 1 and json.loads(contradicted_cli.stdout)["outcome"] == "contradicted"
            await db.connect()
            real_get = PilotTransaction.get

            async def missing_chunk(tx, kind, identity):
                if (
                    kind == "authorization-evidence"
                    and identity in evidence_manifest["configuration"]["verification_key"]["chunks"]
                ):
                    return None
                return await real_get(tx, kind, identity)

            with monkeypatch.context() as patch:
                patch.setattr(PilotTransaction, "get", missing_chunk)
                with pytest.raises(ValueError, match="chunk unavailable"):
                    await exporter.export(receipt["receipt_id"], now=now + 2)
            async with db.connection() as conn:
                assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == before_export
                assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 1
            await check_durable_local_exchange(
                db, principal, configuration, receipt, decision_authority, payload_args, private, now
            )
            return

        assert complete.outcome == "INDETERMINATE" and complete.reasons == ("no_decisive_rule",)
        provided = signals.copy()
        evaluator = service()
        real_transaction = evaluator._inspect_transaction

        async def mutate_after_pairing(*values, **options):
            checked = await real_transaction(*values, **options)
            provided[5] = "0"
            return checked

        monkeypatch.setattr(evaluator, "_inspect_transaction", mutate_after_pairing)
        _, stable = await evaluator.evaluate(credential.credential_nonce, proof, provided, refs, **args)
        assert provided[5] == "0" and stable == complete
        false_refs = await retain(False)
        _, review = await service().evaluate(credential.credential_nonce, proof, signals, false_refs, **args)
        assert review.outcome == "REVIEW" and "required_checks_incomplete" in review.reasons
        changed = json.loads(proof)
        changed["pi_c"][0] = str(int(changed["pi_c"][0]) + 1)
        invalid, absent = await service().evaluate(
            credential.credential_nonce, json.dumps(changed).encode(), signals, refs, **args
        )
        assert not invalid.cryptographic_valid and absent is None
        async with db.connection() as conn:
            assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == before + 4
            assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
        return

    if mutation != "root":
        async with db.connection() as conn:
            before_kinds = dict(
                await (await conn.execute("SELECT kind, count(*) FROM pilot_records GROUP BY kind")).fetchall()
            )
        # Pause at the real pairing boundary with the tenant transaction held.
        # Signature/root checks and the eventual pairing are never replaced.
        from src.services import proof_inspection as inspection_module

        entered, release = asyncio.Event(), asyncio.Event()
        real_inspect = inspection_module.inspect_current_statement

        async def paused(*args, **kwargs):
            entered.set()
            await release.wait()
            return await real_inspect(*args, **kwargs)

        monkeypatch.setattr(inspection_module, "inspect_current_statement", paused)
        inspecting = asyncio.create_task(service().inspect(credential.credential_nonce, proof, signals, now=now))
        revoking = None
        try:
            await asyncio.wait_for(entered.wait(), 5)
            revoking = asyncio.create_task(
                enrollment.revoke(
                    RevocationRequest(
                        credential_id=credential.credential_nonce,
                        idempotency_key="concurrent-revoke",
                        reason_code="withdrawn",
                    ),
                    now=now,
                )
            )
            # Observe an actual PostgreSQL lock wait, not a scheduling delay.
            lock = int.from_bytes(
                hashlib.sha256(("clearproof/pilot/" + principal.tenant_id).encode()).digest()[:8], "big"
            )
            async with asyncio.timeout(5):
                while True:
                    async with db.connection() as conn:
                        waiting = await (
                            await conn.execute(
                                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                                "AND classid=%s AND objid=%s AND objsubid=1 AND NOT granted "
                                "AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))",
                                (lock >> 32, lock & 0xFFFFFFFF),
                            )
                        ).fetchone()
                    if waiting[0]:
                        break
                    await asyncio.sleep(0.02)
            assert not revoking.done()
            if mutation == "cancel":
                inspecting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await inspecting
            else:
                release.set()
                assert (await asyncio.wait_for(inspecting, 10)).cryptographic_valid
            assert (await asyncio.wait_for(revoking, 5))["status"] == "revoked"
        finally:
            release.set()
            pending = [task for task in (inspecting, revoking) if task is not None]
            for task in pending:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        with pytest.raises(EnrollmentIneligible, match="revoked"):
            await service().inspect(credential.credential_nonce, proof, signals, now=now)
        async with db.connection() as conn:
            expected_kinds = {**before_kinds, "revocation": 1, "idempotency": before_kinds["idempotency"] + 1}
            after_kinds = dict(
                await (await conn.execute("SELECT kind, count(*) FROM pilot_records GROUP BY kind")).fetchall()
            )
            assert after_kinds == expected_kinds
            assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
        return

    # A newly published head invalidates the service's older current pin.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    old = configuration.issuers.snapshot
    replacement = RootSnapshot.model_validate({**old.model_dump(), "revision": 2, "previous_digest": old.digest})
    await publication.publish(
        sign_root(replacement, Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)),
        idempotency_key="new-issuer-root",
        now=now,
    )
    with pytest.raises(RootTrustError, match="head differs"):
        await service().inspect(credential.credential_nonce, proof, signals, now=now)
    await enrollment.revoke(
        RevocationRequest(
            credential_id=credential.credential_nonce, idempotency_key="revoke-simulator", reason_code="withdrawn"
        ),
        now=now,
    )
    with pytest.raises(EnrollmentIneligible, match="revoked"):
        await service().inspect(credential.credential_nonce, proof, signals, now=now)


async def test_signed_fact_retention_atomic_retry_reconnect_and_current_trust(db, monkeypatch):
    import runpy
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.policy.fact_approval import FactAuthority, FactTrustError, FactTrustStore, SignedFactApproval
    from src.services.fact_evidence import FactEvidenceService
    from src.storage.pilot import PilotTransaction

    _, authority, approvals, args, _ = runpy.run_path(str(Path(__file__).parents[1] / "unit/test_fact_approval.py"))[
        "case"
    ].__wrapped__()
    trust = FactTrustStore([authority])
    principal = Principal(
        tenant_id=args["tenant_id"], actor_id="fact-operator", roles=("facts:ingest", "policy:read", "evidence:decrypt")
    )
    operation = {key: args[key] for key in ("transfer", "context", "now")}

    def service(who=principal, inventory=trust):
        return FactEvidenceService(db, cipher(), who, inventory)

    # A write failure halfway through a verified batch rolls all new evidence back.
    original_put = PilotTransaction.put
    writes = 0

    async def fail_second(tx, kind, *values, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise RuntimeError("injected failure")
        return await original_put(tx, kind, *values, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(PilotTransaction, "put", fail_second)
        with pytest.raises(RuntimeError, match="injected"):
            await service().retain(approvals, **operation)
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == 0
    deliveries = await asyncio.gather(*(service().retain(approvals, **operation) for _ in range(4)))
    refs = deliveries[0]
    assert all(result == refs for result in deliveries)
    assert len(refs) == len(approvals)
    stored = PilotStore(db, cipher(), principal)
    original = [await stored.get("fact-evidence", ref) for ref in refs]
    await db.close()
    await db.connect()
    assert await service().retain(tuple(reversed(approvals)), **{**operation, "now": args["now"] + 1}) == refs
    assert [await stored.get("fact-evidence", ref) for ref in refs] == original
    assert await service().load_current(refs, **operation) == trust.verify_for_context(approvals, **args)
    with pytest.raises(FactTrustError):
        await service().load_current(refs, **{**operation, "now": args["transfer"].expires_at})
    foreign = Principal.model_validate({**principal.model_dump(), "tenant_id": "foreign"})
    with pytest.raises(FactTrustError):
        await service(foreign).load_current(refs, **operation)
    with pytest.raises(FactTrustError):
        await service(foreign).retain(approvals, **operation)
    reader = Principal.model_validate({**principal.model_dump(), "roles": ("policy:read", "evidence:decrypt")})
    with pytest.raises(HTTPException):
        await service(reader).retain(approvals, **operation)
    replacement = FactAuthority.model_validate(
        {**authority.model_dump(), "public_key": Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()}
    )
    with pytest.raises(FactTrustError):
        await service(inventory=FactTrustStore([replacement])).load_current(refs, **operation)
    invalid = SignedFactApproval(approval=approvals[0].approval, signature="00" * 64)
    with pytest.raises(FactTrustError):
        await service().retain((invalid,), **operation)
    async with db.connection() as conn:
        rows = await (await conn.execute("SELECT ciphertext FROM pilot_records WHERE kind='fact-evidence'")).fetchall()
        assert len(rows) == len(refs)
        assert all(b"business-source" not in bytes(row[0]) for row in rows)
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0


async def test_policy_activation_requires_review_and_serializes_current_selection(db):
    import runpy
    from pathlib import Path

    from src.policy.diff import PolicyCase
    from src.policy.model import PilotPolicy, PolicySource
    from src.protocol.canonical import record_digest
    from src.services.policy_activation import PolicyActivationRequest, PolicyActivationService, activation_scope
    from src.services.policy_review import PolicyReviewRequest, PolicyReviewService, ReviewedCase

    policy, transfer, context, facts = runpy.run_path(str(Path(__file__).parents[1] / "unit/test_policy_evaluator.py"))[
        "case"
    ].__wrapped__()
    principal = Principal(
        tenant_id=transfer.tenant_id,
        actor_id="policy-operator",
        roles=("policy:approve", "policy:activate", "policy:read", "evidence:decrypt"),
    )
    activation = PolicyActivationService(db, cipher(), principal)
    now = context.evaluated_at
    initial = PolicyActivationRequest(policy_digest=policy.digest)
    with pytest.raises(ValueError, match="Reviewed policy unavailable"):
        await activation.activate(initial, idempotency_key="first", now=now)
    review = PolicyReviewService(db, cipher(), principal)
    case = PolicyCase(case_id="approved-case", transfer=transfer, context=context, facts=facts, evaluated_at=now)
    expected = (ReviewedCase(case=case, expected="ALLOW"),)
    await review.approve(PolicyReviewRequest(policy=policy, cases=expected), idempotency_key="review-first", now=now)
    with pytest.raises(ValueError, match="No active"):
        await activation.current(activation_scope(policy), now=now)
    first = await activation.activate(initial, idempotency_key="first", now=now)
    assert first["revision"] == 1
    assert await activation.activate(initial, idempotency_key="first", now=now + 1) == first
    other = PilotPolicy.model_validate({**policy.model_dump(), "revision": 2, "previous_digest": policy.digest})
    source = PolicySource.model_validate({**policy.sources[0].model_dump(), "evidence_digest": "cd" * 32})
    alternate = PilotPolicy.model_validate({**other.model_dump(), "sources": (source,)})
    for index, candidate in enumerate((other, alternate)):
        await review.approve(
            PolicyReviewRequest(policy=candidate, cases=expected), idempotency_key=f"review-next-{index}", now=now
        )
    results = await asyncio.gather(
        *(
            activation.activate(
                PolicyActivationRequest(policy_digest=c.digest, expected_revision=1),
                idempotency_key=f"select-{i}",
                now=now + 1,
            )
            for i, c in enumerate((other, alternate))
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(r, RecordConflict) for r in results) == 1
    winner = next(r for r in results if isinstance(r, dict))
    assert (await activation.current(first["scope_digest"], now=now + 1)).digest == winner["policy_digest"]
    records = PilotStore(db, cipher(), principal)
    prior = await records.read("policy-activation", first["scope_digest"], revision=1)
    head = await records.read("policy-activation", first["scope_digest"])
    assert head.revision == 2 and head.value["previous_digest"] == record_digest(
        "clearproof/policy-activation/v1", prior.value
    )
    # An explicit reviewed rollback is another recorded selection, not history erasure.
    restored = await activation.activate(
        PolicyActivationRequest(policy_digest=policy.digest, expected_revision=2),
        idempotency_key="restore-reviewed",
        now=now + 2,
    )
    assert restored["revision"] == 3
    await db.close()
    await db.connect()
    assert (await activation.current(first["scope_digest"], now=now + 2)).digest == policy.digest
    assert (await records.read("policy-activation", first["scope_digest"], revision=2)).value == head.value
    with pytest.raises(ValueError):
        await activation.current(first["scope_digest"], now=policy.effective_until)
    foreign = Principal.model_validate({**principal.model_dump(), "tenant_id": "foreign"})
    with pytest.raises(ValueError):
        await PolicyActivationService(db, cipher(), foreign).current(first["scope_digest"], now=now + 2)
    reviewer = Principal.model_validate({**principal.model_dump(), "roles": ("policy:approve", "evidence:decrypt")})
    with pytest.raises(HTTPException):
        await PolicyActivationService(db, cipher(), reviewer).activate(initial, idempotency_key="forbidden", now=now)
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0


async def check_current_inspection_http(
    db, monkeypatch, principal, configuration, verifier, proof, signals, credential_id
):
    """Same real proof/state through authenticated HTTP, with no dependency overrides."""
    import json
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from httpx import ASGITransport, AsyncClient

    from src.api.main import create_app
    from src.api.middleware import auth
    from src.api.routes.pilot_proof import InspectionTarget

    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    monkeypatch.setattr(
        auth,
        "JWT_PUBLIC_KEY",
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    monkeypatch.setenv("PII_MASTER_KEY", (b"a" * 32).hex())
    current = int(time.time())
    claims = dict(
        iss=auth.JWT_ISSUER,
        aud=auth.JWT_AUDIENCE,
        sub="simulator",
        iat=current,
        exp=current + 300,
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        roles=["proof:inspect", "evidence:decrypt"],
    )

    def headers(**changes):
        return {"Authorization": "Bearer " + jwt.encode({**claims, **changes}, key, algorithm="ES256")}

    body = dict(
        target_id="synthetic-transfer", credential_id="unused", proof_json=proof.decode(), public_signals=signals
    )
    body["credential_id"] = credential_id
    app = create_app()
    app.state.db = db
    targets = {(principal.tenant_id, "synthetic-transfer"): InspectionTarget(configuration, verifier)}
    app.state.pilot_inspection_targets = targets
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/pilot/proof/inspect", json=body, headers=headers())
        assert response.status_code == 200, response.text
        assert response.json() == dict(
            schema_version="clearproof-current-inspection-v1",
            scope="current-statement-inspection",
            authorization_consumed=False,
            assurance="development-unapproved",
            cryptographic_valid=True,
            manifest_digest=configuration.context.artifact_manifest_digest,
            proof_profile="pilot-transfer-v2",
        )
        altered_proof = json.loads(proof)
        altered_proof["pi_a"] = altered_proof["pi_c"]
        invalid = await client.post(
            "/pilot/proof/inspect", json=dict(body, proof_json=json.dumps(altered_proof)), headers=headers()
        )
        assert invalid.status_code == 200, invalid.text
        assert invalid.json()["cryptographic_valid"] is False
        assert invalid.json()["authorization_consumed"] is False
        assert (await client.post("/pilot/proof/inspect", json=body)).status_code == 401
        for changes, status in [({"roles": ["proof:inspect"]}, 403), ({"tenant_id": "foreign"}, 404)]:
            assert (
                await client.post("/pilot/proof/inspect", json=body, headers=headers(**changes))
            ).status_code == status
        for altered in [dict(body, target_id="missing"), dict(body, credential_id="missing")]:
            assert (await client.post("/pilot/proof/inspect", json=altered, headers=headers())).status_code == 404
        for altered in [
            dict(body, now=current),
            dict(body, root_trust="PRIVATE-MARKER"),
            dict(body, public_signals=[str(int(signals[0]) + 1), *signals[1:]]),
            dict(body, public_signals=signals + ["0"]),
            dict(body, proof_json="PRIVATE-MARKER"),
        ]:
            rejected = await client.post("/pilot/proof/inspect", json=altered, headers=headers())
            assert rejected.status_code == 422, rejected.text
            assert "PRIVATE-MARKER" not in rejected.text
        duplicate = json.dumps(body)[:-1] + ',"target_id":"other"}'
        assert (await client.post("/pilot/proof/inspect", content=duplicate, headers=headers())).status_code == 422
        assert (await client.post("/pilot/proof/inspect", content=b"x" * 16385, headers=headers())).status_code == 413
        app.state.pilot_inspection_targets = None
        assert (await client.post("/pilot/proof/inspect", json=body, headers=headers())).status_code == 503
        app.state.pilot_inspection_targets = targets
    if os.getenv("CLEARPROOF_POLICY_CLI_TEST") == "1":
        await exercise_current_inspection_cli(app, body, headers, response.json())
    await db.close()
    await db.connect()
    restarted = create_app()
    restarted.state.db = db
    restarted.state.pilot_inspection_targets = targets
    async with AsyncClient(transport=ASGITransport(app=restarted), base_url="http://test") as client:
        assert (await client.post("/pilot/proof/inspect", json=body, headers=headers())).json()["cryptographic_valid"]


async def exercise_current_inspection_cli(app, body, headers, expected):
    """Built CLI -> SDK -> real HTTP/JWT -> real pairing and PostgreSQL state."""
    import json
    import shutil
    import socket
    from pathlib import Path

    import uvicorn

    node = shutil.which("node")
    cli = Path(__file__).resolve().parents[2] / "packages/cli/dist/index.js"
    assert node and cli.is_file(), "Build the CLI before enabling the integration gate"
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", access_log=False, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def invoke(payload, **claims):
        process = await asyncio.create_subprocess_exec(
            node,
            str(cli),
            "inspect-current",
            "--api-url",
            origin,
            env={
                "PATH": os.environ.get("PATH", ""),
                "CLEARPROOF_API_TOKEN": headers(**claims)["Authorization"].removeprefix("Bearer "),
            },
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(payload).encode()), 30)
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
        code, stdout, stderr = await invoke(body)
        assert code == 0 and json.loads(stdout) == expected, stderr.decode()
        assert stderr == b""
        changed = json.loads(body["proof_json"])
        changed["pi_a"] = changed["pi_c"]
        code, stdout, stderr = await invoke(dict(body, proof_json=json.dumps(changed)))
        assert code == 1 and json.loads(stdout) == dict(expected, cryptographic_valid=False)
        assert stderr == b""
        for payload, claims in [
            (body, {"tenant_id": "foreign"}),
            (body, {"roles": ["proof:inspect"]}),
            (dict(body, proof_json="PRIVATE-MARKER"), {}),
        ]:
            code, stdout, stderr = await invoke(payload, **claims)
            assert code == 2 and stdout == b""
            assert b"Current proof inspection failed" in stderr
            assert b"PRIVATE-MARKER" not in stderr and origin.encode() not in stderr
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 10)
        finally:
            sock.close()


async def check_current_evaluation_http(
    db, monkeypatch, principal, configuration, verifier, proof, signals, credential_id, trust, authority, cases
):
    """Four synthetic policy outcomes through real JWT, retained facts and pairing."""
    import json
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from httpx import ASGITransport, AsyncClient

    from src.api.main import create_app
    from src.api.middleware import auth
    from src.api.routes.pilot_proof import InspectionTarget
    from src.policy.fact_approval import FactAuthority, FactTrustStore

    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    monkeypatch.setattr(
        auth,
        "JWT_PUBLIC_KEY",
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    monkeypatch.setenv("PII_MASTER_KEY", (b"a" * 32).hex())
    now = int(time.time())
    roles = ["proof:inspect", "policy:read", "evidence:decrypt"]
    claims = dict(
        iss=auth.JWT_ISSUER,
        aud=auth.JWT_AUDIENCE,
        sub="simulator",
        iat=now,
        exp=now + 300,
        tenant_id=principal.tenant_id,
        actor_id=principal.actor_id,
        roles=roles,
    )

    def headers(**changes):
        return {"Authorization": "Bearer " + jwt.encode({**claims, **changes}, key, algorithm="ES256")}

    body = dict(
        target_id="synthetic-transfer",
        credential_id=credential_id,
        proof_json=proof.decode(),
        public_signals=signals,
        fact_ids=list(cases["ALLOW"]),
    )
    app = create_app()
    app.state.db = db
    selector = (principal.tenant_id, "synthetic-transfer")
    targets = {selector: InspectionTarget(configuration, verifier, trust)}
    app.state.pilot_inspection_targets = targets
    async with db.connection() as conn:
        count = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for outcome, references in cases.items():
            result = await client.post("/pilot/proof/evaluate", json=dict(body, fact_ids=references), headers=headers())
            assert result.status_code == 200, result.text
            report = result.json()
            assert report["schema_version"] == "clearproof-current-evaluation-v1"
            assert report["scope"] == "current-policy-evaluation" and report["authorization_consumed"] is False
            assert report["assurance"] == "development-unapproved"
            assert report["inspection"]["cryptographic_valid"] is True
            assert report["policy"]["outcome"] == outcome
            assert report["policy"]["zk_coverage"] == "not-established"
            assert report["policy"]["policy_digest"] == configuration.context.policy_digest
            assert now <= report["policy"]["evaluated_at"] <= int(time.time())
            assert configuration.transfer.originator.wallet not in result.text
            assert "business" not in result.text
        changed = json.loads(proof)
        changed["pi_a"] = changed["pi_c"]
        invalid = await client.post(
            "/pilot/proof/evaluate", json=dict(body, proof_json=json.dumps(changed)), headers=headers()
        )
        assert invalid.status_code == 200 and invalid.json()["inspection"]["cryptographic_valid"] is False
        assert invalid.json()["policy"] is None
        assert (await client.post("/pilot/proof/evaluate", json=body)).status_code == 401
        for omitted in roles:
            assert (
                await client.post(
                    "/pilot/proof/evaluate", json=body, headers=headers(roles=[r for r in roles if r != omitted])
                )
            ).status_code == 403
        assert (
            await client.post("/pilot/proof/evaluate", json=body, headers=headers(tenant_id="foreign"))
        ).status_code == 404
        for altered in [
            dict(body, fact_ids=list(cases["ALLOW"]) * 2),
            dict(body, fact_ids=["00" * 32]),
            dict(body, fact_trust="PRIVATE-MARKER"),
            dict(body, now=now),
            dict(body, fact_ids=["PRIVATE-MARKER"]),
        ]:
            rejected = await client.post("/pilot/proof/evaluate", json=altered, headers=headers())
            assert rejected.status_code == 422, rejected.text
            assert "PRIVATE-MARKER" not in rejected.text
        targets[selector] = InspectionTarget(configuration, verifier)
        assert (await client.post("/pilot/proof/evaluate", json=body, headers=headers())).status_code == 503
        other_authority = FactAuthority.model_validate(
            {
                **authority.model_dump(),
                "public_key": Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
            }
        )
        targets[selector] = InspectionTarget(configuration, verifier, FactTrustStore([other_authority]))
        assert (await client.post("/pilot/proof/evaluate", json=body, headers=headers())).status_code == 422
        targets[selector] = InspectionTarget(configuration, verifier, trust)
    await db.close()
    await db.connect()
    restarted = create_app()
    restarted.state.db = db
    restarted.state.pilot_inspection_targets = targets
    async with AsyncClient(transport=ASGITransport(app=restarted), base_url="http://test") as client:
        result = await client.post("/pilot/proof/evaluate", json=body, headers=headers())
        assert result.status_code == 200 and result.json()["policy"]["outcome"] == "ALLOW"
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == count
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
    await check_durable_observations(
        db,
        monkeypatch,
        principal,
        configuration,
        verifier,
        proof,
        signals,
        credential_id,
        trust,
        cases,
        FactTrustStore([other_authority]),
    )
    await check_observation_http(app, db, headers, body, cases)


async def check_durable_observations(
    db, monkeypatch, principal, configuration, verifier, proof, signals, credential_id, trust, cases, excluded_trust
):
    """Durable non-enforcement, idempotency, isolation and rollback with real proofs."""
    import json
    import time

    from src.services.proof_observation import ObservationRecord, ProofObservationService, read_observation
    from src.storage.pilot import PilotTransaction

    observer = Principal.model_validate(
        {**principal.model_dump(), "roles": ("observations:write", "proof:inspect", "policy:read", "evidence:decrypt")}
    )
    service = ProofObservationService(db, cipher(), observer, verifier, configuration)
    now = int(time.time())
    async with db.connection() as conn:
        baseline = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]

    async def observe(key="observe-allow", refs=cases["ALLOW"], **changes):
        return await service.observe(
            credential_id,
            proof,
            signals,
            refs,
            **{
                "fact_trust": trust,
                "idempotency_key": key,
                "now": now,
                **changes,
            },
        )

    first, repeated = await asyncio.gather(observe(), observe())
    assert first == repeated
    assert first["mode"] == "observation" and first["authorization_consumed"] is False
    assert first["execution"] == "not-requested" and first["assurance"] == "development-unapproved"
    assert first["policy"]["outcome"] == "ALLOW"
    assert first["schema_version"] == "clearproof-proof-observation-v2"
    assert first["latency_scope"] == "current-evaluation-only"
    assert 0 < first["evaluation_duration_ns"] <= 60_000_000_000
    reports = [first]
    for outcome in ("DENY", "REVIEW", "INDETERMINATE"):
        report = await observe(key="observe-" + outcome.lower(), refs=cases[outcome])
        assert report["policy"]["outcome"] == outcome and report["cryptographic_valid"] is True
        reports.append(report)
    changed = json.loads(proof)
    changed["pi_a"] = changed["pi_c"]
    invalid = await service.observe(
        credential_id,
        json.dumps(changed).encode(),
        signals,
        cases["ALLOW"],
        fact_trust=trust,
        idempotency_key="observe-invalid-pairing",
        now=now,
    )
    assert invalid["cryptographic_valid"] is False and invalid["policy"] is None
    reports.append(invalid)
    fresh = await observe(key="observe-again", now=now + 1)
    assert fresh["observation_id"] != first["observation_id"]
    reports.append(fresh)
    # Seed the exact v1 cache/storage shape to exercise upgrade-compatible retries.
    from src.protocol.canonical import record_digest
    from src.services.observation_report import ObservationCase, ObservationCohort, observation_cohort_report

    legacy_request = {
        name: first[name]
        for name in ("credential_id", "proof_digest", "signals_digest", "fact_ids", "transfer_digest", "context_digest")
    }
    legacy_value = {
        name: value
        for name, value in first.items()
        if name not in ("observation_id", "latency_scope", "evaluation_duration_ns")
    }
    legacy_value["schema_version"] = "clearproof-proof-observation-v1"
    legacy_value["request_digest"] = record_digest(
        "clearproof/observation-request/v1",
        {
            "tenant_id": observer.tenant_id,
            "actor_id": observer.actor_id,
            "idempotency_key": "legacy-observation",
            **legacy_request,
        },
    )
    legacy = ObservationRecord.model_validate_json(json.dumps(legacy_value))

    async def retain_legacy(tx):
        await tx.put("observation", legacy.digest, legacy.model_dump(mode="json"))
        return legacy.report()

    await PilotStore(db, cipher(), observer).run_idempotent(
        "observe-proof", "legacy-observation", legacy_request, retain_legacy
    )
    reports.append(legacy.report())
    assert (
        await observe(key="legacy-observation", now=int(signals[5]) + 1, fact_trust=excluded_trust) == legacy.report()
    )
    mixed = await observation_cohort_report(
        db,
        cipher(),
        observer,
        ObservationCohort(
            cohort_id="mixed",
            cases=(
                ObservationCase(case_id="old", observation_id=legacy.digest),
                ObservationCase(case_id="new", observation_id=first["observation_id"]),
            ),
        ),
    )
    assert mixed["latency_status"] == "partial"
    assert mixed["latency"]["measured_count"] == mixed["latency"]["unmeasured_observed_count"] == 1
    assert mixed["latency"]["total_duration_ns"] == first["evaluation_duration_ns"]
    assert configuration.transfer.originator.wallet not in json.dumps(reports)
    with pytest.raises(ValueError):
        ObservationRecord.model_validate_json(
            json.dumps({k: v for k, v in dict(first, mode="enforcement").items() if k != "observation_id"})
        )
    for references in (cases["DENY"], ()):
        with pytest.raises(RecordConflict):
            await observe(refs=references)
    other_actor = Principal.model_validate({**observer.model_dump(), "actor_id": "another-observer"})
    with pytest.raises(RecordConflict):
        await ProofObservationService(db, cipher(), other_actor, verifier, configuration).observe(
            credential_id, proof, signals, cases["ALLOW"], fact_trust=trust, idempotency_key="observe-allow", now=now
        )
    no_write = Principal.model_validate(
        {**observer.model_dump(), "roles": ("proof:inspect", "policy:read", "evidence:decrypt")}
    )
    with pytest.raises(HTTPException) as denied:
        await ProofObservationService(db, cipher(), no_write, verifier, configuration).observe(
            credential_id, proof, signals, cases["ALLOW"], fact_trust=trust, idempotency_key="forbidden", now=now
        )
    assert denied.value.status_code == 403
    with pytest.raises(RecordConflict):
        async with PilotStore(db, cipher(), observer).transaction() as tx:
            await tx.put("observation", first["observation_id"], {}, expected_revision=1)
    # Even a consumption-authorized actor cannot use an observation as an authorization proof.
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        async with PilotStore(db, cipher(), principal).transaction() as tx:
            await tx.consume(format(int(signals[3]), "064x"), first["observation_id"])
    original_put = PilotTransaction._put

    async def fail_idempotency(tx, kind, *args, **kwargs):
        if kind == "idempotency":
            raise RuntimeError("injected observation transaction failure")
        return await original_put(tx, kind, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(PilotTransaction, "_put", fail_idempotency)
        with pytest.raises(RuntimeError, match="injected observation"):
            await observe(key="observe-rollback")
    with pytest.raises(ValueError):
        await service.observe(
            credential_id,
            proof,
            [str(int(signals[0]) + 1), *signals[1:]],
            cases["ALLOW"],
            fact_trust=trust,
            idempotency_key="observe-wrong-binding",
            now=now,
        )
    await db.close()
    await db.connect()
    # A retry after proof expiry and authority replacement is historical retrieval, not reevaluation.
    assert (
        await observe(refs=tuple(reversed(cases["ALLOW"])), now=int(signals[5]) + 1, fact_trust=excluded_trust) == first
    )
    with pytest.raises(ValueError):
        await observe(key="observe-expired-new-request", now=int(signals[5]) + 1)
    foreign = Principal.model_validate({**observer.model_dump(), "tenant_id": "foreign"})
    for report in reports:
        assert await read_observation(db, cipher(), observer, report["observation_id"]) == report
        assert await read_observation(db, cipher(), foreign, report["observation_id"]) is None
    restricted = Principal.model_validate({**observer.model_dump(), "roles": ("evidence:decrypt",)})
    with pytest.raises(HTTPException):
        await read_observation(db, cipher(), restricted, first["observation_id"])
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == baseline + 14
        rows = await (
            await conn.execute("SELECT row_to_json(r)::text FROM pilot_records r WHERE kind='observation'")
        ).fetchall()
        assert len(rows) == 7
        assert all("observe-allow" not in row[0] and '"outcome"' not in row[0] for row in rows)
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0


async def check_observation_http(app, db, headers, evaluation_body, cases):
    """Real authenticated observation creation, deduplicated retries and retained reads."""
    from httpx import ASGITransport, AsyncClient

    from src.api.main import create_app

    writer_headers = headers(roles=["observations:write", "proof:inspect", "policy:read", "evidence:decrypt"])
    reader_headers = headers(roles=["policy:read", "evidence:decrypt"])
    body = dict(evaluation_body, idempotency_key="http-observe-allow")
    reports = []
    async with db.connection() as conn:
        baseline = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first, repeat = await asyncio.gather(
            *[client.post("/pilot/proof/observe", json=body, headers=writer_headers) for _ in range(2)]
        )
        assert first.status_code == repeat.status_code == 200, first.text
        assert first.json() == repeat.json()
        reports.append(first.json())
        assert first.json()["policy"]["outcome"] == "ALLOW"
        for outcome in ("DENY", "REVIEW", "INDETERMINATE"):
            response = await client.post(
                "/pilot/proof/observe",
                json=dict(body, fact_ids=cases[outcome], idempotency_key="http-observe-" + outcome.lower()),
                headers=writer_headers,
            )
            assert response.status_code == 200, response.text
            assert response.json()["policy"]["outcome"] == outcome
            assert response.json()["mode"] == "observation" and response.json()["authorization_consumed"] is False
            reports.append(response.json())
        assert (await client.post("/pilot/proof/observe", json=body)).status_code == 401
        assert (await client.post("/pilot/proof/observe", json=body, headers=headers())).status_code == 403
        foreign = headers(
            tenant_id="foreign", roles=["observations:write", "proof:inspect", "policy:read", "evidence:decrypt"]
        )
        assert (await client.post("/pilot/proof/observe", json=body, headers=foreign)).status_code == 404
        conflict = await client.post("/pilot/proof/observe", json=dict(body, fact_ids=[]), headers=writer_headers)
        assert conflict.status_code == 409
        for extra in (
            {"mode": "enforcement"},
            {"now": 0},
            {"authorization_consumed": True},
            {"fact_trust": "PRIVATE-MARKER"},
        ):
            rejected = await client.post("/pilot/proof/observe", json={**body, **extra}, headers=writer_headers)
            assert rejected.status_code == 422 and "PRIVATE-MARKER" not in rejected.text
        reference = {"observation_id": reports[0]["observation_id"]}
        assert (await client.post("/pilot/proof/observations/read", json=reference)).status_code == 401
        assert (
            await client.post(
                "/pilot/proof/observations/read", json=reference, headers=headers(roles=["evidence:decrypt"])
            )
        ).status_code == 403
        assert (await client.post("/pilot/proof/observations/read", json=reference, headers=foreign)).status_code == 404
        assert (
            await client.post(
                "/pilot/proof/observations/read", json={"observation_id": "00" * 32}, headers=reader_headers
            )
        ).status_code == 404
        for altered in ({"observation_id": "PRIVATE-MARKER"}, {**reference, "tenant_id": "foreign"}):
            rejected = await client.post("/pilot/proof/observations/read", json=altered, headers=reader_headers)
            assert rejected.status_code == 422 and "PRIVATE-MARKER" not in rejected.text
        assert (
            await client.post("/pilot/proof/observations/read", content=b"x" * 1025, headers=reader_headers)
        ).status_code == 413
    if os.getenv("CLEARPROOF_POLICY_CLI_TEST") == "1":
        await exercise_observation_cli(app, headers, body, reports)
    await db.close()
    await db.connect()
    restarted = create_app()
    restarted.state.db = db
    # No current targets are configured in the replacement app.
    async with AsyncClient(transport=ASGITransport(app=restarted), base_url="http://test") as client:
        assert (await client.post("/pilot/proof/observe", json=body, headers=writer_headers)).status_code == 503
        for report in reports:
            loaded = await client.post(
                "/pilot/proof/observations/read",
                json={"observation_id": report["observation_id"]},
                headers=reader_headers,
            )
            assert loaded.status_code == 200 and loaded.json() == report
    await check_observation_cohort_http(restarted, headers, reports)
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == baseline + 2 * len(
            reports
        )
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0


async def exercise_observation_cli(app, headers, body, reports):
    """Built CLI/SDK validates Python record digests through real authenticated HTTP."""
    import json
    import shutil
    import socket
    from pathlib import Path

    import uvicorn

    node = shutil.which("node")
    cli = Path(__file__).resolve().parents[2] / "packages/cli/dist/index.js"
    assert node and cli.is_file()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", access_log=False, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    roles = ["observations:write", "proof:inspect", "policy:read", "evidence:decrypt"]

    async def invoke(operation, payload, **claims):
        bearer = headers(**{"roles": roles, **claims})["Authorization"].removeprefix("Bearer ")
        process = await asyncio.create_subprocess_exec(
            node,
            str(cli),
            "observation",
            operation,
            "--api-url",
            origin,
            env={"PATH": os.environ.get("PATH", ""), "CLEARPROOF_API_TOKEN": bearer},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(payload).encode()), 30)
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
                    raise AssertionError("API stopped before startup")
                await asyncio.sleep(0.01)
        code, stdout, stderr = await invoke("create", body)
        assert code == 0 and json.loads(stdout) == reports[0], stderr.decode()
        assert stderr == b""
        fresh_body = dict(body, idempotency_key="cli-create-observation", fact_ids=reports[1]["fact_ids"])
        code, stdout, stderr = await invoke("create", fresh_body)
        assert code == 0 and stderr == b"", stderr.decode()
        fresh = json.loads(stdout)
        assert fresh["policy"]["outcome"] == "DENY" and fresh["mode"] == "observation"
        assert fresh["authorization_consumed"] is False
        assert fresh["observation_id"] not in {r["observation_id"] for r in reports}
        code, stdout, stderr = await invoke("create", fresh_body)
        assert code == 0 and json.loads(stdout) == fresh and stderr == b""
        reports.append(fresh)
        for report in reports:
            code, stdout, stderr = await invoke(
                "read", {"observation_id": report["observation_id"]}, roles=["policy:read", "evidence:decrypt"]
            )
            assert code == 0 and json.loads(stdout) == report, stderr.decode()
            assert stderr == b""
        from httpx import AsyncClient

        listed = []
        page_body = {"limit": 3}
        for _ in range(32):
            code, stdout, stderr = await invoke("list", page_body, roles=["policy:read", "evidence:decrypt"])
            assert code == 0 and stderr == b"", stderr.decode()
            page = json.loads(stdout)
            listed.extend(page["observations"])
            if page["next_after"] is None:
                break
            page_body["after"] = page["next_after"]
        else:
            pytest.fail("CLI observation pagination did not terminate")
        assert all(r in listed for r in reports)
        assert len({r["observation_id"] for r in listed}) == len(listed)
        code, stdout, stderr = await invoke("list", {}, tenant_id="foreign")
        assert code == 0 and json.loads(stdout)["observations"] == [] and stderr == b""
        cohort = {
            "cohort_id": "cli-cohort",
            "cases": [
                {"case_id": f"case-{i}", "observation_id": r["observation_id"], "baseline_outcome": "ALLOW"}
                for i, r in enumerate(reports)
            ]
            + [{"case_id": "missing", "observation_id": None}, {"case_id": "unavailable", "observation_id": "00" * 32}],
        }
        async with AsyncClient(base_url=origin) as client:
            expected = await client.post(
                "/pilot/proof/observations/report",
                json=cohort,
                headers=headers(roles=["policy:read", "evidence:decrypt"]),
            )
        assert expected.status_code == 200, expected.text
        code, stdout, stderr = await invoke("report", cohort, roles=["policy:read", "evidence:decrypt"])
        assert code == 0 and json.loads(stdout) == expected.json() and stderr == b"", stderr.decode()
        code, stdout, stderr = await invoke(
            "report", cohort, tenant_id="foreign", roles=["policy:read", "evidence:decrypt"]
        )
        assert code == 0 and json.loads(stdout)["observed_count"] == 0 and stderr == b""
        for operation, payload, claims in [
            ("list", {}, {"roles": ["policy:read"]}),
            ("list", {"after": "PRIVATE-MARKER"}, {}),
            ("report", cohort, {"roles": ["evidence:decrypt"]}),
            ("report", dict(cohort, private="PRIVATE-MARKER"), {}),
            ("create", dict(body, fact_ids=[]), {}),
            ("create", body, {"roles": ["policy:read", "evidence:decrypt"]}),
            ("read", {"observation_id": reports[0]["observation_id"]}, {"tenant_id": "foreign"}),
            ("read", {"observation_id": "PRIVATE-MARKER"}, {}),
        ]:
            code, stdout, stderr = await invoke(operation, payload, **claims)
            assert code == 2 and stdout == b""
            assert b"Observation request failed" in stderr and b"PRIVATE-MARKER" not in stderr
            assert origin.encode() not in stderr
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 10)
        finally:
            sock.close()


async def check_observation_cohort_http(app, headers, reports):
    """Selected-cohort reports from real encrypted observations, without current targets."""
    import json

    from httpx import ASGITransport, AsyncClient

    from src.services.observation_report import ObservationCohort

    cases = [
        dict(
            case_id=f"case-{index}",
            observation_id=report["observation_id"],
            baseline_outcome=["ALLOW", "ALLOW", None, "INDETERMINATE"][index],
        )
        for index, report in enumerate(reports[:4])
    ]
    cases += [
        dict(case_id="not-observed", observation_id=None, baseline_outcome="ALLOW"),
        dict(case_id="unavailable", observation_id="00" * 32, baseline_outcome="DENY"),
    ]
    body = dict(cohort_id="synthetic-cohort", cases=cases)
    reader = headers(roles=["policy:read", "evidence:decrypt"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        path = "/pilot/proof/observations/list"
        first = await client.post(path, json={"limit": 2}, headers=reader)
        assert first.status_code == 200, first.text
        page = first.json()
        assert page["scope"] == "live-retained-tenant-observations"
        assert page["order"] == "observation-id-ascending" and page["after"] is None
        discovered = []
        for _ in range(64):
            discovered.extend(page["observations"])
            if page["next_after"] is None:
                break
            assert page["next_after"] == page["observations"][-1]["observation_id"]
            following = await client.post(path, json={"limit": 2, "after": page["next_after"]}, headers=reader)
            assert following.status_code == 200, following.text
            page = following.json()
        else:
            pytest.fail("Observation pagination did not terminate")
        ids = [item["observation_id"] for item in discovered]
        assert ids == sorted(set(ids))
        assert all(item in discovered for item in reports)
        assert {item["schema_version"] for item in discovered} == {
            "clearproof-proof-observation-v1",
            "clearproof-proof-observation-v2",
        }
        complete = await client.post(path, json={"limit": 64}, headers=reader)
        assert complete.json()["observations"] == discovered and complete.json()["next_after"] is None
        assert (await client.post(path, json={"limit": 2}, headers=reader)).json() == first.json()
        end = await client.post(path, json={"after": "ff" * 32}, headers=reader)
        assert end.json()["observations"] == [] and end.json()["next_after"] is None
        foreign_page = await client.post(
            path,
            json={"after": ids[0]},
            headers=headers(tenant_id="foreign", roles=["policy:read", "evidence:decrypt"]),
        )
        assert foreign_page.status_code == 200 and foreign_page.json()["observations"] == []
        assert (await client.post(path, json={})).status_code == 401
        for roles in (["policy:read"], ["evidence:decrypt"], ["usage:read"]):
            assert (await client.post(path, json={}, headers=headers(roles=roles))).status_code == 403
        for bad in (
            {"limit": 0},
            {"limit": 65},
            {"limit": True},
            {"after": "PRIVATE-MARKER"},
            {"tenant_id": "foreign"},
            {"limit": "2"},
        ):
            rejected = await client.post(path, json=bad, headers=reader)
            assert rejected.status_code == 422 and "PRIVATE-MARKER" not in rejected.text
        assert (await client.post(path + "?tenant_id=foreign", json={}, headers=reader)).status_code == 422
        assert (await client.post(path, content=b"x" * 1025, headers=reader)).status_code == 413
        result = await client.post("/pilot/proof/observations/report", json=body, headers=reader)
        assert result.status_code == 200, result.text
        report = result.json()
        assert report["cohort_digest"] == ObservationCohort.model_validate_json(json.dumps(body)).digest
        assert report["case_count"] == 6 and report["observed_count"] == 4 and report["missing_count"] == 2
        assert report["distinct_observed_transfers"] == 1 and report["policy_count"] == 4
        assert report["determinate_count"] == 3 and report["failed_pairing_count"] == 0
        assert report["latency_status"] == "partial"
        assert report["latency"]["measured_count"] == 4 and report["latency"]["unmeasured_case_count"] == 2
        assert report["latency"]["unmeasured_observed_count"] == 0
        assert report["latency"]["total_duration_ns"] == sum(r["evaluation_duration_ns"] for r in reports[:4])
        assert report["outcome_counts"] == {"ALLOW": 1, "DENY": 1, "REVIEW": 1, "INDETERMINATE": 1}
        assert report["baseline_label_count"] == 5 and report["comparable_count"] == 3
        assert report["agreement_count"] == 2 and report["disagreement_count"] == 1
        retain_output("observation-cohort.json", report)
        retain_output("observations.json", reports[:4])
        assert (
            await client.post(
                "/pilot/proof/observations/report", json=dict(body, cases=list(reversed(cases))), headers=reader
            )
        ).json() == report
        assert (await client.post("/pilot/proof/observations/report", json=body)).status_code == 401
        assert (
            await client.post(
                "/pilot/proof/observations/report", json=body, headers=headers(roles=["evidence:decrypt"])
            )
        ).status_code == 403
        foreign = await client.post(
            "/pilot/proof/observations/report",
            json=body,
            headers=headers(tenant_id="foreign", roles=["policy:read", "evidence:decrypt"]),
        )
        assert foreign.status_code == 200 and foreign.json()["observed_count"] == 0
        assert foreign.json()["missing_count"] == 6 and foreign.json()["comparable_count"] == 0
        for altered in [
            dict(body, cases=cases + [cases[0]]),
            dict(body, tenant_id="foreign"),
            dict(body, cases=[dict(cases[0], baseline_outcome="PRIVATE-MARKER")]),
        ]:
            rejected = await client.post("/pilot/proof/observations/report", json=altered, headers=reader)
            assert rejected.status_code == 422 and "PRIVATE-MARKER" not in rejected.text
        assert (
            await client.post("/pilot/proof/observations/report", content=b"x" * 16385, headers=reader)
        ).status_code == 413


async def test_usage_inventory_scope_idempotency_and_read_only_api(db, monkeypatch):
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from httpx import ASGITransport, AsyncClient

    from src.api.main import create_app
    from src.api.middleware import auth
    from src.services.usage import usage_inventory

    usage_reader = Principal(tenant_id="tenant-a", actor_id="usage-reader", roles=("usage:read",))
    empty = await usage_inventory(db, usage_reader, now=1000)
    assert all(value == 0 for value in empty.counters.model_dump().values())
    assert empty.billing_status == "not-an-invoice"
    writer = store(db)

    async def event(tx):
        await tx.put("event", "event-one", {"synthetic": True})
        return {"event_id": "event-one"}

    requests = await asyncio.gather(
        *[writer.run_idempotent("ingest-event", "same-delivery", {"event_id": "event-one"}, event) for _ in range(2)]
    )
    assert requests[0] == requests[1]
    own = await usage_inventory(db, usage_reader, now=1001)
    assert own.counters.encrypted_records == 2 and own.counters.retained_events == 1
    assert own.counters.ciphertext_bytes > 0 and own.counters.consumed_nullifiers == 0
    assert own.counters.retained_observations == own.counters.retained_proofs == own.counters.retained_receipts == 0
    with pytest.raises(RecordConflict):
        await writer.run_idempotent("ingest-event", "same-delivery", {"event_id": "different"}, event)
    async with store(db, tenant="foreign").transaction() as tx:
        await tx.put("event", "foreign-event", {"marker": "PRIVATE-MARKER"})
    await db.close()
    await db.connect()
    assert (await usage_inventory(db, usage_reader, now=1002)).counters == own.counters
    no_scope = Principal(tenant_id="tenant-a", actor_id="reader", roles=("evidence:decrypt", "policy:read"))
    with pytest.raises(HTTPException):
        await usage_inventory(db, no_scope, now=1002)

    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    monkeypatch.setattr(
        auth,
        "JWT_PUBLIC_KEY",
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    now = int(time.time())
    claims = dict(
        iss=auth.JWT_ISSUER,
        aud=auth.JWT_AUDIENCE,
        sub="operator",
        iat=now,
        exp=now + 300,
        tenant_id="tenant-a",
        actor_id="usage-reader",
        roles=["usage:read"],
    )

    def headers(**changes):
        return {"Authorization": "Bearer " + jwt.encode({**claims, **changes}, key, algorithm="ES256")}

    app = create_app()
    app.state.db = db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        result = await client.get("/pilot/usage", headers=headers())
        assert result.status_code == 200, result.text
        assert result.json()["counters"] == own.counters.model_dump(mode="json")
        assert result.json()["tenant_id"] == "tenant-a" and result.json()["billing_status"] == "not-an-invoice"
        assert "PRIVATE-MARKER" not in result.text and "key_id" not in result.text
        assert (await client.get("/pilot/usage")).status_code == 401
        assert (await client.get("/pilot/usage", headers=headers(roles=["policy:read"]))).status_code == 403
        assert (await client.get("/pilot/usage?tenant_id=foreign", headers=headers())).status_code == 422
        foreign = await client.get("/pilot/usage", headers=headers(tenant_id="foreign"))
        assert foreign.status_code == 200 and foreign.json()["counters"]["retained_events"] == 1
        assert foreign.json()["counters"]["encrypted_records"] == 1
        app.state.db = None
        assert (await client.get("/pilot/usage", headers=headers())).status_code == 503
    assert (await usage_inventory(db, usage_reader, now=1003)).counters == own.counters


async def prepare_authorization_http(
    db,
    monkeypatch,
    principal,
    configuration,
    verifier,
    proof,
    signals,
    credential_id,
    refs,
    fact_trust,
    payload_args,
    now,
):
    """Exercise request/trust rejection; return an actual JWT HTTP client for consumption races."""
    import json
    import time
    from dataclasses import replace

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from httpx import ASGITransport, AsyncClient

    from src.api.main import create_app
    from src.api.middleware import auth
    from src.api.routes import authorization
    from src.api.routes.authorization import AuthorizationTarget
    from src.services.authorization_input import SealedAuthorizationInformation

    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    monkeypatch.setattr(
        auth,
        "JWT_PUBLIC_KEY",
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )
    monkeypatch.setenv("PII_MASTER_KEY", (b"a" * 32).hex())
    monkeypatch.setattr(authorization, "inspection_time", lambda: now)
    roles = ["proof:consume", "proof:generate", "proof:inspect", "policy:read", "evidence:decrypt"]

    def headers(**changes):
        claims = dict(
            iss=auth.JWT_ISSUER,
            aud=auth.JWT_AUDIENCE,
            sub=principal.actor_id,
            actor_id=principal.actor_id,
            iat=int(time.time()),
            tenant_id=principal.tenant_id,
            roles=roles,
            exp=int(time.time()) + 600,
        )
        return {"Authorization": "Bearer " + jwt.encode({**claims, **changes}, key, algorithm="ES256")}

    sealed = SealedAuthorizationInformation.seal(
        cipher(),
        tenant_id=principal.tenant_id,
        target_id="local-transfer",
        pii=payload_args["pii"],
        approval=payload_args["information_approval"],
    )
    assert payload_args["pii"] not in sealed.row["ciphertext"]
    assert "payload" not in repr(sealed) and "approval" not in repr(sealed)
    target = AuthorizationTarget(
        configuration=configuration,
        verifier=verifier,
        fact_trust=fact_trust,
        information=sealed,
        information_trust=payload_args["information_trust"],
        decision_signer=payload_args["decision_signer"],
        recipient_trust=payload_args["recipient_trust"],
        recipient_key_id=payload_args["recipient_key_id"],
    )
    app = create_app()
    app.state.db = db
    targets = {(principal.tenant_id, "local-transfer"): target}
    app.state.pilot_authorization_targets = targets
    body = dict(
        target_id="local-transfer",
        credential_id=credential_id,
        proof_json=proof.decode(),
        public_signals=signals,
        fact_ids=list(refs),
        idempotency_key="consume-once",
    )
    path = "/pilot/proof/authorize"

    async def invoke(changes=None, claims=None, *, authenticated=True):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            return await client.post(
                path, json={**body, **(changes or {})}, headers=headers(**(claims or {})) if authenticated else {}
            )

    async with db.connection() as conn:
        before = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
    assert (await invoke(authenticated=False)).status_code == 401
    for missing in roles:
        assert (await invoke(claims={"roles": [r for r in roles if r != missing]})).status_code == 403
    assert (await invoke(claims={"tenant_id": "foreign"})).status_code == 404
    assert (await invoke({"target_id": "missing"})).status_code == 404
    assert (await invoke({"credential_id": "missing"})).status_code == 422  # Signed information binds credential.
    for changes in (
        {"now": now},
        {"recipient_key_id": "PRIVATE-MARKER"},
        {"pii": "PRIVATE-MARKER"},
        {"decision_signer": "PRIVATE-MARKER"},
        {"mode": "observation"},
        {"public_signals": signals + ["0"]},
        {"proof_json": "PRIVATE-MARKER"},
    ):
        rejected = await invoke(changes)
        assert rejected.status_code == 422 and "PRIVATE-MARKER" not in rejected.text
    assert (await invoke({"fact_ids": []})).status_code == 422
    changed_proof = json.loads(proof)
    changed_proof["pi_c"][0] = str(int(changed_proof["pi_c"][0]) + 1)
    assert (await invoke({"proof_json": json.dumps(changed_proof)})).status_code == 422
    # Sealed inputs bind both tenant and target name; neither can be relabeled.
    targets[(principal.tenant_id, "renamed-target")] = target
    assert (await invoke({"target_id": "renamed-target"})).status_code == 503
    targets[(principal.tenant_id, "local-transfer")] = replace(target, fact_trust=None)
    assert (await invoke()).status_code == 503
    targets[(principal.tenant_id, "local-transfer")] = replace(
        target,
        information=SealedAuthorizationInformation({**sealed.row, "ciphertext": b"x" * len(sealed.row["ciphertext"])}),
    )
    assert (await invoke()).status_code == 503
    targets[(principal.tenant_id, "local-transfer")] = target
    app.state.pilot_authorization_targets = None
    assert (await invoke()).status_code == 503
    app.state.pilot_authorization_targets = targets
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        duplicate = json.dumps(body)[:-1] + ',"idempotency_key":"other"}'
        assert (await client.post(path, content=duplicate, headers=headers())).status_code == 422
        assert (await client.post(path, content=b"x" * 16385, headers=headers())).status_code == 413
        assert (await client.post(path + "?tenant_id=foreign", json=body, headers=headers())).status_code == 422
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == before
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
    return invoke, app, headers, body


async def exercise_authorization_cli(app, headers, body, receipt):
    """Built SDK checks the API's exact historical receipt; failures never imply rollback."""
    import json
    import shutil
    import socket
    from pathlib import Path

    import uvicorn

    node = shutil.which("node")
    cli = Path(__file__).resolve().parents[2] / "packages/cli/dist/index.js"
    assert node and cli.is_file()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", access_log=False, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def invoke(payload, **claims):
        process = await asyncio.create_subprocess_exec(
            node,
            str(cli),
            "authorize-current",
            "--api-url",
            origin,
            env={
                "PATH": os.environ.get("PATH", ""),
                "CLEARPROOF_API_TOKEN": headers(**claims)["Authorization"].removeprefix("Bearer "),
            },
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(payload).encode()), 30)
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
                    raise AssertionError("Authorization API stopped before startup")
                await asyncio.sleep(0.01)
        for _ in range(2):
            code, stdout, stderr = await invoke(body)
            assert code == 0 and stderr == b"", stderr.decode()
            result = json.loads(stdout)
            assert result["receipt"] == receipt
            assert result["scope"] == "recorded-local-authorization"
            assert result["receipt"]["execution"] == "not-requested"
        for altered, claims in [
            (dict(body, idempotency_key="cli-another-spend"), {}),
            (dict(body, fact_ids=[]), {}),
            (dict(body, pii="PRIVATE-MARKER"), {}),
            (body, {"roles": ["proof:inspect", "evidence:decrypt"]}),
            (body, {"tenant_id": "foreign"}),
        ]:
            code, stdout, stderr = await invoke(altered, **claims)
            assert code == 2 and stdout == b""
            assert b"retry only the same request and idempotency key" in stderr
            assert b"PRIVATE-MARKER" not in stderr and origin.encode() not in stderr
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 10)
        finally:
            sock.close()


async def check_authorization_mirror(
    db, principal, configuration, verifier, receipt, fact_trust, decision_authority, payload, now, *, mirror_evm=None
):
    import json

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.protocol.decision_attestation import DecisionAuthority, DecisionTrustStore
    from src.services.authorization_mirror import AuthorizationMirrorService

    exporter = Principal.model_validate({**principal.model_dump(), "roles": (*principal.roles, "evidence:export")})
    consumer = mirror_evm.consumer.lower() if mirror_evm else "0x" + "ab" * 20
    service = AuthorizationMirrorService(db, cipher(), exporter, verifier, configuration, consumer=consumer)
    arguments = dict(
        pii=payload["pii"],
        fact_trust=fact_trust,
        decision_trust=DecisionTrustStore([decision_authority]),
        information_trust=payload["information_trust"],
        recipient_trust=payload["recipient_trust"],
        now=now,
    )
    async with db.connection() as conn:
        before = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
    plan = await service.prepare(receipt["receipt_id"], **arguments)
    assert plan["consumption_owner"] == "postgresql" and plan["contract_effect"] == "audit-mirror-only"
    assert plan["publication_state"] == "not-published" and plan["assurance"] == "development-unapproved"
    assert plan["receipt_id"] == receipt["receipt_id"] and plan["nullifier"] == receipt["nullifier"]
    assert plan["consumer"] == consumer and plan["context_digest"] == configuration.context.digest
    assert len(plan["heads"]) == 8 and [h["kind"] for h in plan["heads"]] == list(range(8))
    assert plan["heads"][7]["digest"] == receipt["receipt_id"]
    assert plan["heads"][7]["scope"] == plan["context_digest"] and plan["heads"][7]["value"] == "1"
    assert plan["public_signals"][0] == str(int(plan["public_signals"][0]))
    assert all(h["valid_from"] <= now < h["valid_until"] for h in plan["heads"])
    from src.policy.fact_approval import FactTrustStore

    short_trust = FactTrustStore(
        [a.model_copy(update={"max_observation_age_seconds": 1}) for a in fact_trust._authorities]
    )
    bounded = await service.prepare(receipt["receipt_id"], **{**arguments, "fact_trust": short_trust})
    assert bounded["heads"][6]["valid_until"] == now + 2
    assert bounded["publish_before"] == now + 2
    with pytest.raises(ValueError):
        await service.prepare(receipt["receipt_id"], **{**arguments, "fact_trust": short_trust, "now": now + 2})
    serialized = json.dumps(plan)
    assert "Synthetic José Originator" not in serialized and "Synthetic Recipient Ltd" not in serialized
    assert "payload_digest" not in serialized and "payload_base64" not in serialized and "signature" not in serialized
    assert await service.prepare(receipt["receipt_id"], **arguments) == plan
    await db.close()
    await db.connect()
    assert await service.prepare(receipt["receipt_id"], **arguments) == plan
    for identity, changes in [
        ("00" * 32, {}),
        (receipt["receipt_id"], {"pii": b"{}"}),
        (receipt["receipt_id"], {"now": receipt["expires_at"]}),
    ]:
        with pytest.raises(ValueError):
            await service.prepare(identity, **{**arguments, **changes})
    wrong_authority = DecisionAuthority.model_validate(
        {
            **decision_authority.model_dump(),
            "public_key": Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
        }
    )
    with pytest.raises(ValueError):
        await service.prepare(
            receipt["receipt_id"], **{**arguments, "decision_trust": DecisionTrustStore([wrong_authority])}
        )
    restricted = AuthorizationMirrorService(db, cipher(), principal, verifier, configuration, consumer=consumer)
    with pytest.raises(HTTPException):
        await restricted.prepare(receipt["receipt_id"], **arguments)
    await check_authorization_mirror_rejections(service, arguments, receipt, payload["decision_signer"])
    if mirror_evm:
        import time

        current = max(int(time.time()), (await mirror_evm.web3.eth.get_block("latest"))["timestamp"])
        current_plan = await service.prepare(receipt["receipt_id"], **{**arguments, "now": current})
        from src.protocol.canonical import record_digest
        from src.storage.publication_journal import PublicationJournal

        async def revalidate(binding):
            reviewed = max(int(time.time()), (await mirror_evm.web3.eth.get_block("latest"))["timestamp"])
            assert reviewed < binding.expires_at
            refreshed = await service.prepare(receipt["receipt_id"], **{**arguments, "now": reviewed})
            assert (
                record_digest("clearproof/mirror-plan/v1", {k: v for k, v in refreshed.items() if k != "prepared_at"})
                == binding.plan_digest
            )

        journal = PublicationJournal(db, cipher(), exporter)
        assert await mirror_evm.check(current_plan, journal, revalidate) == receipt["receipt_id"]
    # A signed receipt is insufficient if its actual authoritative consumption is absent.
    async with db.connection() as conn:
        await conn.execute(
            "DELETE FROM pilot_consumptions WHERE tenant_id=%s AND nullifier=%s",
            (principal.tenant_id, receipt["nullifier"]),
        )
    try:
        with pytest.raises(ValueError, match="consumption"):
            await service.prepare(receipt["receipt_id"], **arguments)
    finally:
        async with db.connection() as conn:
            await conn.execute(
                "INSERT INTO pilot_consumptions (tenant_id,nullifier,proof_id) VALUES (%s,%s,%s)",
                (principal.tenant_id, receipt["nullifier"], receipt["proof_id"]),
            )
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == before
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 1


def check_bilateral_scenarios(record, receipt, configuration, decision_authority, payload, private, now, tmp_path):
    import copy
    import json

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from src.protocol.bridges.pilot_bilateral import LocalBilateralCounterparty
    from src.protocol.bridges.trp_bridge import TRPBridge
    from src.protocol.decision_attestation import DecisionTrustStore
    from src.sar.pilot_envelope import RecipientTrustStore

    request = TRPBridge.build_pilot_request(record, receipt)
    assert payload["pii"].decode() not in json.dumps(request)
    configuration_args = dict(
        transfer=configuration.transfer,
        context=configuration.context,
        decision_trust=DecisionTrustStore([decision_authority]),
        information_trust=payload["information_trust"],
        recipient_trust=payload["recipient_trust"],
        private_keys={receipt["recipient_key_id"]: private},
    )
    receiver = LocalBilateralCounterparty(**configuration_args)
    for behavior, outcome in (
        ("accept", "accepted"),
        ("reject", "rejected"),
        ("request-information", "information-requested"),
    ):
        result = receiver.receive(request, now=now, behavior=behavior)
        assert result["outcome"] == outcome and result["source_authenticity"] == "local-simulator"
        assert result["authorization"] == "not-created" and result["execution"] == "not-requested"
        assert receiver.receive(copy.deepcopy(request), now=now, behavior=behavior) == result
        assert payload["pii"].decode() not in json.dumps(result)
    assert receiver.receive(request, now=now, behavior="timeout", deadline=now + 1)["outcome"] == "pending"
    assert receiver.receive(request, now=now + 1, behavior="timeout", deadline=now + 1)["outcome"] == "timeout"
    unsupported = {**request, "profile": "unsupported-pilot-v99"}
    assert receiver.receive(unsupported, now=now)["outcome"] == "unsupported-version"
    authority = payload["recipient_trust"].select(
        receipt["recipient_key_id"], configuration.transfer, configuration.context, now=now
    )
    new_private = X25519PrivateKey.from_private_bytes(bytes([33]) * 32)
    successor = authority.model_copy(update={"public_key": new_private.public_key().public_bytes_raw().hex()})
    overlap = LocalBilateralCounterparty(
        **{
            **configuration_args,
            "recipient_trust": RecipientTrustStore([authority, successor]),
            "private_keys": {authority.key_id: private, successor.key_id: new_private.private_bytes_raw()},
        }
    )
    assert overlap.receive(request, now=now)["outcome"] == "accepted"
    retired = LocalBilateralCounterparty(
        **{
            **configuration_args,
            "recipient_trust": RecipientTrustStore([successor]),
            "private_keys": {successor.key_id: new_private.private_bytes_raw()},
        }
    )
    with pytest.raises(ValueError):
        retired.receive(request, now=now)
    if os.getenv("CLEARPROOF_POLICY_CLI_TEST") == "1":
        check_bilateral_cli(request, configuration_args, authority, successor, new_private, now, tmp_path)
    for field in ("envelope", "authorization_request", "decision", "information_approval"):
        changed = copy.deepcopy(request)
        changed[field] = {}
        with pytest.raises(ValueError, match="Invalid local bilateral"):
            receiver.receive(changed, now=now)
    with pytest.raises(ValueError):
        receiver.receive(request, now=receipt["expires_at"])
    with pytest.raises(ValueError):
        LocalBilateralCounterparty(**{**configuration_args, "private_keys": {}}).receive(request, now=now)


async def check_durable_local_exchange(
    db, principal, configuration, receipt, decision_authority, payload, private, now
):
    from src.protocol.bridges.pilot_bilateral import LocalBilateralCounterparty
    from src.protocol.decision_attestation import DecisionTrustStore
    from src.reconciliation.events import SourceEvent, reconcile
    from src.services.event_ingestion import EventAuthority, EventIngestionService
    from src.services.local_exchange import ExchangeDelivery, LocalExchangeService

    reviewer = Principal.model_validate({**principal.model_dump(), "roles": (*principal.roles, "evidence:read")})
    authority = EventAuthority(
        tenant_id=principal.tenant_id,
        chain_id=configuration.context.deployment_chain_id,
        registry_address=configuration.context.deployment_address,
        source_id="local-bilateral",
        actors=(principal.actor_id,),
        dimensions=("counterparty",),
        valid_from=now - 1,
        valid_until=now + 100,
    )
    custody_authority = authority.model_copy(update={"source_id": "custody-simulator", "dimensions": ("custody",)})
    events = EventIngestionService(db, cipher(), reviewer, authorities=(authority, custody_authority))
    args = dict(
        transfer=configuration.transfer,
        context=configuration.context,
        decision_trust=DecisionTrustStore([decision_authority]),
        information_trust=payload["information_trust"],
        recipient_trust=payload["recipient_trust"],
        private_keys={receipt["recipient_key_id"]: private},
    )
    counterparty = LocalBilateralCounterparty(**args)
    accepted = LocalExchangeService(events, counterparty, source_id="local-bilateral")
    requested = LocalExchangeService(events, counterparty, source_id="local-bilateral", behavior="request-information")
    first = ExchangeDelivery(
        receipt_id=receipt["receipt_id"], delivery_id="information-first", source_sequence=1, observed_at=now
    )
    second = ExchangeDelivery(
        receipt_id=receipt["receipt_id"], delivery_id="accepted-second", source_sequence=2, observed_at=now + 1
    )
    async with db.connection() as conn:
        before = (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0]
    replies = await asyncio.gather(accepted.deliver(second, now=now + 2), accepted.deliver(second, now=now + 2))
    assert replies[0] == replies[1] and replies[0]["result"]["outcome"] == "accepted"
    earlier = await requested.deliver(first, now=now + 3)
    assert earlier["result"]["outcome"] == "information-requested"
    report = await events.investigate(accepted.scope, now=now + 4)
    assert report.states["counterparty"] == "accepted"
    assert [e.source_sequence for e in report.timeline] == [1, 2]
    assert [e.ingested_at for e in report.timeline] == [now + 3, now + 2]
    assert reconcile(accepted.scope, tuple(reversed(report.timeline)) + report.timeline, now=now + 4) == report
    await db.close()
    await db.connect()
    assert await events.investigate(accepted.scope, now=now + 4) == report
    assert await accepted.deliver(second, now=now + 5) == replies[0]
    with pytest.raises(RecordConflict):
        await requested.deliver(second, now=now + 5)
    denied = LocalExchangeService(
        events, LocalBilateralCounterparty(**{**args, "private_keys": {}}), source_id="local-bilateral"
    )
    with pytest.raises(ValueError):
        await denied.deliver(
            second.model_copy(update={"delivery_id": "unavailable-key", "source_sequence": 3}), now=now + 5
        )
    # An exact retry remains a historical recorded result after recipient-key retirement.
    assert await denied.deliver(second, now=now + 5) == replies[0]
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_records")).fetchone())[0] == before + 6
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 1
    for sequence, state in ((2, "completed"), (1, "submitted"), (2, "completed")):
        event = SourceEvent(
            scope=accepted.scope,
            source_id="custody-simulator",
            source_event_id=f"custody-{sequence}",
            source_sequence=sequence,
            dimension="custody",
            state=state,
            occurred_at=now + sequence,
            evidence_digest="ab" * 32,
        )
        await events.ingest(event, now=now + 6)
    combined = await events.investigate(accepted.scope, now=now + 7)
    assert combined.states["counterparty"] == "accepted" and combined.states["custody"] == "completed"
    assert "custody-completed-without-finality" in {f.reason for f in combined.findings}
    assert len(combined.timeline) == 4
    retain_output("investigation.json", combined.model_dump(mode="json"))
    async with db.connection() as conn:
        local_event = await events.store.get("event", replies[0]["event_id"])
        evidence = await events.store.get("provider-evidence", local_event["evidence_records"][0])
        assert evidence["result"]["source_authenticity"] == "local-simulator"
        assert evidence["receipt_id"] == receipt["receipt_id"]
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 1


def check_bilateral_cli(request, args, authority, successor, new_private, now, tmp_path):
    """Built CLI consumes the actual encrypted authorization, with separate recipient configuration."""
    import json
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    node = shutil.which("node")
    cli = Path(__file__).resolve().parents[2] / "packages/cli/dist/index.js"
    assert node and cli.is_file()
    config = dict(
        schema_version="clearproof-local-counterparty-configuration-v1",
        transfer=args["transfer"].model_dump(mode="json"),
        context=args["context"].model_dump(mode="json"),
        decisions=[a.model_dump(mode="json") for a in args["decision_trust"]._keys.values()],
        information=[a.model_dump(mode="json") for a in args["information_trust"]._keys.values()],
        recipients=[authority.model_dump(mode="json")],
    )
    keys = {key: value.hex() for key, value in args["private_keys"].items()}
    request_path, trust_path = tmp_path / "bilateral-request.json", tmp_path / "counterparty-trust.json"

    dispositions = []

    def invoke(message=request, trust=config, secret_keys=keys, behavior="accept", clock=now, deadline=None):
        request_path.write_text(json.dumps(message))
        trust_path.write_text(json.dumps(trust))
        command = [
            node,
            str(cli),
            "counterparty",
            "--python",
            sys.executable,
            "--request",
            str(request_path),
            "--trust",
            str(trust_path),
            "--observed-at",
            str(clock),
            "--behavior",
            behavior,
        ]
        if deadline is not None:
            command += ["--deadline", str(deadline)]
        result = subprocess.run(
            command, input=json.dumps({"keys": secret_keys}), text=True, capture_output=True, timeout=30
        )
        assert not result.stderr, result.stderr
        assert all(key not in result.stdout for key in secret_keys.values())
        report = json.loads(result.stdout)
        dispositions.append(
            {"behavior": behavior, "observed_at": clock, "exit_code": result.returncode, "result": report}
        )
        return result.returncode, report

    for behavior, outcome in (
        ("accept", "accepted"),
        ("reject", "rejected"),
        ("request-information", "information-requested"),
    ):
        code, report = invoke(behavior=behavior)
        assert code == 0 and report["outcome"] == outcome
        assert report["source_authenticity"] == "local-simulator"
        assert report["authorization"] == "not-created" and report["execution"] == "not-requested"
    assert invoke(behavior="timeout", deadline=now + 1)[1]["outcome"] == "pending"
    assert invoke(behavior="timeout", deadline=now + 1, clock=now + 1)[1]["outcome"] == "timeout"
    assert invoke(message={**request, "profile": "unsupported-pilot-v99"})[1]["outcome"] == "unsupported-version"
    overlap = {**config, "recipients": [authority.model_dump(mode="json"), successor.model_dump(mode="json")]}
    rotated = {**keys, successor.key_id: new_private.private_bytes_raw().hex()}
    assert invoke(trust=overlap, secret_keys=rotated)[1]["outcome"] == "accepted"
    retired = {**config, "recipients": [successor.model_dump(mode="json")]}
    assert invoke(trust=retired, secret_keys={successor.key_id: rotated[successor.key_id]})[0] == 2
    for changed in (
        {"secret_keys": {}},
        {"clock": request["receipt"]["expires_at"]},
        {"message": {**request, "envelope": {"private": "PRIVATE-MARKER"}}},
        {"trust": {**config, "extra": "PRIVATE-MARKER"}},
    ):
        code, report = invoke(**changed)
        assert code == 2 and report["outcome"] == "invalid-input"
        assert "PRIVATE-MARKER" not in json.dumps(report)

    retain_output("counterparty-scenarios.json", dispositions)


@pytest.mark.parametrize("record_id", [None, 1, "", "UPPER", "../record", "a" * 65])
async def test_storage_rejects_noncanonical_identifiers(db, record_id):
    with pytest.raises(ValueError, match="Expected opaque record identifier"):
        await store(db).read("proof", record_id)


async def test_storage_rejects_unknown_kind_and_operation_before_callback(db):
    target = store(db)
    with pytest.raises(ValueError, match="Unsupported pilot record kind"):
        await target.read("unknown-kind", "synthetic-id")

    async def unexpected(tx):
        pytest.fail("Unsupported operation must not invoke its callback")

    with pytest.raises(ValueError, match="Unsupported pilot operation"):
        await target.run_idempotent("unknown-operation", "synthetic-key", {}, unexpected)
    async with target.transaction() as tx:
        assert await tx.record_ids("proof") == []


@pytest.mark.parametrize("result", [None, [], True])
async def test_nonobject_idempotent_result_rolls_back_and_allows_retry(db, result):
    target = store(db)

    async def invalid(tx):
        await tx.put("proof", "synthetic-proof", {"fixture": "synthetic"})
        await tx.consume("a" * 64, "synthetic-proof")
        return result

    with pytest.raises(ValueError, match="Idempotent operation result must be an object"):
        await target.run_idempotent("consume-proof", "synthetic-key", {}, invalid)
    assert await target.get("proof", "synthetic-proof") is None
    async with target.transaction() as tx:
        assert not await tx.is_consumed("a" * 64)

    async def retry(tx):
        await tx.put("proof", "synthetic-proof", {"fixture": "synthetic"})
        await tx.consume("a" * 64, "synthetic-proof")
        return {"accepted": True}

    assert await target.run_idempotent("consume-proof", "synthetic-key", {}, retry) == {"accepted": True}


@pytest.mark.parametrize("revision", [True, "1", 0, -1, 2**53])
async def test_storage_read_revision_rejects_invalid_safe_integer(db, revision):
    with pytest.raises(ValueError, match="Revision must be a positive safe integer"):
        await store(db).read("proof", "synthetic-proof", revision=revision)


@pytest.mark.parametrize("revision", [True, "1", 0, -1, 2**53 - 1])
async def test_storage_write_revision_rejects_invalid_successor_without_mutation(db, revision):
    target = store(db)
    async with target.transaction() as tx:
        await tx.put("issuance-root", "synthetic-root", {"root": "original"})
    with pytest.raises(ValueError, match="Expected revision must allow a positive safe-integer successor"):
        async with target.transaction() as tx:
            await tx.put("issuance-root", "synthetic-root", {"root": "replacement"}, expected_revision=revision)
    snapshot = await target.read("issuance-root", "synthetic-root")
    assert snapshot.revision == 1 and snapshot.value == {"root": "original"}


@pytest.mark.parametrize("limit", [True, "1", 0, 257])
async def test_storage_record_scan_rejects_invalid_limits(db, limit):
    async with store(db).transaction() as tx:
        with pytest.raises(ValueError, match="Scan limit must be"):
            await tx.record_ids("event", limit=limit)


@pytest.mark.parametrize("limit", [True, "1", 0, 17])
async def test_storage_event_scope_scan_rejects_invalid_limits(db, limit):
    async with store(db).transaction() as tx:
        with pytest.raises(ValueError, match="Invalid scope page limit"):
            await tx.event_scopes(after=None, limit=limit)


@pytest.mark.parametrize("sequence", [True, "1", 0, -1, 2**53])
async def test_storage_event_index_rejects_invalid_sequences(db, sequence):
    target = store(db)
    with pytest.raises(ValueError, match="Invalid source sequence"):
        async with target.transaction() as tx:
            await tx.put("event", "a" * 64, {"fixture": "synthetic"})
            await tx.index_event("a" * 64, "b" * 64, "c" * 64, sequence)
    assert await target.get("event", "a" * 64) is None
    async with target.transaction() as tx:
        assert await tx.event_ids("b" * 64) == []


@pytest.mark.parametrize("nullifier", [None, 1, "", "a" * 63, "a" * 65, "A" * 64, "g" * 64])
async def test_storage_rejects_noncanonical_consumption_nullifiers(db, nullifier):
    async with store(db).transaction() as tx:
        with pytest.raises(ValueError, match="Expected canonical 32-byte nullifier"):
            await tx.consume(nullifier, "synthetic-proof")
        with pytest.raises(ValueError, match="Expected canonical 32-byte nullifier"):
            await tx.consumed_proof_id(nullifier)
        assert not await tx.is_consumed("a" * 64)


async def test_storage_event_capacity_rejects_overflow_without_truncating(db):
    target = store(db)
    scope, stream = "b" * 64, "c" * 64
    async with target.transaction() as tx:
        for sequence in range(1, 257):
            record_id = f"{sequence:064x}"
            await tx.put("event", record_id, {"fixture": "synthetic"})
            await tx.index_event(record_id, scope, stream, sequence)
        expected = [f"{sequence:064x}" for sequence in range(1, 257)]
        assert await tx.event_ids(scope) == expected
    # The low-level index admits a 257th retained record. Readers must reject
    # the oversized scope explicitly rather than report an incomplete history.
    async with target.transaction() as tx:
        await tx.put("event", f"{257:064x}", {"fixture": "synthetic"})
        await tx.index_event(f"{257:064x}", scope, stream, 257)
    async with target.transaction() as tx:
        with pytest.raises(ValueError, match="Transfer event capacity exceeded"):
            await tx.event_ids(scope)
    async with store(db, tenant="tenant-b").transaction() as tx:
        assert await tx.event_ids(scope) == []


@pytest.fixture
def policy_review_case(db):
    import runpy
    from pathlib import Path

    from src.policy.diff import PolicyCase
    from src.services.policy_review import PolicyReviewRequest, PolicyReviewService, ReviewedCase

    policy, transfer, context, facts = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "unit/test_policy_evaluator.py")
    )["case"].__wrapped__()
    case = PolicyCase(
        case_id="synthetic-case", transfer=transfer, context=context, facts=facts, evaluated_at=context.evaluated_at
    )
    request = PolicyReviewRequest(policy=policy, cases=(ReviewedCase(case=case, expected="ALLOW"),))
    principal = Principal(
        tenant_id=policy.tenant_id,
        actor_id="synthetic-reviewer",
        roles=("policy:approve", "policy:read", "evidence:decrypt"),
    )
    return PolicyReviewService(db, cipher(), principal), request, context.evaluated_at


@pytest.mark.parametrize("clock", [True, "100", "before", "expiry"])
async def test_policy_review_requires_effective_integer_clock(policy_review_case, clock):
    service, request, now = policy_review_case
    if clock == "before":
        clock = request.policy.effective_from - 1
    elif clock == "expiry":
        clock = request.policy.effective_until
    with pytest.raises(ValueError, match="currently effective policy"):
        await service.approve(request, idempotency_key="synthetic-review", now=clock)
    assert await service.store.get("policy", request.policy.digest) is None
    assert (await service.approve(request, idempotency_key="synthetic-review", now=now))["approved_at"] == now


@pytest.mark.parametrize("duplicate", ["case", "transfer"])
async def test_policy_review_rejects_duplicate_review_inventory(policy_review_case, duplicate):
    from src.services.policy_review import PolicyReviewRequest

    service, request, now = policy_review_case
    item = request.cases[0]
    value = item.model_dump()
    if duplicate == "transfer":
        value["case"]["case_id"] = "synthetic-other-case"
    else:
        value["case"]["transfer"]["transfer_id"] = "synthetic-other-transfer"
    invalid = PolicyReviewRequest.model_validate({**request.model_dump(), "cases": (item.model_dump(), value)})
    with pytest.raises(ValueError, match="unique business transfers and case IDs"):
        await service.approve(invalid, idempotency_key="synthetic-review", now=now)
    assert await service.store.get("policy", request.policy.digest) is None


async def test_policy_review_rejects_future_observation(policy_review_case):
    from src.services.policy_review import PolicyReviewRequest

    service, request, now = policy_review_case
    value = request.model_dump()
    value["cases"][0]["case"]["evaluated_at"] = now + 1
    with pytest.raises(ValueError, match="future observations"):
        await service.approve(PolicyReviewRequest.model_validate(value), idempotency_key="synthetic-review", now=now)
    assert await service.store.get("policy", request.policy.digest) is None


@pytest.mark.parametrize("mutation", ["digest", "scope", "policy-id", "revision", "future-approval"])
async def test_policy_review_rejects_inconsistent_retained_parent(policy_review_case, mutation):
    from src.policy.model import PilotPolicy
    from src.services.policy_review import PolicyReviewRequest

    service, request, now = policy_review_case
    parent = request.policy
    if mutation == "scope":
        parent = PilotPolicy.model_validate(
            {**parent.model_dump(), "jurisdiction": "EU" if parent.jurisdiction != "EU" else "US"}
        )
    child = {**request.policy.model_dump(), "previous_digest": parent.digest, "revision": 2}
    retained = {
        "schema_version": "clearproof-policy-approval-v1",
        "policy": parent.model_dump(mode="json"),
        "approved_at": now,
    }
    if mutation == "digest":
        retained["policy"]["policy_id"] = "synthetic-different-policy"
    elif mutation == "policy-id":
        child["policy_id"] = "synthetic-different-policy"
    elif mutation == "revision":
        child["revision"] = 3
    elif mutation == "future-approval":
        retained["approved_at"] = now + 1
    child = PilotPolicy.model_validate(child)
    async with service.store.transaction() as tx:
        await tx.put("policy", parent.digest, retained)
    # Evaluate the candidate normally before testing its retained predecessor.
    # The scope case uses a foreign-scope parent and a locally valid candidate.
    from src.policy.evaluator import evaluate_policy
    from src.services.policy_review import ReviewedCase

    case = request.cases[0].case
    expected = evaluate_policy(child, case.transfer, case.context, case.facts, now=case.evaluated_at).outcome
    candidate = PolicyReviewRequest(policy=child, cases=(ReviewedCase(case=case, expected=expected),))
    with pytest.raises(ValueError, match="does not extend the retained policy history"):
        await service.approve(candidate, idempotency_key="synthetic-child", now=now)
    assert await service.store.get("policy", child.digest) is None
    async with service.store.transaction() as tx:
        assert await tx.record_ids("policy") == [parent.digest]


async def test_policy_review_rejects_conflicting_retained_case(policy_review_case):
    from src.protocol.canonical import record_digest

    service, request, now = policy_review_case
    value = request.cases[0].case.model_dump(mode="json")
    digest = record_digest("clearproof/review-case/v1", value)
    async with service.store.transaction() as tx:
        await tx.put(
            "policy", digest, {"schema_version": "clearproof-reviewed-case-v1", "case": {"fixture": "synthetic"}}
        )
    with pytest.raises(RecordConflict, match="Reviewed case content differs"):
        await service.approve(request, idempotency_key="synthetic-review", now=now)
    assert await service.store.get("policy", request.policy.digest) is None


@pytest.mark.parametrize(
    "mutation", ["duplicate", "policy-digest", "policy-tenant", "case-missing", "case-schema", "case-digest"]
)
async def test_policy_review_rejects_invalid_retained_comparison(policy_review_case, mutation):
    from src.policy.model import PilotPolicy
    from src.protocol.canonical import record_digest
    from src.services.policy_review import StoredPolicyComparison

    service, request, _ = policy_review_case
    policy = request.policy
    if mutation == "policy-tenant":
        policy = PilotPolicy.model_validate({**policy.model_dump(), "tenant_id": "tenant-b"})
    case = request.cases[0].case.model_dump(mode="json")
    digest = record_digest("clearproof/review-case/v1", case)
    policy_record = {"schema_version": "clearproof-policy-approval-v1", "policy": policy.model_dump(mode="json")}
    case_record = {"schema_version": "clearproof-reviewed-case-v1", "case": case}
    if mutation == "policy-digest":
        policy_record["policy"]["policy_id"] = "synthetic-other-policy"
    elif mutation == "case-schema":
        case_record["schema_version"] = "unknown-synthetic-schema"
    elif mutation == "case-digest":
        case_record["case"]["case_id"] = "synthetic-other-case"
    async with service.store.transaction() as tx:
        await tx.put("policy", policy.digest, policy_record)
        if mutation != "case-missing":
            await tx.put("policy", digest, case_record)
    comparison = StoredPolicyComparison(
        before_digest=policy.digest,
        after_digest=policy.digest,
        case_digests=(digest,) * (2 if mutation == "duplicate" else 1),
    )
    expected = {
        "duplicate": "Duplicate retained case",
        "policy-digest": "Retained policy binding is invalid",
        "policy-tenant": "Retained policy binding is invalid",
        "case-missing": "unavailable",
        "case-schema": "unavailable",
        "case-digest": "Retained case binding is invalid",
    }[mutation]
    with pytest.raises(ValueError, match=expected):
        await service.compare_stored(comparison)
    assert await service.store.get("policy", policy.digest) == policy_record


@pytest.fixture
def event_service(db, event_case):
    from src.services.event_ingestion import EventIngestionService

    _, authority = event_case
    principal = Principal(
        tenant_id="tenant-a", actor_id="actor-a", roles=("events:ingest", "evidence:decrypt", "evidence:read")
    )
    return EventIngestionService(db, cipher(), principal, authorities=(authority,))


@pytest.mark.parametrize(
    "changes", [{"valid_until": 1}, {"actors": ("actor-a", "actor-a")}, {"dimensions": ("custody", "custody")}]
)
async def test_event_ingestion_authority_rejects_incoherent_configuration(event_case, changes):
    from src.services.event_ingestion import EventAuthority

    _, authority = event_case
    with pytest.raises(ValueError, match="Invalid event authority"):
        EventAuthority.model_validate({**authority.model_dump(), **changes})


@pytest.mark.parametrize("inventory", ["list", "overflow"])
async def test_event_ingestion_authority_inventory_bounds(db, event_case, inventory):
    from src.services.event_ingestion import EventIngestionService

    _, authority = event_case
    values = [authority] if inventory == "list" else (authority,) * 257
    principal = Principal(tenant_id="tenant-a", actor_id="actor-a", roles=("events:ingest", "evidence:decrypt"))
    with pytest.raises(ValueError, match="bounded authority inventory"):
        EventIngestionService(db, cipher(), principal, authorities=values)


@pytest.mark.parametrize("evidence", [[], ({"fixture": "synthetic"},) * 34])
async def test_event_ingestion_provider_evidence_bounds_before_retention(event_service, event_case, evidence):
    source, _ = event_case
    with pytest.raises(ValueError, match="Provider evidence exceeds retention bounds"):
        await event_service._ingest_with_evidence(source, now=110, evidence=evidence)
    async with event_service.store.transaction() as tx:
        assert await tx.record_ids("event") == []
        assert await tx.record_ids("provider-evidence") == []


async def test_event_ingestion_conflicting_provider_evidence_rolls_back(event_service, event_case):
    from src.protocol.canonical import record_digest

    source, _ = event_case
    evidence = {"fixture": "synthetic-provider-evidence"}
    digest = record_digest("clearproof/provider-evidence/v1", evidence)
    retained = {"fixture": "synthetic-conflicting-content"}
    async with event_service.store.transaction() as tx:
        await tx.put("provider-evidence", digest, retained)
    with pytest.raises(RecordConflict, match="Provider evidence identity differs"):
        await event_service._ingest_with_evidence(source, now=110, evidence=(evidence,))
    async with event_service.store.transaction() as tx:
        assert await tx.record_ids("event") == []
        assert await tx.event_ids(source.scope.digest) == []
        assert await tx.get("provider-evidence", digest) == retained


async def test_event_ingestion_capacity_rejects_new_event_but_allows_exact_retry(event_service, event_case):
    from src.reconciliation.events import SourceEvent

    source, _ = event_case
    first = await event_service.ingest(source, now=110)
    for sequence in range(2, 257):
        current = SourceEvent.model_validate(
            {**source.model_dump(), "source_event_id": f"synthetic-{sequence}", "source_sequence": sequence}
        )
        await event_service.ingest(current, now=110)
    overflow = SourceEvent.model_validate(
        {**source.model_dump(), "source_event_id": "synthetic-overflow", "source_sequence": 257}
    )
    with pytest.raises(ValueError, match="Transfer event capacity exceeded"):
        await event_service.ingest(overflow, now=110)
    assert await event_service.ingest(source, now=111) == {**first, "duplicate": True}
    async with event_service.store.transaction() as tx:
        assert len(await tx.event_ids(source.scope.digest)) == 256
        assert len(await tx.record_ids("event")) == 256


@pytest.mark.parametrize("mutation", ["identity", "scope", "tenant"])
async def test_event_ingestion_investigation_rejects_misbound_retained_event(event_service, event_case, mutation):
    from src.protocol.canonical import record_digest
    from src.reconciliation.events import TransferEvent

    source, _ = event_case
    record_id = record_digest(
        "clearproof/source-event-id/v1",
        {"tenant_id": "tenant-a", "source_id": source.source_id, "source_event_id": source.source_event_id},
    )
    value = {**source.model_dump(), "ingested_at": 110}
    if mutation == "identity":
        value["source_event_id"] = "synthetic-different-event"
    else:
        value["scope"]["tenant_id" if mutation == "tenant" else "transfer_id"] = "synthetic-foreign"
    retained = TransferEvent.model_validate(value).model_dump(mode="json")
    async with event_service.store.transaction() as tx:
        await tx.put("event", record_id, {"event": retained})
        await tx.index_event(record_id, source.scope.digest, "a" * 64, 1)
    with pytest.raises(ValueError, match="Indexed event identity or scope differs"):
        await event_service.investigate(source.scope, now=120)


async def test_event_ingestion_investigation_rejects_missing_indexed_record(event_service, event_case, monkeypatch):
    from src.storage.pilot import PilotTransaction

    source, _ = event_case
    await event_service.ingest(source, now=110)
    original = PilotTransaction.get

    async def missing(tx, kind, record_id):
        if kind == "event":
            return None
        return await original(tx, kind, record_id)

    # Inject a broken storage read contract. PostgreSQL foreign keys ordinarily
    # prevent missing indexed rows; the service must not silently omit one.
    monkeypatch.setattr(PilotTransaction, "get", missing)
    with pytest.raises(ValueError, match="Indexed event is missing"):
        await event_service.investigate(source.scope, now=120)


async def test_event_ingestion_queue_rejects_indexed_scope_without_events(event_service, event_case, monkeypatch):
    from unittest.mock import AsyncMock

    from src.reconciliation.queue import QueueRequest
    from src.storage.pilot import PilotTransaction

    source, _ = event_case
    await event_service.ingest(source, now=110)
    # Fault-inject an inconsistent index scan after retaining a genuine scope.
    monkeypatch.setattr(PilotTransaction, "event_ids", AsyncMock(return_value=[]))
    with pytest.raises(ValueError, match="Indexed transfer has no events"):
        await event_service.queue(QueueRequest(), now=120)


async def check_authorization_mirror_rejections(service, arguments, receipt, signer):
    """Fault-inject dependency results after establishing a real valid baseline."""
    from dataclasses import replace
    from unittest.mock import AsyncMock

    from src.services.authorization_mirror import MirrorDestination
    from src.storage.pilot import PilotTransaction

    with pytest.raises(ValueError, match="Mirror consumer must be configured"):
        MirrorDestination(consumer="0x" + "00" * 20)
    original_get = PilotTransaction.get
    for missing in (None, {"schema_version": "synthetic-wrong-schema"}):

        async def unavailable(tx, kind, record_id):
            if kind == "proof":
                return missing
            return await original_get(tx, kind, record_id)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(PilotTransaction, "get", unavailable)
            with pytest.raises(ValueError, match="Retained authorization proof is unavailable"):
                await service.prepare(receipt["receipt_id"], **arguments)

    observed = []
    original_evaluate = service._evaluate_transaction

    async def capture(*args, **kwargs):
        result = await original_evaluate(*args, **kwargs)
        observed.append(result)
        return result

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(service, "_evaluate_transaction", capture)
        await service.prepare(receipt["receipt_id"], **arguments)
    inspection, decision = observed[0]
    assert inspection.cryptographic_valid and decision.outcome == "ALLOW"
    rejected = [
        (replace(inspection, cryptographic_valid=False), decision),
        (inspection, None),
        (inspection, decision.model_copy(update={"outcome": "DENY"})),
        (inspection, decision.model_copy(update={"policy_digest": "ab" * 32})),
        (replace(inspection, proof_profile="synthetic-unsupported-profile"), decision),
        (replace(inspection, manifest_digest="ab" * 32), decision),
    ]
    # These are dependency-contract tests: signatures, proof and retained inputs
    # were verified above. Altered inspection results must never authorize a plan.
    for result in rejected:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(service, "_evaluate_transaction", AsyncMock(return_value=result))
            with pytest.raises(ValueError, match="Current authorization checks did not confirm ALLOW"):
                await service.prepare(receipt["receipt_id"], **arguments)

    original_read = PilotTransaction.read
    for missing_kind in ("policy-activation", "credential"):

        async def missing_source(tx, kind, record_id, **kwargs):
            if kind == missing_kind:
                return None
            return await original_read(tx, kind, record_id, **kwargs)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(service, "_evaluate_transaction", AsyncMock(return_value=(inspection, decision)))
            patch.setattr(PilotTransaction, "read", missing_source)
            with pytest.raises(ValueError, match="Current source records are unavailable"):
                await service.prepare(receipt["receipt_id"], **arguments)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(service, "_evaluate_transaction", AsyncMock(return_value=(inspection, decision)))
        patch.setattr(service._inputs["valuation_trust"], "current_valid_until", lambda *a, **k: arguments["now"])
        with pytest.raises(ValueError, match="Mirror checkpoint interval is not current"):
            await service.prepare(receipt["receipt_id"], **arguments)
    # Every patch has been restored; the original evidence remains usable.
    assert (await service.prepare(receipt["receipt_id"], **arguments))["receipt_id"] == receipt["receipt_id"]

    await check_mirror_rebound_evidence(service, arguments, receipt, signer, (inspection, decision))


async def check_mirror_rebound_evidence(service, arguments, receipt, signer, evaluation):
    """Rebind synthetic encrypted evidence without bypassing digest/signature checks."""
    from copy import deepcopy
    from unittest.mock import AsyncMock

    from src.protocol.canonical import record_digest

    target = service._store
    db = target._db
    original_proof_id = receipt["proof_id"]
    original_proof = await target.get("proof", original_proof_id)
    original_receipt = await target.get("receipt", receipt["receipt_id"])
    tenant = target.tenant_id
    async with db.connection() as conn:
        original_sealed = await (
            await conn.execute(
                "SELECT key_id,content_tag,nonce,ciphertext FROM pilot_records "
                "WHERE tenant_id=%s AND kind='proof' AND record_id=%s AND revision=1",
                (tenant, original_proof_id),
            )
        ).fetchone()

    async def retain(conn, kind, identity, value):
        sealed = cipher().seal(tenant, kind, identity, 1, value)
        await conn.execute(
            "INSERT INTO pilot_records (tenant_id,kind,record_id,revision,key_id,content_tag,nonce,ciphertext) "
            "VALUES (%s,%s,%s,1,%s,%s,%s,%s) ON CONFLICT (tenant_id,kind,record_id,revision) "
            "DO UPDATE SET key_id=EXCLUDED.key_id,content_tag=EXCLUDED.content_tag,"
            "nonce=EXCLUDED.nonce,ciphertext=EXCLUDED.ciphertext",
            (tenant, kind, identity, sealed["key_id"], sealed["content_tag"], sealed["nonce"], sealed["ciphertext"]),
        )

    for mutation, message in (
        ("information", "Authorization information binding does not match"),
        ("envelope", "Recipient envelope binding does not match"),
        ("participants", "Mirror requires retained participant evidence"),
    ):
        proof_record, candidate = deepcopy(original_proof), deepcopy(original_receipt)
        if mutation == "information":
            candidate["information_signature_digest"] = "ab" * 32
        elif mutation == "envelope":
            proof_record["recipient_envelope"]["binding"]["sealed_at"] += 1
        else:
            proof_record["fact_ids"] = []
        candidate["envelope_digest"] = record_digest("clearproof/pilot-envelope/v1", proof_record["recipient_envelope"])
        request = {
            k: proof_record[k]
            for k in (
                "credential_id",
                "proof_digest",
                "signals",
                "fact_ids",
                "transfer_digest",
                "context_digest",
                "recipient_key_id",
                "information_signature_digest",
            )
        }
        candidate["proof_id"] = record_digest(
            "clearproof/authorized-proof/v1", {**request, "envelope_digest": candidate["envelope_digest"]}
        )
        identity = record_digest("clearproof/local-authorization/v1", candidate)
        assert identity != receipt["receipt_id"]
        proof_record["decision_attestation"] = signer.sign(candidate, service._context).model_dump(mode="json")
        try:
            # Only the isolated synthetic test schema is changed. Re-encrypt the
            # records and maintain the consumption foreign key so earlier checks
            # authenticate the candidate before its targeted inconsistency fails.
            async with db.connection() as conn:
                await retain(conn, "proof", candidate["proof_id"], proof_record)
                await retain(conn, "receipt", identity, candidate)
                await conn.execute(
                    "UPDATE pilot_consumptions SET proof_id=%s WHERE tenant_id=%s AND nullifier=%s",
                    (candidate["proof_id"], tenant, receipt["nullifier"]),
                )
            with pytest.MonkeyPatch.context() as patch:
                if mutation == "participants":
                    # Independently test the final participant-evidence gate even
                    # if a policy dependency reports ALLOW without participant facts.
                    patch.setattr(service, "_evaluate_transaction", AsyncMock(return_value=evaluation))
                with pytest.raises(ValueError, match=message):
                    await service.prepare(identity, **arguments)
        finally:
            async with db.connection() as conn:
                await conn.execute(
                    "UPDATE pilot_consumptions SET proof_id=%s WHERE tenant_id=%s AND nullifier=%s",
                    (original_proof_id, tenant, receipt["nullifier"]),
                )
                await conn.execute(
                    "UPDATE pilot_records SET key_id=%s,content_tag=%s,nonce=%s,ciphertext=%s "
                    "WHERE tenant_id=%s AND kind='proof' AND record_id=%s AND revision=1",
                    (*original_sealed, tenant, original_proof_id),
                )
                await conn.execute(
                    "DELETE FROM pilot_records WHERE tenant_id=%s AND kind='receipt' AND record_id=%s",
                    (tenant, identity),
                )
                if candidate["proof_id"] != original_proof_id:
                    await conn.execute(
                        "DELETE FROM pilot_records WHERE tenant_id=%s AND kind='proof' AND record_id=%s",
                        (tenant, candidate["proof_id"]),
                    )
        assert await target.get("proof", original_proof_id) == original_proof
        assert (await service.prepare(receipt["receipt_id"], **arguments))["receipt_id"] == receipt["receipt_id"]
