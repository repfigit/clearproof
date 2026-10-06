# SPDX-License-Identifier: Apache-2.0
"""Real PostgreSQL pages, signed enrollment, atomic indexing and corruption rejection."""

import os

import pytest
from eth_account import Account
from fastapi import HTTPException

from src.auth.principal import Principal
from src.protocol.credential import PilotCredential, holder_commitment
from src.protocol.enrollment import EnrollmentConsent
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, PilotTree
from src.services.enrollment import EnrollmentService, RevocationRequest, enrollment_scope
from src.services.enrollment_inventory import EnrollmentInventoryService, EnrollmentPageRequest
from src.services.issuance_tree import build_issuance_tree
from src.storage.pilot import PilotStore, PilotTransaction
from src.storage.pilot_cipher import RecordIntegrityError
from tests.integration.test_pilot_storage import cipher
from tests.integration.test_pilot_storage import db as db  # noqa: F401

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")
ISSUERS = ("did:web:issuer.example", "did:web:other.example")
REGISTRY = "0x" + "1" * 40
WALLET = Account.from_key(bytes([8]) * 32)  # Public synthetic-only signer.
HOLDER = holder_commitment("123456")


def principal(tenant="tenant-a", **changes):
    return Principal(
        **dict(
            tenant_id=tenant,
            actor_id="registrar",
            issuer_dids=ISSUERS,
            roles=("tenant:admin", "credential:issue", "credential:revoke", "evidence:decrypt"),
            **changes,
        )
    )


def enrollment(index, *, issuer=ISSUERS[0], tenant="tenant-a", registry=REGISTRY, expires_at=1000):
    credential = PilotCredential(
        tenant_id=tenant,
        credential_nonce=f"{index:064x}",
        issuer_did=issuer,
        subject_wallet=WALLET.address.lower(),
        holder_commitment=HOLDER,
        jurisdiction="US",
        kyc_tier=2,
        sanctions_clear=True,
        issued_at=100,
        expires_at=expires_at,
    )
    consent = EnrollmentConsent(
        credential=credential,
        chain_id=31337,
        registry_address=registry,
        consent_expires_at=min(200, expires_at),
    )
    signature = "0x" + WALLET.sign_message(consent.signing_message()).signature.hex()
    stored = dict(
        schema_version="clearproof-enrolled-credential-v1",
        consent=consent.model_dump(mode="json"),
        signature=signature,
        credential_commitment=credential.commitment,
        accepted_at=110,
        accepted_by="registrar",
    )
    return consent, signature, stored


def inventory(db, who=None):
    return EnrollmentInventoryService(db, cipher(), who or principal(), chain_id=31337, registry_address=REGISTRY)


async def persist(db, records, *, indexed=True, who=None):
    async with PilotStore(db, cipher(), who or principal()).transaction() as tx:
        for consent, _, stored in records:
            nonce = consent.credential.credential_nonce
            await tx.put("credential", nonce, stored)
            if indexed:
                await tx.index_enrollment(nonce, enrollment_scope(consent))


async def counts(db):
    async with db.connection() as conn:
        return await (
            await conn.execute(
                "SELECT (SELECT count(*) FROM pilot_records),(SELECT count(*) FROM pilot_enrollment_index),"
                "(SELECT count(*) FROM pilot_consumptions)"
            )
        ).fetchone()


async def test_service_enrollment_indexes_atomically_with_issue_only_role_and_exact_retries(db, monkeypatch):
    who = principal().model_copy(update={"roles": ("credential:issue",)})
    service = EnrollmentService(db, cipher(), who, chain_id=31337, registry_address=REGISTRY)
    consent, signature, _ = enrollment(1)
    first = await service.enroll(consent, signature, idempotency_key="enroll-1", now=110)
    before = await counts(db)
    assert before == (3, 1, 0)  # Credential, encrypted inventory head and idempotency receipt.
    assert await service.enroll(consent, signature, idempotency_key="enroll-1", now=111) == first
    assert await counts(db) == before
    original = PilotTransaction.index_enrollment

    async def fail_after_index(self, *args):
        await original(self, *args)
        raise RuntimeError("SYNTHETIC-INJECTED-INTERRUPTION")

    with monkeypatch.context() as patch:
        patch.setattr(PilotTransaction, "index_enrollment", fail_after_index)
        other, sig, _ = enrollment(2)
        with pytest.raises(RuntimeError, match="INJECTED"):
            await service.enroll(other, sig, idempotency_key="enroll-2", now=110)
    assert await counts(db) == before
    page = await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=120)
    assert [item.credential_id for item in page.entries] == [consent.credential.credential_nonce]
    assert page.entries[0].eligible and page.next_cursor is None and not page.authorization_consumed


async def test_live_pages_are_scoped_minimized_readonly_and_survive_reconnection(db):
    records = [enrollment(i) for i in range(1, 5)]
    await persist(db, records + [enrollment(5, issuer=ISSUERS[1]), enrollment(6, registry="0x" + "2" * 40)])
    await persist(db, [enrollment(7, tenant="tenant-b")], who=principal("tenant-b"))
    before = await counts(db)
    first = await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0], limit=2), now=120)
    assert [e.credential_id for e in first.entries] == [f"{i:064x}" for i in (1, 2)]
    assert first.next_cursor == f"{2:064x}"
    assert set(first.entries[0].model_dump()) == {"credential_id", "eligible"}
    text = first.model_dump_json()
    assert "subject_wallet" not in text and WALLET.address.lower() not in text and REGISTRY not in text
    await db.close()
    await db.connect()
    second = await inventory(db).page(
        EnrollmentPageRequest(issuer_did=ISSUERS[0], after=first.next_cursor, limit=2),
        now=120,
    )
    assert [e.credential_id for e in second.entries] == [f"{i:064x}" for i in (3, 4)] and second.next_cursor is None
    assert await counts(db) == before
    consent = records[0][0]
    await EnrollmentService(db, cipher(), principal(), chain_id=31337, registry_address=REGISTRY).revoke(
        RevocationRequest(
            credential_id=consent.credential.credential_nonce, idempotency_key="revoke", reason_code="test"
        ),
        now=130,
    )
    page = await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=140)
    assert [e.eligible for e in page.entries] == [False, True, True, True]
    assert not any(
        e.eligible for e in (await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=1000)).entries
    )
    assert not any(
        e.eligible for e in (await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=109)).entries
    )


async def test_backfill_is_validated_resumable_idempotent_and_cannot_claim_skipped_pages_complete(db):
    records = [enrollment(i) for i in range(1, 4)]
    await persist(db, records, indexed=False)
    service = inventory(db)
    with pytest.raises(ValueError, match="incomplete"):
        await service.page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=120)
    skipped = await service.backfill_page(after=f"{2:064x}", limit=1)
    assert skipped == dict(validated_records=1, next_cursor=None, inventory_complete=False)
    first = await service.backfill_page(limit=1)
    assert first == dict(validated_records=1, next_cursor=f"{1:064x}", inventory_complete=False)
    before = await counts(db)
    assert await service.backfill_page(limit=1) == first
    assert await counts(db) == before
    await db.close()
    await db.connect()
    final = await service.backfill_page(after=first["next_cursor"], limit=2)
    assert final == dict(validated_records=2, next_cursor=None, inventory_complete=True)
    assert len((await service.page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=120)).entries) == 3


async def test_backfill_failure_rolls_back_the_entire_page_and_never_trusts_an_index_in_place_of_signatures(db):
    first, second = enrollment(1), enrollment(2)
    second[2]["signature"] = "0x" + "00" * 65
    await persist(db, [first, second], indexed=False)
    before = await counts(db)
    with pytest.raises(ValueError, match="signature"):
        await inventory(db).backfill_page(limit=2)
    assert await counts(db) == before
    # Index rows and their encrypted counts alone do not approve bad consent.
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        for consent, _, _ in (first, second):
            await tx.index_enrollment(consent.credential.credential_nonce, enrollment_scope(consent))
    with pytest.raises(ValueError, match="signature"):
        await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=120)


@pytest.mark.parametrize(
    "damage", ["missing", "scope", "head", "boolean-head", "missing-head", "extra-head", "ciphertext"]
)
async def test_inventory_index_and_encrypted_head_corruption_cannot_hide_a_credential(db, damage):
    record = enrollment(1)
    await persist(db, [record])
    scope = enrollment_scope(record[0])
    async with db.connection() as conn:
        if damage == "missing":
            await conn.execute("DELETE FROM pilot_enrollment_index")
        elif damage == "scope":
            await conn.execute("UPDATE pilot_enrollment_index SET scope_digest=%s", ("ff" * 32,))
        elif damage == "missing-head":
            await conn.execute("DELETE FROM pilot_records WHERE kind='enrollment-inventory'")
        elif damage == "ciphertext":
            await conn.execute("UPDATE pilot_records SET ciphertext=%s WHERE kind='enrollment-inventory'", (b"x" * 16,))
    if damage in ("head", "boolean-head", "extra-head"):
        async with PilotStore(db, cipher(), principal()).transaction() as tx:
            selected = "ff" * 32 if damage == "extra-head" else scope
            await tx.put(
                "enrollment-inventory",
                selected,
                dict(scope_digest=selected, count=True if damage == "boolean-head" else 2),
                expected_revision=None if damage == "extra-head" else 1,
            )
    with pytest.raises(RecordIntegrityError if damage == "ciphertext" else ValueError):
        await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=120)


@pytest.mark.parametrize(
    "roles,issuers",
    [
        (("tenant:admin",), ISSUERS),
        (("credential:issue",), ISSUERS),
        (("evidence:decrypt",), ISSUERS),
        (("credential:issue", "evidence:decrypt"), ()),
    ],
)
async def test_page_requires_explicit_decryption_issuance_role_and_issuer_scope(db, roles, issuers):
    who = principal().model_copy(update={"roles": roles, "issuer_dids": issuers})
    with pytest.raises(HTTPException) as error:
        await inventory(db, who).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=120)
    assert error.value.status_code == 403


async def test_issuer_scoped_tree_construction_pages_past_the_former_total_tenant_limit(db):
    records = [enrollment(i, issuer=ISSUERS[0] if i <= 130 else ISSUERS[1]) for i in range(1, 261)]
    await persist(db, records)
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        candidate = await build_issuance_tree(
            tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120
        )
    expected = [(c.credential.credential_nonce, c.credential.commitment) for c, _, _ in records[:130]]
    old_tree = PilotTree(expected, depth=ISSUANCE_TREE_DEPTH)
    assert candidate.tree.root == old_tree.root and candidate.tree.entries == old_tree.entries
    assert candidate.source["entries"] == [dict(credential_id=key, commitment=leaf) for key, leaf in old_tree.entries]
    assert candidate.tree.membership(expected[-1][0]) == old_tree.membership(expected[-1][0])


async def test_small_explicit_tree_depth_still_fails_before_a_partial_tree_can_be_used(db):
    await persist(db, [enrollment(i) for i in range(1, 258)])
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        with pytest.raises(ValueError, match="issuance tree capacity exceeded"):
            await build_issuance_tree(
                tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120, depth=8
            )


@pytest.mark.skipif(not os.getenv("CLEARPROOF_PILOT_TEST_ARTIFACTS"), reason="requires explicit development artifacts")
async def test_paged_registrar_source_generates_and_independently_verifies_a_real_current_proof(db):
    import json
    from dataclasses import replace

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.protocol.root_snapshot import RootTrustError, SignedRootSnapshot, root_scope_id
    from src.protocol.transfer import VerificationContext
    from src.prover.pilot_compliance import PUBLIC_SIGNALS
    from src.prover.pilot_roots import CurrentRootPins
    from src.services.issuance_source import PagedIssuanceSource
    from src.services.proof_inspection import ProofInspectionService
    from src.services.proof_preparation import ProofPreparationService
    from src.services.registrar import PilotRegistrar
    from tests.integration.pilot_job_setup import provision

    jobs, who, operator, credential = await provision(db)
    target = next(iter(jobs.targets.values()))
    config = target.configuration
    pins = config.root_pins
    additions = []
    for index in range(1, 258):
        added = PilotCredential.model_validate({**credential.model_dump(), "credential_nonce": f"{index:064x}"})
        consent = EnrollmentConsent(
            credential=added,
            chain_id=pins.chain_id,
            registry_address=pins.registry_address,
            consent_expires_at=min(added.issued_at + 300, added.expires_at),
        )
        signature = "0x" + WALLET.sign_message(consent.signing_message()).signature.hex()
        additions.append(
            (
                consent,
                signature,
                dict(
                    schema_version="clearproof-enrolled-credential-v1",
                    consent=consent.model_dump(mode="json"),
                    signature=signature,
                    credential_commitment=added.commitment,
                    accepted_at=added.issued_at,
                    accepted_by=operator.actor_id,
                ),
            )
        )
    await persist(db, additions, who=operator)
    now = config.context.evaluated_at + 1
    registrar = PilotRegistrar(
        db,
        cipher(),
        operator,
        config.root_trust,
        Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32),
        issuers=(credential.issuer_did,),
        chain_id=pins.chain_id,
        registry_address=pins.registry_address,
    )
    refreshed = await registrar.refresh(
        expected_revision=1, idempotency_key="paged-refresh", now=now, ttl=config.transfer.expires_at - now
    )
    assert refreshed["revision"] == 2
    roots = {}
    async with PilotStore(db, cipher(), operator).transaction() as tx:
        for name in ("issuance", "issuers"):
            previous = getattr(config, name).snapshot
            roots[name] = SignedRootSnapshot.model_validate(await tx.get(previous.kind, root_scope_id(previous)))
        source = await tx.get("root-source", roots["issuance"].snapshot.source_digest)
        manifest = PagedIssuanceSource.model_validate_json(json.dumps(source))
    assert manifest.entry_count == 258 and len(manifest.page_digests) == 3 and manifest.depth == 32
    config = replace(
        config,
        **roots,
        root_pins=CurrentRootPins.model_validate(
            {
                **pins.model_dump(),
                "issuance_digest": roots["issuance"].snapshot.digest,
                "issuer_digest": roots["issuers"].snapshot.digest,
            }
        ),
        context=VerificationContext.model_validate(
            {
                **config.context.model_dump(),
                "evaluated_at": now,
                "issuance_snapshot_digest": roots["issuance"].snapshot.digest,
                "issuer_snapshot_digest": roots["issuers"].snapshot.digest,
            }
        ),
    )
    service = ProofPreparationService(db, cipher(), who, target.prover.verifier, config)
    witness = await service.prepare_witness(
        credential.credential_nonce, secret="123456", sanctions_tree=target.sanctions, now=now
    )
    assert len(witness["issuance_siblings"]) == 32
    signals = [witness[name] for name in PUBLIC_SIGNALS]
    result = await target.prover.prove(witness, expected_signals=signals)
    inspection = await ProofInspectionService(db, cipher(), operator, target.prover.verifier, config).inspect(
        credential.credential_nonce,
        result.proof,
        list(result.public_signals),
        now=now,
    )
    assert inspection.cryptographic_valid
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT count(*) FROM pilot_consumptions")).fetchone())[0] == 0
        await conn.execute(
            "DELETE FROM pilot_records WHERE kind='root-source' AND record_id=%s", (manifest.page_digests[1],)
        )
    with pytest.raises(RootTrustError, match="page is missing"):
        await service.prepare_witness(
            credential.credential_nonce, secret="123456", sanctions_tree=target.sanctions, now=now
        )


@pytest.mark.parametrize("now", [True, -1, 2**53])
async def test_inventory_rejects_invalid_evaluation_clock_before_database_access(db, now):
    with pytest.raises(ValueError, match="clock"):
        await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=now)


@pytest.mark.parametrize("limit", [True, 0, 65])
async def test_backfill_rejects_invalid_page_size(db, limit):
    with pytest.raises(ValueError, match="backfill page"):
        await inventory(db).backfill_page(limit=limit)


async def test_index_scope_mismatch_is_never_repaired_by_enrollment_retry(db):
    from src.storage.pilot import RecordConflict

    consent, signature, stored = enrollment(1)
    await persist(db, [(consent, signature, stored)])
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        with pytest.raises(RecordConflict, match="scope differs"):
            await tx.index_enrollment(consent.credential.credential_nonce, "a" * 64)
        with pytest.raises(ValueError, match="binding"):
            await tx.index_enrollment("private-noncanonical-id", "a" * 64)
        with pytest.raises(ValueError, match="page"):
            await tx.enrollment_ids(enrollment_scope(consent), after="A" * 64)


async def test_signed_enrollment_cannot_be_hidden_under_a_different_inventory_audience(db):
    from src.services.enrollment import enrollment_audience

    consent, signature, stored = enrollment(1, issuer=ISSUERS[1])
    wrong_scope = enrollment_audience("tenant-a", ISSUERS[0], 31337, REGISTRY)
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        await tx.put("credential", consent.credential.credential_nonce, stored)
        await tx.index_enrollment(consent.credential.credential_nonce, wrong_scope)
    with pytest.raises(ValueError, match="audience differs"):
        await inventory(db).page(EnrollmentPageRequest(issuer_did=ISSUERS[0]), now=120)
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        with pytest.raises(ValueError, match="audience differs"):
            await build_issuance_tree(tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120)


@pytest.mark.parametrize(
    "issuer,registry",
    [("did:web:ISSUER.example", REGISTRY), ("issuer.example", REGISTRY), (ISSUERS[0], "0x" + "0" * 40)],
)
async def test_issuance_context_rejects_noncanonical_or_zero_audience(db, issuer, registry):
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        with pytest.raises(ValueError, match="context"):
            await build_issuance_tree(tx, issuer_did=issuer, chain_id=31337, registry_address=registry, now=120)


async def test_root_scan_budget_counts_ineligible_records_and_never_returns_a_partial_tree(db):
    await persist(db, [enrollment(1, expires_at=115), enrollment(2)])
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        with pytest.raises(ValueError, match="scan capacity"):
            await build_issuance_tree(
                tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120, scan_limit=1
            )
        with pytest.raises(ValueError, match="scan budget"):
            await build_issuance_tree(
                tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120, scan_limit=True
            )
        tree = await build_issuance_tree(
            tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120, scan_limit=2
        )
        assert tree.scanned_enrollments == 2 and len(tree.tree.entries) == 1


async def test_invalid_encrypted_inventory_head_prevents_new_enrollment_atomically(db):
    from src.storage.pilot import RecordConflict

    first = enrollment(1)
    await persist(db, [first])
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        await tx.put(
            "enrollment-inventory",
            enrollment_scope(first[0]),
            dict(scope_digest=enrollment_scope(first[0]), count=True),
            expected_revision=1,
        )
    before = await counts(db)
    second, signature, _ = enrollment(2)
    with pytest.raises(RecordConflict, match="head is inconsistent"):
        await EnrollmentService(db, cipher(), principal(), chain_id=31337, registry_address=REGISTRY).enroll(
            second, signature, idempotency_key="bad-head", now=110
        )
    assert await counts(db) == before


async def test_page_and_backfill_routes_use_actual_postgresql_and_preserve_readonly_counts(db, monkeypatch):
    import httpx
    from fastapi import FastAPI

    from src.api.routes.enrollment import router
    from src.auth.principal import TenantPrincipalDependency

    monkeypatch.setenv("PII_MASTER_KEY", "61" * 32)
    monkeypatch.setenv("PILOT_CHAIN_ID", "31337")
    monkeypatch.setenv("PILOT_REGISTRY_ADDRESS", REGISTRY)
    monkeypatch.delenv("PII_ROTATED_KEYS", raising=False)
    await persist(db, [enrollment(1)], indexed=False)
    app = FastAPI()
    app.include_router(router)
    app.state.db = db
    app.dependency_overrides[TenantPrincipalDependency] = lambda: principal()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://synthetic.local") as client:
        before = await counts(db)
        response = await client.post("/pilot/credential/list", json={"issuer_did": ISSUERS[0]})
        assert response.status_code == 503 and await counts(db) == before
        repair = await client.post("/pilot/credential/backfill", json={})
        assert repair.status_code == 200 and repair.json()["inventory_complete"]
        before = await counts(db)
        page = await client.post("/pilot/credential/list", json={"issuer_did": ISSUERS[0]})
        assert page.status_code == 200 and page.json()["entries"] == [
            dict(credential_id="0" * 63 + "1", eligible=False)
        ]
        assert page.headers["Cache-Control"] == "no-store" and await counts(db) == before


async def test_audience_capacity_is_atomic_and_exact_boundary_has_no_hidden_heads(db):
    from src.storage.pilot import RecordConflict

    records = [enrollment(index, registry=f"0x{index:040x}") for index in range(1, 257)]
    await persist(db, records)
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        await tx.check_enrollment_inventory()
    before = await counts(db)
    extra, signature, _ = enrollment(257, registry=f"0x{257:040x}")
    with pytest.raises(RecordConflict, match="audience capacity"):
        await EnrollmentService(
            db, cipher(), principal(), chain_id=31337, registry_address=extra.registry_address
        ).enroll(extra, signature, idempotency_key="over-audience-limit", now=110)
    assert await counts(db) == before
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        await tx.put("enrollment-inventory", "f" * 64, dict(scope_digest="f" * 64, count=1))
        with pytest.raises(ValueError, match="scope set"):
            await tx.check_enrollment_inventory()


async def test_lost_count_head_cannot_reset_an_existing_index_counter(db):
    from src.storage.pilot import RecordConflict

    first = enrollment(1)
    await persist(db, [first])
    async with db.connection() as conn:
        await conn.execute("DELETE FROM pilot_records WHERE kind='enrollment-inventory'")
    before = await counts(db)
    second, signature, _ = enrollment(2)
    with pytest.raises(RecordConflict, match="count differs"):
        await EnrollmentService(db, cipher(), principal(), chain_id=31337, registry_address=REGISTRY).enroll(
            second, signature, idempotency_key="lost-count-head", now=110
        )
    assert await counts(db) == before


async def test_registrar_shares_scan_budget_across_issuers_and_rolls_back_every_partial_root(db, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.protocol.root_snapshot import RootAuthority, RootTrustStore
    from src.services import registrar as module

    await persist(db, [enrollment(1), enrollment(2, issuer=ISSUERS[1])])
    key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    trust = RootTrustStore(
        [
            RootAuthority(
                public_key=key.public_key().public_bytes_raw().hex(),
                tenant_id="tenant-a",
                chain_id=31337,
                registry_address=REGISTRY,
                kinds=("issuance-root", "issuer-root"),
                issuer_dids=ISSUERS,
                not_before=1,
                not_after=1000,
            )
        ]
    )
    registrar = module.PilotRegistrar(
        db,
        cipher(),
        principal(),
        trust,
        key,
        issuers=ISSUERS,
        chain_id=31337,
        registry_address=REGISTRY,
    )
    monkeypatch.setattr(module, "MAX_ISSUANCE_ENTRIES", 1)
    before = await counts(db)
    with pytest.raises(ValueError, match="scan capacity"):
        await registrar.refresh(expected_revision=0, idempotency_key="shared-budget", now=120)
    assert await counts(db) == before
    monkeypatch.setattr(module, "MAX_ISSUANCE_ENTRIES", 2)
    result = await registrar.refresh(expected_revision=0, idempotency_key="shared-budget", now=120)
    assert result["status"] == "published"
    before = await counts(db)
    assert await registrar.refresh(expected_revision=0, idempotency_key="shared-budget", now=121) == result
    assert await counts(db) == before


async def test_paged_registrar_reuses_complete_pages_and_rejects_a_corrupt_page_atomically(db):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.protocol.canonical import record_digest
    from src.protocol.root_snapshot import RootAuthority, RootTrustStore
    from src.services.issuance_source import PAGE_DOMAIN
    from src.services.registrar import PilotRegistrar
    from src.storage.pilot import RecordConflict

    await persist(db, [enrollment(index) for index in range(1, 258)])
    key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    trust = RootTrustStore(
        [
            RootAuthority(
                public_key=key.public_key().public_bytes_raw().hex(),
                tenant_id="tenant-a",
                chain_id=31337,
                registry_address=REGISTRY,
                kinds=("issuance-root", "issuer-root"),
                issuer_dids=(ISSUERS[0],),
                not_before=1,
                not_after=1000,
            )
        ]
    )
    registrar = PilotRegistrar(
        db,
        cipher(),
        principal(),
        trust,
        key,
        issuers=(ISSUERS[0],),
        chain_id=31337,
        registry_address=REGISTRY,
    )
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        candidate = await build_issuance_tree(
            tx,
            issuer_did=ISSUERS[0],
            chain_id=31337,
            registry_address=REGISTRY,
            now=120,
        )
        page_digest = record_digest(PAGE_DOMAIN, candidate.pages[0])
        await tx.put("root-source", page_digest, dict(damage="synthetic-faulted-writer"))
    before = await counts(db)
    with pytest.raises(RecordConflict, match="page collision"):
        await registrar.refresh(expected_revision=0, idempotency_key="paged-atomic", now=120)
    assert await counts(db) == before
    # Remove only the injected synthetic fault in the owned test schema.
    async with db.connection() as conn:
        await conn.execute("DELETE FROM pilot_records WHERE kind='root-source' AND record_id=%s", (page_digest,))
    first = await registrar.refresh(expected_revision=0, idempotency_key="paged-atomic", now=120)
    assert first["revision"] == 1
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        assert await tx.get("root-source", page_digest) == candidate.pages[0]
    second = await registrar.refresh(expected_revision=1, idempotency_key="paged-reuse", now=120)
    assert second["revision"] == 2
    async with db.connection() as conn:
        assert (
            await (
                await conn.execute(
                    "SELECT count(*) FROM pilot_records WHERE kind='root-source' AND record_id=%s", (page_digest,)
                )
            ).fetchone()
        )[0] == 1
    before = await counts(db)
    assert await registrar.refresh(expected_revision=1, idempotency_key="paged-reuse", now=120) == second
    assert await counts(db) == before
