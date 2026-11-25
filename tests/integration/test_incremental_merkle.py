# SPDX-License-Identifier: Apache-2.0
"""Integration tests for persisted incremental Merkle tree, concurrency, rollback, and migrations."""

from __future__ import annotations

import asyncio
import hashlib
import os
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account

from src.auth.principal import Principal
from src.protocol.canonical import record_digest
from src.protocol.credential import PilotCredential, holder_commitment
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.root_snapshot import RootAuthority, RootTrustError, RootTrustStore, SignedRootSnapshot, root_scope_id
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, PilotTree, zero_root
from src.services.enrollment import EnrollmentService, RevocationRequest, enrollment_audience, enrollment_scope
from src.services.issuance_source import ISSUANCE_SOURCE_PAGE_SIZE, issuance_source_domain
from src.services.issuance_tree import (
    PersistedIssuanceTree,
    build_issuance_tree,
    read_issuance_membership,
    read_issuance_root,
)
from src.services.registrar import PilotRegistrar
from src.storage.database import _SCHEMA_MIGRATIONS
from src.storage.merkle import IncrementalMerkleStore, MerkleIntegrityError
from src.storage.merkle_schema import ISSUANCE_MERKLE_DOWNGRADE, ISSUANCE_MERKLE_MIGRATION
from src.storage.pilot import PilotStore, PilotTransaction, RecordConflict
from tests.integration.test_enrollment_inventory import ISSUERS, REGISTRY, enrollment, persist, principal
from tests.integration.test_pilot_storage import cipher
from tests.integration.test_pilot_storage import db as db  # noqa: F401

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="requires PostgreSQL")
WALLET = Account.from_key(bytes([8]) * 32)
HOLDER = holder_commitment("123456")


def _scope(issuer=ISSUERS[0], tenant="tenant-a"):
    return enrollment_audience(tenant, issuer, 31337, REGISTRY)


def _synthetic_entries(count: int, *, start: int = 1) -> list[tuple[str, str]]:
    return [(f"{i:064x}", str(i * 17 + 3)) for i in range(start, start + count)]


async def test_differential_incremental_vs_full_rebuild_randomized_and_boundaries(db):
    """Differential check: incremental append & batch append match full PilotTree rebuild."""
    store = PilotStore(db, cipher(), principal())
    rng = random.Random(20261125)

    # Boundary leaf counts on small/medium depths: 0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33
    for depth, target_counts in ((1, (0, 1, 2)), (4, (0, 1, 2, 3, 4, 7, 8, 15, 16)), (6, (1, 15, 16, 17, 31, 32, 33))):
        scope = hashlib.sha256(f"boundary-{depth}".encode()).hexdigest()
        all_entries = _synthetic_entries(max(target_counts))
        added: list[tuple[str, str]] = []
        async with store.transaction() as tx:
            merkle = IncrementalMerkleStore(tx, scope, depth=depth)
            assert merkle.scope_digest == scope and merkle.depth == depth
            for target in target_counts:
                if target == 0:
                    state = await merkle.append_many([])
                    assert state.root_hash == str(zero_root(depth)) and state.leaf_count == 0
                    continue
                for cid, comm in all_entries[len(added) : target]:
                    state, idx = await merkle.append(cid, comm)
                    assert idx == len(added)
                    added.append((cid, comm))
                full = PilotTree(list(added), depth=depth)
                assert state.root_hash == full.root
                assert state.leaf_count == len(added)
                for cid, _ in (added[0], added[len(added) // 2], added[-1]):
                    assert await merkle.membership(cid) == full.membership(cid)

    # Randomized mixed single-append, batch-append, and out-of-order / removal sync_entries
    scope = hashlib.sha256(b"randomized-diff").hexdigest()
    depth = 8
    pool = [(f"{rng.getrandbits(256):064x}", str(rng.randint(1, 10**18))) for _ in range(90)]
    pool = sorted(pool, key=lambda x: x[0])
    async with store.transaction() as tx:
        merkle = IncrementalMerkleStore(tx, scope, depth=depth)
        cursor = 0
        while cursor < 64:
            step = rng.choice([1, 2, 3, 5, 8])
            batch = pool[cursor : min(64, cursor + step)]
            if len(batch) == 1:
                state, _ = await merkle.append(batch[0][0], batch[0][1])
            else:
                state = await merkle.append_many(batch)
            cursor += len(batch)
            full = PilotTree(pool[:cursor], depth=depth)
            assert state.root_hash == full.root
            probe = rng.choice(pool[:cursor])[0]
            assert await merkle.membership(probe) == full.membership(probe)

        # sync_entries with prefix extension appends incrementally without reset
        v_before = (await merkle.read_root()).root_version
        state = await merkle.sync_entries(pool[:75])
        assert state.root_version == v_before + 1
        assert state.root_hash == PilotTree(pool[:75], depth=depth).root

        # sync_entries with identical list is a no-op
        same = await merkle.sync_entries(pool[:75])
        assert same == state

        # sync_entries with a removal (revocation) resets cleanly and matches PilotTree
        reduced = [entry for i, entry in enumerate(pool[:75]) if i % 7 != 0]
        state_reduced = await merkle.sync_entries(reduced)
        full_reduced = PilotTree(reduced, depth=depth)
        assert state_reduced.root_hash == full_reduced.root
        assert state_reduced.leaf_count == len(reduced)
        assert await merkle.membership(reduced[-1][0]) == full_reduced.membership(reduced[-1][0])

        # sync_entries to empty set resets cleanly to zero_root
        empty_state = await merkle.sync_entries([])
        assert empty_state.leaf_count == 0 and empty_state.root_hash == str(zero_root(depth))

        # Re-growing from empty synced state works incrementally
        regrown = await merkle.sync_entries(pool[:5])
        assert regrown.root_hash == PilotTree(pool[:5], depth=depth).root
        assert regrown.leaf_count == 5


async def test_differential_above_1024_leaves_at_production_depth_32(db):
    """Exceeds the removed 1,024-entry ceiling at depth 32 and matches full rebuild exactly."""
    store = PilotStore(db, cipher(), principal())
    scope = _scope()
    total = 1050
    entries = _synthetic_entries(total)

    async with store.transaction() as tx:
        merkle = IncrementalMerkleStore(tx, scope, depth=ISSUANCE_TREE_DEPTH)
        # Seed 1024 leaves via batch append
        state_1024 = await merkle.append_many(entries[:1024])
        assert state_1024.leaf_count == 1024
        assert state_1024.root_version == 1

        # Cross the old 1,024 ceiling with individual O(32) incremental appends
        for idx in range(1024, 1030):
            cid, comm = entries[idx]
            state_inc, leaf_idx = await merkle.append(cid, comm)
            assert leaf_idx == idx
        assert state_inc.leaf_count == 1030
        assert state_inc.root_version == 7

        # Extend further to 1,050 leaves via batch append
        state_final = await merkle.append_many(entries[1030:total])
        assert state_final.leaf_count == total
        assert state_final.root_version == 8

    # Persist survives reconnection
    await db.close()
    await db.connect()

    full = PilotTree(entries, depth=ISSUANCE_TREE_DEPTH)
    async with store.transaction() as tx:
        merkle = IncrementalMerkleStore(tx, scope, depth=ISSUANCE_TREE_DEPTH)
        state = await merkle.read_root()
        assert state is not None
        assert state.root_hash == full.root
        assert state.leaf_count == total
        for probe_idx in (0, 255, 256, 1023, 1024, 1025, total - 1):
            cid = entries[probe_idx][0]
            path = await merkle.membership(cid)
            assert path == full.membership(cid)
            assert len(path["siblings"]) == ISSUANCE_TREE_DEPTH


async def test_registrar_and_build_issuance_tree_exceed_1024_entries_without_ceiling(db, monkeypatch):
    """End-to-end build_issuance_tree + PilotRegistrar > 1,024 entries with incremental updates."""
    count = 1030
    issuer = ISSUERS[0]
    # Use a fast synthetic enrollment builder for 1,030 persisted records without 1,030 slow ECDSA checks
    # by validating one real signed record and fast-tracking signature verification only in this scale test.
    sample_consent, sample_sig, _ = enrollment(1, issuer=issuer)
    entries_expected: list[tuple[str, str]] = []
    records = []
    for i in range(1, count + 1):
        cred = PilotCredential.model_validate(
            {**sample_consent.credential.model_dump(), "credential_nonce": f"{i:064x}"}
        )
        consent = EnrollmentConsent(
            credential=cred,
            chain_id=31337,
            registry_address=REGISTRY,
            consent_expires_at=200,
        )
        stored = dict(
            schema_version="clearproof-enrolled-credential-v1",
            consent=consent.model_dump(mode="json"),
            signature=sample_sig,
            credential_commitment=cred.commitment,
            accepted_at=110,
            accepted_by="registrar",
        )
        records.append((consent, sample_sig, stored))
        entries_expected.append((cred.credential_nonce, cred.commitment))

    await persist(db, records)
    monkeypatch.setattr(EnrollmentConsent, "verify_wallet_signature", lambda self, sig: None)

    key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    trust = RootTrustStore(
        [
            RootAuthority(
                public_key=key.public_key().public_bytes_raw().hex(),
                tenant_id="tenant-a",
                chain_id=31337,
                registry_address=REGISTRY,
                kinds=("issuance-root", "issuer-root"),
                issuer_dids=(issuer,),
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
        issuers=(issuer,),
        chain_id=31337,
        registry_address=REGISTRY,
    )
    refreshed = await registrar.refresh(expected_revision=0, idempotency_key="scale-1030", now=120)
    assert refreshed["status"] == "published" and refreshed["revision"] == 1

    full = PilotTree(entries_expected, depth=ISSUANCE_TREE_DEPTH)
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        root_state = await read_issuance_root(tx, issuer_did=issuer, chain_id=31337, registry_address=REGISTRY)
        assert root_state is not None
        assert root_state.leaf_count == count
        assert root_state.root_hash == full.root
        assert root_state.root_version == 1

        # Persisted O(32) membership read matches PilotTree
        path_last = await read_issuance_membership(
            tx,
            entries_expected[-1][0],
            issuer_did=issuer,
            chain_id=31337,
            registry_address=REGISTRY,
        )
        assert path_last == full.membership(entries_expected[-1][0])

        # Verify source manifest has 9 pages (ceil(1030 / 128)) and preserves v2 source digest semantics
        issuance_id = (await tx.record_ids("issuance-root"))[0]
        signed = SignedRootSnapshot.model_validate(await tx.get("issuance-root", issuance_id))
        assert signed.snapshot.root == full.root
        source = await tx.get("root-source", signed.snapshot.source_digest)
        assert source["entry_count"] == count
        assert len(source["page_digests"]) == (count + ISSUANCE_SOURCE_PAGE_SIZE - 1) // ISSUANCE_SOURCE_PAGE_SIZE
        assert record_digest(issuance_source_domain(source), source) == signed.snapshot.source_digest

    # Append 2 more credentials and refresh; incremental path updates version 1 -> 2 without full rebuild
    extra = []
    for i in range(count + 1, count + 3):
        cred = PilotCredential.model_validate(
            {**sample_consent.credential.model_dump(), "credential_nonce": f"{i:064x}"}
        )
        consent = EnrollmentConsent(credential=cred, chain_id=31337, registry_address=REGISTRY, consent_expires_at=200)
        stored = dict(
            schema_version="clearproof-enrolled-credential-v1",
            consent=consent.model_dump(mode="json"),
            signature=sample_sig,
            credential_commitment=cred.commitment,
            accepted_at=110,
            accepted_by="registrar",
        )
        extra.append((consent, sample_sig, stored))
        entries_expected.append((cred.credential_nonce, cred.commitment))
    await persist(db, extra)

    refreshed2 = await registrar.refresh(expected_revision=1, idempotency_key="scale-1032", now=125)
    assert refreshed2["revision"] == 2 and refreshed2["root"] != refreshed["root"]

    full2 = PilotTree(entries_expected, depth=ISSUANCE_TREE_DEPTH)
    async with PilotStore(db, cipher(), principal()).transaction() as tx:
        root_state2 = await read_issuance_root(tx, issuer_did=issuer, chain_id=31337, registry_address=REGISTRY)
        assert root_state2 is not None
        assert root_state2.leaf_count == count + 2
        assert root_state2.root_hash == full2.root
        assert root_state2.root_version == 2
        assert await read_issuance_membership(
            tx,
            entries_expected[-1][0],
            issuer_did=issuer,
            chain_id=31337,
            registry_address=REGISTRY,
        ) == full2.membership(entries_expected[-1][0])
        # Exercise PersistedIssuanceTree.persisted_membership, depth, cached membership, and root_version properties
        candidate = await build_issuance_tree(tx, issuer_did=issuer, chain_id=31337, registry_address=REGISTRY, now=125)
        assert candidate.tree.depth == ISSUANCE_TREE_DEPTH
        assert candidate.tree.root_version == 2
        assert candidate.root_version == 2
        assert await candidate.tree.persisted_membership(entries_expected[0][0]) == full2.membership(
            entries_expected[0][0]
        )
        assert await candidate.tree.persisted_membership(entries_expected[0][0]) == candidate.tree.membership(
            entries_expected[0][0]
        )
        assert candidate.tree.membership(entries_expected[-1][0]) == full2.membership(entries_expected[-1][0])
        # Standalone PersistedIssuanceTree without merkle store fails closed on persisted_membership
        detached = PersistedIssuanceTree(full2.root, full2.entries, ISSUANCE_TREE_DEPTH, 2)
        with pytest.raises(RuntimeError, match="unavailable"):
            await detached.persisted_membership(entries_expected[0][0])


async def test_concurrent_appends_serialized_under_tenant_lock_without_root_drift(db):
    """Concurrent enrollments and Merkle appends serialize under PilotStore's advisory lock."""
    who = principal()
    service = EnrollmentService(db, cipher(), who, chain_id=31337, registry_address=REGISTRY)
    items = [enrollment(i) for i in range(1, 13)]

    async def enroll_one(i: int):
        consent, sig, _ = items[i]
        return await service.enroll(consent, sig, idempotency_key=f"conc-{i}", now=110)

    results = await asyncio.gather(*(enroll_one(i) for i in range(len(items))))
    assert len(results) == len(items)

    # Reconcile via build_issuance_tree (handles any out-of-order concurrent arrival)
    async with PilotStore(db, cipher(), who).transaction() as tx:
        candidate = await build_issuance_tree(
            tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120
        )
    expected = [(c.credential.credential_nonce, c.credential.commitment) for c, _, _ in items]
    full = PilotTree(expected, depth=ISSUANCE_TREE_DEPTH)
    assert candidate.tree.root == full.root
    assert candidate.tree.entries == full.entries

    # Concurrent direct IncrementalMerkleStore.append calls on a separate scope
    scope = hashlib.sha256(b"concurrent-direct-append").hexdigest()
    direct_entries = _synthetic_entries(10)

    async def append_one(cid: str, comm: str):
        async with PilotStore(db, cipher(), who).transaction() as tx:
            merkle = IncrementalMerkleStore(tx, scope, depth=6)
            return await merkle.append(cid, comm)

    appended = await asyncio.gather(*(append_one(cid, comm) for cid, comm in direct_entries))
    assigned_indices = sorted(idx for _, idx in appended)
    assert assigned_indices == list(range(len(direct_entries)))

    # Because concurrent tasks acquire the advisory lock in arbitrary order, verify the
    # persisted leaves match the persisted root AND every membership path verifies cleanly.
    async with PilotStore(db, cipher(), who).transaction() as tx:
        merkle = IncrementalMerkleStore(tx, scope, depth=6)
        state = await merkle.read_root()
        leaves = await merkle.read_leaves()
        assert state is not None
        assert state.leaf_count == len(direct_entries)
        assert state.root_version == len(direct_entries)
        assert len(leaves) == len(direct_entries)
        # Recompute dense root in the exact persisted leaf_index order and verify zero drift
        layer = [int(leaf.commitment) for leaf in leaves] + [0] * (2**6 - len(leaves))
        from src.registry.poseidon import poseidon_hash

        while len(layer) > 1:
            layer = [poseidon_hash(layer[i : i + 2]) for i in range(0, len(layer), 2)]
        assert state.root_hash == str(layer[0])
        for leaf in leaves:
            proof = await merkle.membership(leaf.credential_id)
            assert proof["root"] == state.root_hash


async def test_rollback_on_partial_failure_leaves_merkle_tables_untouched(db, monkeypatch):
    """Any failure mid-append or mid-batch rolls back leaves, nodes, and root atomically."""
    who = principal()
    store = PilotStore(db, cipher(), who)
    scope = hashlib.sha256(b"rollback-scope").hexdigest()
    seed = _synthetic_entries(4)

    async with store.transaction() as tx:
        merkle = IncrementalMerkleStore(tx, scope, depth=6)
        initial = await merkle.append_many(seed)

    async def table_snapshot():
        async with db.connection() as conn:
            roots = await (await conn.execute("SELECT * FROM pilot_merkle_roots ORDER BY scope_digest")).fetchall()
            leaves = await (await conn.execute("SELECT * FROM pilot_merkle_leaves ORDER BY leaf_index")).fetchall()
            nodes = await (
                await conn.execute(
                    "SELECT level, node_index, node_hash, root_version "
                    "FROM pilot_merkle_nodes ORDER BY level, node_index"
                )
            ).fetchall()
            return roots, leaves, nodes

    before = await table_snapshot()

    # 1. Failure after _upsert_nodes inside append() rolls back leaf + nodes + root
    original_upsert = IncrementalMerkleStore._upsert_nodes

    async def fail_after_upsert(self, nodes, root_version):
        await original_upsert(self, nodes, root_version)
        raise RuntimeError("SYNTHETIC-NODE-WRITE-CRASH")

    with monkeypatch.context() as patch:
        patch.setattr(IncrementalMerkleStore, "_upsert_nodes", fail_after_upsert)
        with pytest.raises(RuntimeError, match="SYNTHETIC-NODE-WRITE-CRASH"):
            async with store.transaction() as tx:
                await IncrementalMerkleStore(tx, scope, depth=6).append(f"{99:064x}", "9999")
    assert await table_snapshot() == before

    # 2. Failure after _upsert_nodes inside append_many() rolls back batch
    with monkeypatch.context() as patch:
        patch.setattr(IncrementalMerkleStore, "_upsert_nodes", fail_after_upsert)
        with pytest.raises(RuntimeError, match="SYNTHETIC-NODE-WRITE-CRASH"):
            async with store.transaction() as tx:
                await IncrementalMerkleStore(tx, scope, depth=6).append_many(_synthetic_entries(3, start=50))
    assert await table_snapshot() == before

    # 3. Failure during EnrollmentService.enroll after Merkle append rolls back credential + index + Merkle
    service = EnrollmentService(db, cipher(), who, chain_id=31337, registry_address=REGISTRY)
    first_c, first_s, _ = enrollment(1)
    await service.enroll(first_c, first_s, idempotency_key="rb-1", now=110)
    enroll_before = await table_snapshot()

    original_append = IncrementalMerkleStore.append

    async def fail_after_append(self, cid, comm):
        await original_append(self, cid, comm)
        raise RuntimeError("SYNTHETIC-ENROLL-CRASH")

    with monkeypatch.context() as patch:
        patch.setattr(IncrementalMerkleStore, "append", fail_after_append)
        second_c, second_s, _ = enrollment(2)
        with pytest.raises(RuntimeError, match="SYNTHETIC-ENROLL-CRASH"):
            await service.enroll(second_c, second_s, idempotency_key="rb-2", now=110)
    assert await table_snapshot() == enroll_before

    # Verify original root is still intact and valid
    async with store.transaction() as tx:
        state = await IncrementalMerkleStore(tx, scope, depth=6).read_root()
        assert state == initial


async def test_migration_up_and_down_preserves_existing_records_and_reapplies_cleanly(db):
    """Migration down removes Merkle tables cleanly; up re-creates them without touching pilot_records."""
    who = principal()
    service = EnrollmentService(db, cipher(), who, chain_id=31337, registry_address=REGISTRY)
    c1, s1, _ = enrollment(1)
    await service.enroll(c1, s1, idempotency_key="mig-1", now=110)
    stored_before = await PilotStore(db, cipher(), who).get("credential", c1.credential.credential_nonce)

    merkle_version = _SCHEMA_MIGRATIONS.index(ISSUANCE_MERKLE_MIGRATION) + 1
    head_version = len(_SCHEMA_MIGRATIONS)
    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT max(version) FROM schema_migrations")).fetchone())[0] == head_version
        for tbl in ("pilot_merkle_roots", "pilot_merkle_leaves", "pilot_merkle_nodes"):
            assert (await (await conn.execute("SELECT to_regclass(%s)", (tbl,))).fetchone())[0] == tbl

        # Downgrade back below ISSUANCE_MERKLE_MIGRATION (dropping later tables too)
        await conn.execute("DROP TABLE api_rate_limit_buckets, siwe_sessions")
        await conn.execute(ISSUANCE_MERKLE_DOWNGRADE)
        await conn.execute("DELETE FROM schema_migrations WHERE version >= %s", (merkle_version,))
        for tbl in ("pilot_merkle_roots", "pilot_merkle_leaves", "pilot_merkle_nodes"):
            assert (await (await conn.execute("SELECT to_regclass(%s)", (tbl,))).fetchone())[0] is None

    # Reconnect triggers _migrate() which runs ISSUANCE_MERKLE_MIGRATION and later migrations up again
    await db.close()
    await db.connect()

    async with db.connection() as conn:
        assert (await (await conn.execute("SELECT max(version) FROM schema_migrations")).fetchone())[0] == head_version
        for tbl in ("pilot_merkle_roots", "pilot_merkle_leaves", "pilot_merkle_nodes"):
            assert (await (await conn.execute("SELECT to_regclass(%s)", (tbl,))).fetchone())[0] == tbl

    # Existing encrypted enrollment survived downgrade + upgrade intact and rebuilds cleanly
    assert await PilotStore(db, cipher(), who).get("credential", c1.credential.credential_nonce) == stored_before
    async with PilotStore(db, cipher(), who).transaction() as tx:
        candidate = await build_issuance_tree(
            tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120
        )
        assert candidate.tree.entries == ((c1.credential.credential_nonce, c1.credential.commitment),)
        assert (
            candidate.tree.root
            == PilotTree([(c1.credential.credential_nonce, c1.credential.commitment)], depth=32).root
        )

    # Verify raw migration SQL string is exported and valid
    assert "CREATE TABLE pilot_merkle_roots" in ISSUANCE_MERKLE_MIGRATION


async def test_fail_closed_validation_and_drift_detection(db):
    """Covers every validation, capacity, version-overflow, CAS conflict, and corruption guard."""
    who = principal()
    store = PilotStore(db, cipher(), who)
    scope = hashlib.sha256(b"fail-closed-scope").hexdigest()

    async with store.transaction() as tx:
        # Invalid scope / depth
        with pytest.raises(ValueError, match="scope digest"):
            IncrementalMerkleStore(tx, "not-hex", depth=4)
        with pytest.raises(ValueError, match="Tree depth"):
            IncrementalMerkleStore(tx, scope, depth=0)
        with pytest.raises(ValueError, match="Tree depth"):
            IncrementalMerkleStore(tx, scope, depth=True)
        with pytest.raises(ValueError, match="Tree depth"):
            IncrementalMerkleStore(tx, scope, depth=33)

        merkle = IncrementalMerkleStore(tx, scope, depth=2)

        # Invalid credential id / commitment
        with pytest.raises(ValueError, match="credential identifier"):
            await merkle.append("bad-id", "123")
        with pytest.raises(ValueError, match="credential identifier"):
            await merkle.membership("bad-id")
        with pytest.raises(KeyError, match="not found"):
            await merkle.membership("a" * 64)

        # Empty tree read_root is None, last_credential_id is None
        assert await merkle.read_root() is None
        assert await merkle.last_credential_id() is None

        # Populate via reset_and_populate from uninitialized state (both empty and non-empty)
        r0 = await merkle.reset_and_populate([])
        assert r0.root_version == 1 and r0.leaf_count == 0
        assert await merkle.last_credential_id() is None

        # Duplicate in batch rejected
        with pytest.raises(ValueError, match="Duplicate"):
            await merkle.append_many([("a" * 64, "11"), ("a" * 64, "22")])
        with pytest.raises(ValueError, match="Duplicate"):
            await merkle.append_many([("a" * 64, "11"), ("b" * 64, "11")])
        with pytest.raises(ValueError, match="Duplicate"):
            await merkle.reset_and_populate([("a" * 64, "11"), ("a" * 64, "22")])

        # Over-capacity rejected
        with pytest.raises(ValueError, match="capacity exceeded"):
            await merkle.append_many(_synthetic_entries(5))
        with pytest.raises(ValueError, match="capacity exceeded"):
            await merkle.reset_and_populate(_synthetic_entries(5))

        # Fill to capacity (4 leaves at depth 2)
        entries4 = _synthetic_entries(4)
        await merkle.append_many(entries4[:2])
        assert await merkle.last_credential_id() == entries4[1][0]

        # Duplicate against already-persisted leaves rejected
        with pytest.raises(RecordConflict, match="Duplicate"):
            await merkle.append(entries4[0][0], "999")
        with pytest.raises(RecordConflict, match="Duplicate"):
            await merkle.append("f" * 64, entries4[0][1])
        with pytest.raises(RecordConflict, match="Duplicate"):
            await merkle.append_many([entries4[0]])

        # Missing entry lookup fails with KeyError
        with pytest.raises(KeyError, match="not found"):
            await merkle.membership("e" * 64)

        await merkle.append_many(entries4[2:])
        with pytest.raises(ValueError, match="capacity exceeded"):
            await merkle.append("f" * 64, "99999")

    # Test corruption & drift scenarios directly via SQL
    async with store.transaction() as tx:
        merkle = IncrementalMerkleStore(tx, scope, depth=2)
        # 1. Corrupt internal node hash -> membership recomputation fails closed
        await tx._conn.execute(
            "UPDATE pilot_merkle_nodes SET node_hash='1234567' "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=2 AND level=1 AND node_index=1",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="Recomputed Merkle path root differs"):
            await merkle.membership(entries4[0][0])

        # 2. Corrupt leaf node hash -> membership leaf check fails closed
        await tx._conn.execute(
            "UPDATE pilot_merkle_nodes SET node_hash='7654321' "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=2 AND level=0 AND node_index=0",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="leaf node differs"):
            await merkle.membership(entries4[0][0])

        # 2b. Missing leaf node in pilot_merkle_nodes -> _load_node returns zero_root(0) != leaf_value -> fails closed
        await tx._conn.execute(
            "DELETE FROM pilot_merkle_nodes "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=2 AND level=0 AND node_index=0",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="leaf node differs"):
            await merkle.membership(entries4[0][0])

        # 3. Corrupt root node vs metadata -> sync_entries fails closed
        await tx._conn.execute(
            "UPDATE pilot_merkle_nodes SET node_hash='999999' "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=2 AND level=2 AND node_index=0",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="root node differs"):
            await merkle.sync_entries(entries4)

        # 4. Corrupt leaf_count vs actual stored leaves -> sync_entries fails closed
        await tx._conn.execute(
            "UPDATE pilot_merkle_roots SET leaf_count=3 WHERE tenant_id=%s AND scope_digest=%s AND depth=2",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="leaf_count differs"):
            await merkle.sync_entries(entries4)

        # 5. Leaf count exceeding 2**depth -> read_root fails closed
        await tx._conn.execute(
            "UPDATE pilot_merkle_roots SET leaf_count=5 WHERE tenant_id=%s AND scope_digest=%s AND depth=2",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="exceeds tree depth capacity"):
            await merkle.read_root()

        # 6. Non-contiguous leaf indices -> read_leaves fails closed
        await tx._conn.execute(
            "DELETE FROM pilot_merkle_leaves WHERE tenant_id=%s AND scope_digest=%s AND depth=2 AND leaf_index=1",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="non-contiguous"):
            await merkle.read_leaves()

        # 7. Empty root with corrupted root_hash -> sync_entries fails closed
        await tx._conn.execute(
            "DELETE FROM pilot_merkle_leaves WHERE tenant_id=%s AND scope_digest=%s AND depth=2",
            (who.tenant_id, scope),
        )
        await tx._conn.execute(
            "UPDATE pilot_merkle_roots SET leaf_count=0, root_hash='42' "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=2",
            (who.tenant_id, scope),
        )
        with pytest.raises(MerkleIntegrityError, match="zero_root"):
            await merkle.sync_entries([])

        # 8. Root version overflow guards on append, append_many, reset_and_populate
        await tx._conn.execute(
            "UPDATE pilot_merkle_roots SET root_version=%s, leaf_count=0, root_hash=%s "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=2",
            (2**53 - 1, str(zero_root(2)), who.tenant_id, scope),
        )
        with pytest.raises(ValueError, match="version overflow"):
            await merkle.append("a" * 64, "11")
        with pytest.raises(ValueError, match="version overflow"):
            await merkle.append_many([("a" * 64, "11")])
        with pytest.raises(ValueError, match="version overflow"):
            await merkle.reset_and_populate([])

    # 9. Root version CAS conflict guards during append & append_many (each in its own tx so rollback is clean)
    scope_cas = hashlib.sha256(b"cas-conflict-scope").hexdigest()
    async with store.transaction() as tx:
        await IncrementalMerkleStore(tx, scope_cas, depth=4).append("a" * 64, "11")

    with pytest.raises(RecordConflict, match="version conflict during append"):
        async with store.transaction() as tx:
            merkle = IncrementalMerkleStore(tx, scope_cas, depth=4)
            orig_upsert = merkle._upsert_nodes

            async def bump_append(nodes, root_version):
                await orig_upsert(nodes, root_version)
                await tx._conn.execute(
                    "UPDATE pilot_merkle_roots SET root_version = root_version + 10 "
                    "WHERE tenant_id=%s AND scope_digest=%s AND depth=4",
                    (who.tenant_id, scope_cas),
                )

            merkle._upsert_nodes = bump_append
            await merkle.append("b" * 64, "22")

    with pytest.raises(RecordConflict, match="version conflict during batch append"):
        async with store.transaction() as tx:
            merkle = IncrementalMerkleStore(tx, scope_cas, depth=4)
            orig_upsert = merkle._upsert_nodes

            async def bump_batch(nodes, root_version):
                await orig_upsert(nodes, root_version)
                await tx._conn.execute(
                    "UPDATE pilot_merkle_roots SET root_version = root_version + 10 "
                    "WHERE tenant_id=%s AND scope_digest=%s AND depth=4",
                    (who.tenant_id, scope_cas),
                )

            merkle._upsert_nodes = bump_batch
            await merkle.append_many([("c" * 64, "33")])

    # 10. Registrar invalid scan_limit rejected before writing
    key = Ed25519PrivateKey.generate()
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
        who,
        trust,
        key,
        issuers=(ISSUERS[0],),
        chain_id=31337,
        registry_address=REGISTRY,
        issuance_depth=4,
    )
    for bad_limit in (True, -1, 17):
        with pytest.raises(ValueError, match="scan budget"):
            await registrar.refresh(expected_revision=0, idempotency_key="bad-scan", now=120, scan_limit=bad_limit)


async def test_enrollment_out_of_order_and_revocation_reconcile_cleanly(db):
    """Out-of-order enrollments defer to sync_entries; revocations update persisted root cleanly."""
    who = principal()
    service = EnrollmentService(db, cipher(), who, chain_id=31337, registry_address=REGISTRY)
    # Enroll index 5 first (creates root with 1 leaf), then index 2 (smaller credential_id: deferred)
    c5, s5, _ = enrollment(5)
    c2, s2, _ = enrollment(2)
    await service.enroll(c5, s5, idempotency_key="ooo-5", now=110)
    await service.enroll(c2, s2, idempotency_key="ooo-2", now=110)

    # Before refresh, persisted tree has only leaf 5 (append-only skipped out-of-order leaf 2)
    async with PilotStore(db, cipher(), who).transaction() as tx:
        state_before = await read_issuance_root(tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY)
        assert state_before is not None and state_before.leaf_count == 1

        # Refresh reconciles sorted order [2, 5] cleanly
        candidate = await build_issuance_tree(
            tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=120
        )
        full = PilotTree(
            [
                (c2.credential.credential_nonce, c2.credential.commitment),
                (c5.credential.credential_nonce, c5.credential.commitment),
            ],
            depth=ISSUANCE_TREE_DEPTH,
        )
        assert candidate.tree.root == full.root
        assert await candidate.tree.persisted_membership(c2.credential.credential_nonce) == full.membership(
            c2.credential.credential_nonce
        )

    # Revoke c2, rebuild -> persisted tree has only c5; then enroll c9 (extends tail incrementally!)
    await service.revoke(
        RevocationRequest(credential_id=c2.credential.credential_nonce, idempotency_key="rev-2", reason_code="test"),
        now=130,
    )
    async with PilotStore(db, cipher(), who).transaction() as tx:
        after_rev = await build_issuance_tree(
            tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY, now=140
        )
        assert after_rev.tree.entries == ((c5.credential.credential_nonce, c5.credential.commitment),)
        assert after_rev.tree.root == PilotTree(list(after_rev.tree.entries), depth=ISSUANCE_TREE_DEPTH).root

    c9, s9, _ = enrollment(9)
    await service.enroll(c9, s9, idempotency_key="ooo-9", now=145)
    async with PilotStore(db, cipher(), who).transaction() as tx:
        state_after = await read_issuance_root(tx, issuer_did=ISSUERS[0], chain_id=31337, registry_address=REGISTRY)
        full_5_9 = PilotTree(
            [
                (c5.credential.credential_nonce, c5.credential.commitment),
                (c9.credential.credential_nonce, c9.credential.commitment),
            ],
            depth=ISSUANCE_TREE_DEPTH,
        )
        assert state_after is not None and state_after.root_hash == full_5_9.root
        assert state_after.leaf_count == 2


async def test_proof_preparation_consumes_persisted_incremental_merkle_and_fails_closed_on_drift(db):
    """ProofPreparationService reads O(32) paths from persisted Merkle nodes and rejects drift."""
    import runpy
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from src.policy.diff import PolicyCase
    from src.policy.evaluator import PolicyFacts
    from src.protocol.transfer import VerificationContext
    from src.prover.pilot_roots import CurrentRootPins
    from src.registry.pilot_sanctions import PilotSanctionsTree
    from src.services.policy_activation import PolicyActivationRequest, PolicyActivationService
    from src.services.policy_review import PolicyReviewRequest, PolicyReviewService, ReviewedCase
    from src.services.proof_inspection import CurrentStatementConfiguration
    from src.services.proof_preparation import ProofPreparationService
    from src.services.root_publication import RootPublicationService
    from tests.integration.test_pilot_storage import ROLES

    helper = runpy.run_path(str(Path(__file__).parents[1] / "unit/test_pilot_compliance.py"))["synthetic_case"]
    _, _, inputs = helper(with_trust=True)
    credential, now = inputs.pop("credential"), inputs.pop("now")
    operator = Principal(
        tenant_id=credential.tenant_id,
        actor_id="prep-operator",
        roles=(*ROLES, "policy:activate", "policy:read"),
        issuer_dids=(credential.issuer_did,),
    )
    pins = inputs["root_pins"]
    consent = EnrollmentConsent(
        credential=credential,
        chain_id=pins.chain_id,
        registry_address=pins.registry_address,
        consent_expires_at=min(credential.issued_at + 600, credential.expires_at),
    )
    await EnrollmentService(
        db, cipher(), operator, chain_id=pins.chain_id, registry_address=pins.registry_address
    ).enroll(
        consent,
        "0x" + WALLET.sign_message(consent.signing_message()).signature.hex(),
        idempotency_key="prep-enroll",
        now=credential.issued_at,
    )
    await PilotRegistrar(
        db,
        cipher(),
        operator,
        inputs["root_trust"],
        Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32),
        issuers=(credential.issuer_did,),
        chain_id=pins.chain_id,
        registry_address=pins.registry_address,
    ).refresh(expected_revision=0, idempotency_key="prep-refresh", now=now, ttl=credential.expires_at - now)

    reader = PilotStore(db, cipher(), operator)
    async with reader.transaction() as tx:
        for name in ("issuance", "issuers"):
            snap = inputs[name].snapshot
            inputs[name] = SignedRootSnapshot.model_validate(await tx.get(snap.kind, root_scope_id(snap)))
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
    await RootPublicationService(db, cipher(), operator, inputs["root_trust"]).publish(
        inputs["sanctions"], idempotency_key="prep-sanctions", now=now
    )
    policy = inputs["policy_trust"].for_transfer(
        inputs["transfer"], inputs["context"], tenant_id=operator.tenant_id, now=now
    )
    case = PolicyCase(
        case_id="prep-case",
        transfer=inputs["transfer"],
        context=inputs["context"],
        facts=PolicyFacts(tenant_id=operator.tenant_id, transfer_digest=inputs["transfer"].digest, facts=()),
        evaluated_at=now,
    )
    await PolicyReviewService(db, cipher(), operator).approve(
        PolicyReviewRequest(policy=policy, cases=(ReviewedCase(case=case, expected="INDETERMINATE"),)),
        idempotency_key="prep-review",
        now=now,
    )
    await PolicyActivationService(db, cipher(), operator).activate(
        PolicyActivationRequest(policy_digest=policy.digest), idempotency_key="prep-activate", now=now
    )

    # Lightweight stub verifier (prepare_witness checks artifact context only, never runs snarkjs)
    stub_verifier = SimpleNamespace(artifacts=SimpleNamespace(check_artifact_context=lambda ctx: None))
    prep = ProofPreparationService(db, cipher(), operator, stub_verifier, CurrentStatementConfiguration(**inputs))

    # 1. Happy path: consumes persisted incremental Merkle path directly
    witness_persisted = await prep.prepare_witness(
        credential.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now
    )
    assert len(witness_persisted["issuance_siblings"]) == ISSUANCE_TREE_DEPTH
    assert witness_persisted["issuance_root"] == inputs["issuance"].snapshot.root

    # 2. If persisted Merkle leaves drift from retained source while root hash matches, fail closed
    scope = enrollment_scope(consent)
    async with db.connection() as conn:
        await conn.execute(
            "UPDATE pilot_merkle_leaves SET credential_id=%s WHERE tenant_id=%s AND scope_digest=%s",
            ("ff" * 32, operator.tenant_id, scope),
        )
    with pytest.raises(RootTrustError, match="Persisted Merkle state is inconsistent"):
        await prep.prepare_witness(
            credential.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now
        )

    # 3. Historical fallback: if persisted Merkle root has advanced/cleared, reconstructs from retained source
    async with db.connection() as conn:
        await conn.execute(
            "DELETE FROM pilot_merkle_nodes WHERE tenant_id=%s AND scope_digest=%s", (operator.tenant_id, scope)
        )
        await conn.execute(
            "DELETE FROM pilot_merkle_leaves WHERE tenant_id=%s AND scope_digest=%s", (operator.tenant_id, scope)
        )
        await conn.execute(
            "DELETE FROM pilot_merkle_roots WHERE tenant_id=%s AND scope_digest=%s", (operator.tenant_id, scope)
        )
    witness_fallback = await prep.prepare_witness(
        credential.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now
    )
    assert witness_fallback == witness_persisted

    # 4. Sanctions root mismatch hits the witness inventory root guard
    with pytest.raises(RootTrustError, match="Witness inventory roots differ"):
        await prep.prepare_witness(
            credential.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree(["0x" + "9" * 40]), now=now
        )

    # 5. Absent enrollment in source still fails closed
    bad_source_prep = ProofPreparationService(
        db, cipher(), operator, stub_verifier, CurrentStatementConfiguration(**inputs)
    )
    orig_get = PilotTransaction.get

    async def empty_entries_source(self, kind, record_id):
        val = await orig_get(self, kind, record_id)
        if kind == "root-source" and record_id == inputs["issuance"].snapshot.source_digest:
            return {**val, "entries": []}
        return val

    # Recompute digest for empty entries to pass source digest check and hit membership guard
    empty_src = {**(await reader.get("root-source", inputs["issuance"].snapshot.source_digest)), "entries": []}
    empty_digest = record_digest("clearproof/issuance-source/v1", empty_src)
    signed_iss = bad_source_prep._inputs["issuance"]
    bad_source_prep._inputs["issuance"] = signed_iss.model_copy(
        update={"snapshot": signed_iss.snapshot.model_copy(update={"source_digest": empty_digest})}
    )

    async def return_empty(self, kind, record_id):
        if kind == "root-source" and record_id == empty_digest:
            return empty_src
        return await orig_get(self, kind, record_id)

    bad_source_prep._load_current_credential = AsyncMock(return_value=credential)
    old_get = PilotTransaction.get
    PilotTransaction.get = return_empty
    try:
        with pytest.raises(RootTrustError, match="absent from retained issuance inventory"):
            await bad_source_prep.prepare_witness(
                credential.credential_nonce, secret="123456", sanctions_tree=PilotSanctionsTree([]), now=now
            )
    finally:
        PilotTransaction.get = old_get
