"""Integration tests for durable storage layer. Requires PostgreSQL."""

from __future__ import annotations

import asyncio
import os
import time
import uuid

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("DATABASE_URL"),
        reason="requires DATABASE_URL pointing at a running PostgreSQL",
    ),
]

DB_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/clearproof_test")


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def db():
    """Exercise the real Database class against a live PostgreSQL."""
    from src.storage.database import Database

    os.environ["DATABASE_URL"] = DB_URL
    database = Database(pool_min=1, pool_max=1)
    await database.connect()
    yield database
    await database.close()


@pytest.fixture
def credential_store(db):
    from src.storage.credentials import CredentialStore

    return CredentialStore(db)


@pytest.fixture
def proof_store(db):
    from src.storage.proofs import ProofStore

    return ProofStore(db)


@pytest.fixture
def sanctions_store(db):
    from src.storage.sanctions import SanctionsStore

    return SanctionsStore(db)


@pytest.fixture
def audit_log(db):
    from src.storage.audit import PersistentAuditLog

    return PersistentAuditLog(db)


class TestCredentialStore:
    async def test_upsert_and_get_by_id(self, credential_store):
        cred = type(
            "Cred",
            (),
            {
                "credential_id": "cred-001",
                "issuer_did": "did:example:issuer",
                "subject_wallet": "0x1234567890abcdef1234567890abcdef12345678",
                "jurisdiction": "US",
                "kyc_tier": "professional",
                "sanctions_clear": True,
                "issued_at": int(time.time()) - 86400,
                "expires_at": int(time.time()) + 86400 * 365,
                "revoked": False,
                "commitment": "abc123",
            },
        )()
        await credential_store.upsert(cred)
        result = await credential_store.get_by_id("cred-001")
        assert result.credential_id == "cred-001"
        assert result.jurisdiction == "US"

    async def test_get_by_wallet(self, credential_store):
        cred = type(
            "Cred",
            (),
            {
                "credential_id": "cred-w-" + uuid.uuid4().hex[:8],
                "issuer_did": "did:example:issuer",
                "subject_wallet": "0xabcd",
                "jurisdiction": "DE",
                "kyc_tier": "retail",
                "sanctions_clear": True,
                "issued_at": int(time.time()) - 86400,
                "expires_at": int(time.time()) + 86400 * 365,
                "revoked": False,
                "commitment": "def456",
            },
        )()
        await credential_store.upsert(cred)
        results = await credential_store.get_by_wallet("0xabcd")
        assert len(results) == 1
        assert results[0].credential_id == cred.credential_id

    async def test_revoke(self, credential_store):
        cred = type(
            "Cred",
            (),
            {
                "credential_id": "cred-r-" + uuid.uuid4().hex[:8],
                "issuer_did": "did:example:issuer",
                "subject_wallet": "0x5678",
                "jurisdiction": "FR",
                "kyc_tier": "institutional",
                "sanctions_clear": True,
                "issued_at": int(time.time()) - 86400,
                "expires_at": int(time.time()) + 86400 * 365,
                "revoked": False,
                "commitment": "ghi789",
            },
        )()
        await credential_store.upsert(cred)
        assert await credential_store.is_revoked(cred.credential_id) is False
        result = await credential_store.revoke(cred.credential_id)
        assert result is True
        assert await credential_store.is_revoked(cred.credential_id) is True

    async def test_get_nonexistent(self, credential_store):
        result = await credential_store.get_by_id("nonexistent-" + uuid.uuid4().hex[:8])
        assert result is None


class TestProofStore:
    async def test_store_and_get(self, proof_store):
        proof = type(
            "Proof",
            (),
            {
                "proof_id": "proof-001",
                "transfer_id": "transfer-001",
                "groth16_proof": "proof_data",
                "public_signals": ["1", "0", "abc"],
                "verification_key": "vk_data",
                "originator_vasp_did": "did:vasp:origin",
                "beneficiary_vasp_did": "did:vasp:benef",
                "jurisdiction": "US",
                "amount_tier": 3,
                "proof_generated_at": int(time.time()),
                "proof_expires_at": int(time.time()) + 3600,
                "is_expired": False,
            },
        )()
        await proof_store.store(proof)
        result = await proof_store.get_by_id("proof-001")
        assert result is not None
        assert result.transfer_id == "transfer-001"
        assert result.amount_tier == 3

    async def test_nullifier_dedup(self, proof_store):
        nullifier = type(
            "Nullifier",
            (),
            {
                "nullifier_hash": "null-" + uuid.uuid4().hex[:8],
                "credential_commitment": "commit-001",
                "transfer_id": "transfer-002",
                "proof_id": "proof-002",
            },
        )()
        result1 = await proof_store.add_nullifier(nullifier)
        assert result1 is True
        result2 = await proof_store.add_nullifier(nullifier)
        assert result2 is False
        assert await proof_store.nullifier_exists(nullifier.nullifier_hash) is True

    async def test_idempotency(self, proof_store):
        key = str(uuid.uuid4())
        result_hash = "abc123"
        await proof_store.record_idempotency(key, "0xwallet", result_hash, ttl_seconds=3600)
        cached = await proof_store.check_idempotency(key)
        assert cached == result_hash


class TestSanctionsStore:
    async def test_record_root(self, sanctions_store):
        root = await sanctions_store.record_root("root-abc", 1000, "ofac")
        assert root.root_hash == "root-abc"
        assert root.leaf_count == 1000
        assert root.is_current is True

    async def test_get_current(self, sanctions_store):
        await sanctions_store.record_root("root-old", 900, "ofac")
        current = await sanctions_store.record_root("root-new", 950, "ofac")
        assert current.root_hash == "root-new"
        latest = await sanctions_store.get_current()
        assert latest.root_hash == "root-new"

    async def test_root_history(self, sanctions_store):
        await sanctions_store.record_root("root-1", 100, "ofac")
        await sanctions_store.record_root("root-2", 150, "un")
        await sanctions_store.record_root("root-3", 200, "eu")
        history = await sanctions_store.get_latest(limit=3)
        assert len(history) == 3
        assert history[0].root_hash == "root-3"


class TestPersistentAuditLog:
    async def test_append_and_verify(self, audit_log):
        entry = await audit_log.append(
            entry_type="proof_generated",
            actor="did:vasp:origin",
            transaction_ref="transfer-001",
            data=b"test data",
        )
        assert entry.entry_type == "proof_generated"
        assert entry.sequence_number == 1

        valid = await audit_log.verify_chain()
        assert valid is True

    async def test_get_entries(self, audit_log):
        await audit_log.append("proof_generated", "actor-1", "t-1", b"data1")
        await audit_log.append("proof_verified", "actor-2", "t-2", b"data2")
        entries = await audit_log.get_entries(entry_type="proof_generated")
        assert len(entries) == 1
        assert entries[0].entry_type == "proof_generated"

    async def test_chain_integrity_broken(self, db):
        from src.storage.audit import PersistentAuditLog

        log = PersistentAuditLog(db)
        await log.append("test", "actor", "t-1", b"data")
        async with db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("UPDATE audit_entries SET entry_hash = 'deadbeef' WHERE sequence_number = 1")
        valid = await log.verify_chain(start_seq=0)
        assert valid is False
