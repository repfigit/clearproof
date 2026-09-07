"""Integration tests for durable storage layer. Requires PostgreSQL."""

from __future__ import annotations

import os
import time
import uuid

import pytest

from src.storage.models import StoredProof
from tests.integration.test_pilot_storage import db as database_fixture

db = database_fixture

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("DATABASE_URL"),
        reason="requires DATABASE_URL pointing at a running PostgreSQL",
    ),
]

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
        assert await credential_store.get_by_commitment(cred.commitment) == result
        assert await credential_store.is_expired(cred.credential_id) is False
        cred.revoked = True
        await credential_store.upsert(cred)
        assert await credential_store.is_revoked(cred.credential_id) is True

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
        assert await credential_store.get_by_commitment("missing") is None
        assert await credential_store.get_by_wallet("missing") == []
        assert await credential_store.revoke("missing") is False
        assert await credential_store.is_revoked("missing") is False
        assert await credential_store.is_expired("missing") is True


class TestProofStore:
    async def test_store_and_get(self, proof_store, sample_compliance_proof):
        proof = StoredProof.model_validate(sample_compliance_proof.model_dump())
        await proof_store.store(proof)
        result = await proof_store.get_by_id(proof.proof_id)
        assert result == proof
        assert await proof_store.get_by_transfer_id(proof.transfer_id) == proof

    async def test_nullifier_dedup(self, proof_store, sample_compliance_proof):
        proof = StoredProof.model_validate(sample_compliance_proof.model_dump())
        await proof_store.store(proof)
        nullifier = type(
            "Nullifier",
            (),
            {
                "nullifier_hash": "null-" + uuid.uuid4().hex[:8],
                "credential_commitment": "commit-001",
                "transfer_id": proof.transfer_id,
                "proof_id": proof.proof_id,
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
    async def test_empty(self, sanctions_store):
        assert await sanctions_store.get_current() is None
        assert await sanctions_store.get_latest() == []

    async def test_timestamp_and_tied_history(self, sanctions_store, db):
        first = await sanctions_store.record_root("first", 1, "synthetic")
        second = await sanctions_store.record_root("second", 2, "synthetic")
        async with db.connection() as conn:
            await conn.execute("UPDATE sanctions_roots SET updated_at = to_timestamp(1700000000)")
        history = await sanctions_store.get_latest()
        assert [root.root_id for root in history] == [second.root_id, first.root_id]
        assert [root.updated_at for root in history] == [1700000000, 1700000000]
        assert [root.is_current for root in history] == [True, False]

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
        assert (await audit_log.get_entries(transaction_ref="t-2"))[0].entry_type == "proof_verified"
        assert await audit_log.get_entries(entry_type="proof_generated", transaction_ref="t-2") == []
        assert len(await audit_log.get_entries(limit=1)) == 1

    async def test_chain_integrity_broken(self, db):
        from src.storage.audit import PersistentAuditLog

        log = PersistentAuditLog(db)
        await log.append("test", "actor", "t-1", b"data")
        async with db.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("UPDATE audit_entries SET entry_hash = 'deadbeef' WHERE sequence_number = 1")
        valid = await log.verify_chain(start_seq=0)
        assert valid is False
