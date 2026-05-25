"""
Durable storage layer for the ZK Travel Rule Compliance Bridge.

Provides PostgreSQL-backed persistence for:
- zkKYC credentials (commitments, revocation status)
- Proofs (nullifiers, proof records, idempotency keys)
- Sanctions roots (root history, leaf count, update metadata)
- Audit entries (hash-chained, encrypted)

All operations are async. Connection pooling via psycopg.

Configuration via environment variables:
  DATABASE_URL  — PostgreSQL connection string (required)
  DB_POOL_MIN   — Minimum pool size (default: 2)
  DB_POOL_MAX   — Maximum pool size (default: 10)
"""

from __future__ import annotations

from src.storage.audit import PersistentAuditLog
from src.storage.credentials import CredentialStore
from src.storage.database import Database
from src.storage.models import (
    StoredAuditEntry,
    StoredCredential,
    StoredIdempotencyKey,
    StoredNullifier,
    StoredProof,
    StoredSanctionsRoot,
)
from src.storage.proofs import ProofStore
from src.storage.sanctions import SanctionsStore

__all__ = [
    "Database",
    "StoredCredential",
    "StoredProof",
    "StoredNullifier",
    "StoredSanctionsRoot",
    "StoredAuditEntry",
    "StoredIdempotencyKey",
    "CredentialStore",
    "ProofStore",
    "SanctionsStore",
    "PersistentAuditLog",
]
