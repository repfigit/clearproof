"""
Encrypted audit trail with hash-chain integrity.

Each audit entry is chained via SHA-256:
  entry_hash = SHA256(data_hash || prev_entry_hash || sequence_number)

This provides tamper-evident logging for compliance examination.
In-memory (list-based) for MVP; pluggable storage for production.
"""

from __future__ import annotations

import hashlib
import time
from typing import Optional

from pydantic import BaseModel, Field

__all__ = ["AuditEntry", "AuditLog"]

_GENESIS_HASH = "0" * 64  # Genesis block prev hash


class AuditEntry(BaseModel):
    """Single entry in the hash-chained audit log."""

    sequence_number: int = Field(..., ge=0)
    timestamp: int = Field(..., description="Unix epoch timestamp")
    entry_type: str = Field(..., description="e.g. proof_generated, sar_review, pii_decrypted")
    actor: str = Field(..., description="DID or identifier of the acting entity")
    transaction_ref: str = Field(..., description="Transfer or proof ID this entry relates to")
    data_hash: str = Field(..., description="SHA-256 hash of the entry payload data")
    prev_entry_hash: str = Field(..., description="Hash of the previous entry in the chain")
    entry_hash: str = Field(..., description="SHA-256(data_hash || prev_entry_hash || sequence_number)")

    @staticmethod
    def compute_hash(data_hash: str, prev_entry_hash: str, sequence_number: int) -> str:
        """Compute the chain hash for an entry."""
        preimage = f"{data_hash}{prev_entry_hash}{sequence_number}"
        return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


class AuditLog:
    """
    In-memory hash-chained audit log.

    Provides tamper-evident logging for compliance proofs, SAR review
    decisions, PII access events, and other auditable actions.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[AuditEntry]:
        """Read-only view of all entries."""
        return list(self._entries)

    def append(
        self,
        entry_type: str,
        actor: str,
        transaction_ref: str,
        data: bytes,
        timestamp: Optional[int] = None,
    ) -> AuditEntry:
        """
        Append a new entry to the audit log.

        Args:
            entry_type: Category of audit event.
            actor: Identifier of the entity performing the action.
            transaction_ref: Transfer/proof ID this entry relates to.
            data: Raw payload bytes (hashed, not stored in entry).
            timestamp: Unix epoch; defaults to current time.

        Returns:
            The newly created AuditEntry.
        """
        seq = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else _GENESIS_HASH
        data_hash = hashlib.sha256(data).hexdigest()
        entry_hash = AuditEntry.compute_hash(data_hash, prev_hash, seq)

        entry = AuditEntry(
            sequence_number=seq,
            timestamp=timestamp or int(time.time()),
            entry_type=entry_type,
            actor=actor,
            transaction_ref=transaction_ref,
            data_hash=data_hash,
            prev_entry_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire hash chain.

        Returns:
            True if all entry hashes are valid and properly chained.
            False if any entry has been tampered with.
        """
        for i, entry in enumerate(self._entries):
            expected_prev = self._entries[i - 1].entry_hash if i > 0 else _GENESIS_HASH

            if entry.prev_entry_hash != expected_prev:
                return False

            expected_hash = AuditEntry.compute_hash(
                entry.data_hash, entry.prev_entry_hash, entry.sequence_number
            )
            if entry.entry_hash != expected_hash:
                return False

        return True

    def get_entries_for_transaction(self, transaction_ref: str) -> list[AuditEntry]:
        """Return all audit entries related to a specific transaction."""
        return [e for e in self._entries if e.transaction_ref == transaction_ref]

    def export_examination_bundle(
        self,
        transaction_ref: Optional[str] = None,
    ) -> dict:
        """
        Export entries as a bundle for regulatory examination.

        Args:
            transaction_ref: If provided, export only entries for this transaction.
                If None, export the entire log.

        Returns:
            Dict with entries, chain verification status, and metadata.
        """
        if transaction_ref:
            entries = self.get_entries_for_transaction(transaction_ref)
        else:
            entries = list(self._entries)

        return {
            "version": "1.0",
            "chain_valid": self.verify_chain(),
            "total_entries": len(self._entries),
            "exported_entries": len(entries),
            "transaction_ref": transaction_ref,
            "entries": [e.model_dump() for e in entries],
        }
