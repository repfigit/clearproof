"""Append-only off-chain audit mirror.

Mirrors all on-chain compliance events to a local file for:
1. Regulatory examination (chain events may be insufficient)
2. Offline access during chain downtime
3. Additional context not stored on-chain (PII hashes, request metadata)

Format: JSON Lines (one JSON object per line)
Location: configurable via AUDIT_MIRROR_PATH env var

Each record includes a SHA-256 hash of the previous record to form a
tamper-evident hash chain.
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import BinaryIO

import portalocker

logger = logging.getLogger(__name__)


class AuditMirror:
    """Append-only audit mirror with hash-chain integrity."""

    def __init__(self, path: str | None = None, *, lock_timeout: float = 30) -> None:
        self._path = Path(path or os.environ.get("AUDIT_MIRROR_PATH", "./audit/mirror.jsonl"))
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_timeout = lock_timeout
        self._compute_tail_hash()  # Fail on an unreadable existing log.

    # -- internal helpers ------------------------------------------------------

    def _compute_tail_hash(self) -> str:
        """Read the last line of the mirror file and return its hash.

        Returns the zero hash if the file is empty or does not exist.
        """
        zero_hash = "0" * 64
        if not self._path.exists():
            return zero_hash
        with portalocker.Lock(self._path, "rb", timeout=self._lock_timeout) as f:
            return self._read_tail_hash(f)

    @staticmethod
    def _read_tail_hash(f: BinaryIO) -> str:
        # Read backwards until a complete non-empty record is available. Records
        # can exceed a chunk; hashing only the last 4 KB would fork the chain.
        f.seek(0, 2)
        position = f.tell()
        fragment = b""
        while position:
            size = min(4096, position)
            position -= size
            f.seek(position)
            lines = (f.read(size) + fragment).split(b"\n")
            complete = lines[1:] if position else lines
            for line in reversed(complete):
                # Match text-mode verification of legacy Windows CRLF records.
                line = line.rstrip(b"\r")
                if line:
                    return hashlib.sha256(line).hexdigest()
            fragment = lines[0]
        return "0" * 64

    # -- public API ------------------------------------------------------------

    def record(
        self,
        event_type: str,
        data: dict,
        block_number: int | None = None,
        tx_hash: str | None = None,
    ) -> None:
        """Append an audit record.

        Args:
            event_type: Category of the event (e.g. "proof_recorded", "credential_revoked").
            data: Arbitrary event payload.
            block_number: Ethereum block number (if applicable).
            tx_hash: Ethereum transaction hash (if applicable).
        """
        # Every writer derives the predecessor from the file while holding the
        # same lock through flush/fsync. No per-instance cached tail is trusted.
        with portalocker.Lock(self._path, "a+b", timeout=self._lock_timeout) as f:
            f.seek(0, 2)
            if f.tell():
                f.seek(-1, 2)
                if f.read(1) != b"\n":
                    raise ValueError("Audit mirror has an incomplete trailing record")
            entry = {
                "timestamp": time.time(),
                "event_type": event_type,
                "block_number": block_number,
                "tx_hash": tx_hash,
                "data": data,
                "prev_hash": self._read_tail_hash(f),
            }
            line = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode("utf-8")
            f.seek(0, 2)
            f.write(line + b"\n")
            f.flush()
            os.fsync(f.fileno())

        logger.debug("Audit mirror record appended (hash=%s)", hashlib.sha256(line).hexdigest()[:12])

    def verify_integrity(self) -> bool:
        """Verify the hash chain of the entire mirror file.

        Returns True if every record's prev_hash matches the SHA-256 of the
        preceding line. Returns True for an empty or missing file.
        """
        if not self._path.exists():
            return True

        prev_hash = "0" * 64
        try:
            with portalocker.Lock(self._path, "r", timeout=self._lock_timeout, encoding="utf-8") as f:
                for lineno, raw_line in enumerate(f, start=1):
                    raw_line = raw_line.rstrip("\n")
                    if not raw_line:
                        continue
                    try:
                        record = json.loads(raw_line)
                    except json.JSONDecodeError:
                        logger.error("Audit mirror integrity: malformed JSON at line %d", lineno)
                        return False

                    if record.get("prev_hash") != prev_hash:
                        logger.error("Audit mirror integrity: hash mismatch at line %d", lineno)
                        return False

                    prev_hash = hashlib.sha256(raw_line.encode()).hexdigest()
        except Exception:
            logger.exception("Audit mirror integrity check failed")
            return False

        return True
