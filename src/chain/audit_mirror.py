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

logger = logging.getLogger(__name__)


class AuditMirror:
    """Append-only audit mirror with hash-chain integrity."""

    def __init__(self, path: str | None = None) -> None:
        self._path = Path(
            path or os.environ.get("AUDIT_MIRROR_PATH", "./audit/mirror.jsonl")
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash: str = self._compute_tail_hash()

    # -- internal helpers ------------------------------------------------------

    def _compute_tail_hash(self) -> str:
        """Read the last line of the mirror file and return its hash.

        Returns the zero hash if the file is empty or does not exist.
        """
        zero_hash = "0" * 64
        if not self._path.exists():
            return zero_hash
        try:
            with open(self._path, "rb") as f:
                # Seek to find last non-empty line
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return zero_hash
                # Read last chunk (up to 4 KB is more than enough for one JSON line)
                chunk_size = min(4096, size)
                f.seek(size - chunk_size)
                chunk = f.read()
                lines = chunk.strip().split(b"\n")
                last_line = lines[-1]
                return hashlib.sha256(last_line).hexdigest()
        except Exception:
            logger.warning("Could not read audit mirror tail; starting fresh hash chain")
            return zero_hash

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
        entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "block_number": block_number,
            "tx_hash": tx_hash,
            "data": data,
            "prev_hash": self._prev_hash,
        }
        line = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        self._prev_hash = hashlib.sha256(line.encode()).hexdigest()

        with open(self._path, "a") as f:
            f.write(line + "\n")

        logger.debug("Audit mirror: %s recorded (hash=%s)", event_type, self._prev_hash[:12])

    def verify_integrity(self) -> bool:
        """Verify the hash chain of the entire mirror file.

        Returns True if every record's prev_hash matches the SHA-256 of the
        preceding line. Returns True for an empty or missing file.
        """
        if not self._path.exists():
            return True

        prev_hash = "0" * 64
        try:
            with open(self._path, "r") as f:
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
                        logger.error(
                            "Audit mirror integrity: hash mismatch at line %d "
                            "(expected %s, got %s)",
                            lineno,
                            prev_hash[:12],
                            record.get("prev_hash", "")[:12],
                        )
                        return False

                    prev_hash = hashlib.sha256(raw_line.encode()).hexdigest()
        except Exception:
            logger.exception("Audit mirror integrity check failed")
            return False

        return True
