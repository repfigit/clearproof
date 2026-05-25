"""
PII encryption key rotation support.

Manages a set of active and retired encryption keys with version IDs.
Only the latest key is used for encryption; all active keys are used for decryption.
Keys are stored as environment variables keyed by version ID.

Configuration:
  PII_MASTER_KEY       — Current active key (required)
  PII_ROTATED_KEYS     — Comma-separated list of rotated key version IDs (optional)
  PII_KEY_1, PII_KEY_2 — Encrypted key material for each version ID
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)


class KeyVersion:
    version_id: str
    key_bytes: bytes
    activated_at: int
    retired: bool

    def __init__(self, version_id: str, key_bytes: bytes, activated_at: int, retired: bool = False) -> None:
        self.version_id = version_id
        self.key_bytes = key_bytes
        self.activated_at = activated_at
        self.retired = retired

    @property
    def is_active(self) -> bool:
        return not self.retired

    @property
    def is_expired(self) -> bool:
        return int(time.time()) - self.activated_at > 86400 * 90

    def to_dict(self) -> dict:
        return {
            "version_id": self.version_id,
            "activated_at": self.activated_at,
            "retired": self.retired,
            "is_expired": self.is_expired,
        }


class KeyRing:
    def __init__(self, active_key: KeyVersion, rotated_keys: Optional[list[KeyVersion]] = None) -> None:
        self._active = active_key
        self._versions: dict[str, KeyVersion] = {active_key.version_id: active_key}
        for k in rotated_keys or []:
            self._versions[k.version_id] = k

    @property
    def active_key(self) -> KeyVersion:
        return self._active

    @property
    def active_versions(self) -> list[KeyVersion]:
        return [v for v in self._versions.values() if v.is_active and not v.is_expired]

    @property
    def all_versions(self) -> list[KeyVersion]:
        return list(self._versions.values())

    def get_key(self, version_id: str) -> Optional[KeyVersion]:
        return self._versions.get(version_id)

    def add_version(self, key: KeyVersion) -> None:
        self._versions[key.version_id] = key
        if key.is_active:
            self._active = key

    def retire_version(self, version_id: str) -> bool:
        key = self._versions.get(version_id)
        if key and not key.retired and not key.is_expired:
            key.retired = True
            return True
        return False

    def cleanup_expired(self) -> int:
        removed = 0
        for v in list(self._versions.values()):
            if v.is_expired and v.retired:
                del self._versions[v.version_id]
                removed += 1
        return removed


def load_keyring() -> KeyRing:
    active_key_hex = os.environ.get("PII_MASTER_KEY", "")
    if not active_key_hex:
        raise RuntimeError("PII_MASTER_KEY environment variable is required")

    is_valid_hex = len(active_key_hex) == 64
    if is_valid_hex:
        try:
            active_bytes = bytes.fromhex(active_key_hex)
        except ValueError:
            is_valid_hex = False
    is_valid_utf8 = len(active_key_hex.encode("utf-8")) >= 32
    if not is_valid_hex and not is_valid_utf8:
        raise RuntimeError(
            "PII_MASTER_KEY does not meet minimum entropy requirements. "
            "Provide either exactly 64 hex characters (32 bytes decoded) "
            "or a value that is at least 32 bytes when UTF-8 encoded."
        )

    active_key = KeyVersion(
        version_id="v1",
        key_bytes=active_key_hex.encode("utf-8") if not is_valid_hex else active_bytes,
        activated_at=int(time.time()),
    )

    rotated = []
    rotated_ids = os.environ.get("PII_ROTATED_KEYS", "")
    if rotated_ids:
        for vid in rotated_ids.split(","):
            vid = vid.strip()
            if not vid:
                continue
            key_var = f"PII_KEY_{vid}"
            key_hex = os.environ.get(key_var, "")
            if not key_hex:
                logger.warning("Rotated key %s not found in environment", vid)
                continue
            is_hex = len(key_hex) == 64
            if is_hex:
                try:
                    key_bytes = bytes.fromhex(key_hex)
                except ValueError:
                    key_bytes = key_hex.encode("utf-8")
            else:
                key_bytes = key_hex.encode("utf-8")
            rotated.append(
                KeyVersion(
                    version_id=vid,
                    key_bytes=key_bytes,
                    activated_at=int(time.time()),
                )
            )

    return KeyRing(active_key, rotated if rotated else None)


def derive_key_id(key: bytes) -> str:
    return "key_" + hashlib.sha256(key).hexdigest()[:16]
