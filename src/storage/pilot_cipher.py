"""Authenticated encryption for private tenant records, separate from recipient HPKE."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from types import MappingProxyType

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.protocol.canonical import canonical_bytes
from src.storage.keyring import KeyRing


class RecordIntegrityError(Exception):
    """Missing key, malformed ciphertext or authenticated metadata mismatch."""


class RecordCipher:
    def __init__(self, keyring: KeyRing):
        keys = {}
        for version in keyring.all_versions:
            key = bytes(version.key_bytes)
            if len(key) < 32:
                raise ValueError("Storage encryption keys require at least 32 bytes")
            keys[self.key_id(key)] = key
        self._active = self.key_id(bytes(keyring.active_key.key_bytes))
        if self._active not in keys:
            raise ValueError("Active storage key is unavailable")
        self._keys = MappingProxyType(keys)

    @staticmethod
    def key_id(key: bytes) -> str:
        return hashlib.sha256(b"clearproof/store-key-id/v1\0" + key).hexdigest()

    def _derive(self, key_id: str, tenant: str, purpose: str) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise RecordIntegrityError("Storage decryption key is unavailable")
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"clearproof/store/v1", info=canonical_bytes([tenant, purpose])
        ).derive(key)

    @staticmethod
    def _aad(tenant: str, kind: str, record_id: str, revision: int, key_id: str, tag: str) -> bytes:
        return canonical_bytes(["clearproof-store-v1", tenant, kind, record_id, revision, key_id, tag])

    def seal(self, tenant: str, kind: str, record_id: str, revision: int, value: dict) -> dict:
        if type(value) is not dict:
            raise ValueError("Stored record must be an object")
        plaintext = canonical_bytes(value)
        kid = self._active
        tag = hmac.new(self._derive(kid, tenant, "content-tag"), plaintext, hashlib.sha256).hexdigest()
        nonce = os.urandom(12)
        aad = self._aad(tenant, kind, record_id, revision, kid, tag)
        ciphertext = AESGCM(self._derive(kid, tenant, "encryption")).encrypt(nonce, plaintext, aad)
        return dict(key_id=kid, content_tag=tag, nonce=nonce, ciphertext=ciphertext)

    def open(self, tenant: str, kind: str, record_id: str, row: dict) -> dict:
        try:
            kid, tag = row["key_id"], row["content_tag"]
            aad = self._aad(tenant, kind, record_id, row["revision"], kid, tag)
            plaintext = AESGCM(self._derive(kid, tenant, "encryption")).decrypt(row["nonce"], row["ciphertext"], aad)
            expected = hmac.new(self._derive(kid, tenant, "content-tag"), plaintext, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, tag):
                raise RecordIntegrityError("Stored record content authentication failed")
            value = json.loads(plaintext)
            if type(value) is not dict or canonical_bytes(value) != plaintext:
                raise RecordIntegrityError("Stored record is not canonical")
            return value
        except (InvalidTag, ValueError, TypeError, KeyError) as exc:
            raise RecordIntegrityError("Stored record authentication failed") from exc
