"""Key rotation lifecycle and environment parsing without disclosing key material."""

import hashlib

import pytest

from src.storage import keyring as module
from src.storage.pilot_cipher import RecordCipher


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    for name in list(module.os.environ):
        if name.startswith("PII_KEY_") or name in ("PII_MASTER_KEY", "PII_ROTATED_KEYS"):
            monkeypatch.delenv(name)
    monkeypatch.setattr(module.time, "time", lambda: 10_000_000)


def version(name="current", key=b"a" * 32, *, age=0, retired=False):
    return module.KeyVersion(name, key, 10_000_000 - age, retired)


def test_metadata_expiry_and_key_identifier_never_include_material():
    key = version(age=86400 * 90 + 1)
    assert key.is_active and key.is_expired
    assert version(age=86400 * 90).is_expired is False
    assert key.to_dict() == {
        "version_id": "current",
        "activated_at": key.activated_at,
        "retired": False,
        "is_expired": True,
    }
    assert "key_bytes" not in key.to_dict()
    assert module.derive_key_id(key.key_bytes) == "key_" + hashlib.sha256(key.key_bytes).hexdigest()[:16]


def test_rotation_retirement_and_expired_cleanup_preserve_current_key():
    current, old, expired = version(), version("old", b"b" * 32), version("expired", b"c" * 32, age=86400 * 91)
    ring = module.KeyRing(current, [old, expired])
    assert ring.active_versions == [current, old]
    assert ring.all_versions == [current, old, expired]
    assert ring.get_key("missing") is None
    assert ring.get_key("old") is old
    assert ring.retire_version("missing") is False
    assert ring.retire_version("expired") is False
    assert ring.retire_version("old") is True
    assert ring.retire_version("old") is False
    assert ring.cleanup_expired() == 0
    retired = version("retired", b"d" * 32, age=86400 * 91, retired=True)
    ring.add_version(retired)
    assert ring.active_key is current
    assert ring.cleanup_expired() == 1
    assert ring.get_key("retired") is None
    replacement = version("replacement", b"e" * 32)
    ring.add_version(replacement)
    assert ring.active_key is replacement
    assert ring.retire_version("current") is True
    assert ring.active_versions == [replacement]


def test_rotation_retains_decryption_of_existing_encrypted_records():
    old = version("old")
    ring = module.KeyRing(old)
    encrypted = RecordCipher(ring).seal("tenant", "credential", "record", 1, {"synthetic": "payload"})
    ring.add_version(version("new", b"b" * 32))
    assert ring.retire_version("old") is True
    cipher = RecordCipher(ring)
    assert cipher.open("tenant", "credential", "record", {**encrypted, "revision": 1}) == {"synthetic": "payload"}
    assert cipher.seal("tenant", "credential", "record", 2, {})["key_id"] != encrypted["key_id"]


def test_active_version_cannot_be_retired_without_a_replacement():
    current = version()
    ring = module.KeyRing(current)
    assert ring.retire_version("current") is False
    assert current.is_active


def test_duplicate_version_ids_cannot_discard_retained_keys():
    current = version()
    conflicting = version(key=b"b" * 32)
    with pytest.raises(ValueError, match="Duplicate"):
        module.KeyRing(current, [conflicting])
    ring = module.KeyRing(current)
    with pytest.raises(ValueError, match="Duplicate"):
        ring.add_version(conflicting)
    assert ring.active_key is current
    assert ring.get_key("current") is current


@pytest.mark.parametrize(
    "value,expected", [("ab" * 32, bytes.fromhex("ab" * 32)), ("z" * 64, b"z" * 64), ("é" * 16, ("é" * 16).encode())]
)
def test_current_key_accepts_documented_hex_and_utf8_forms(monkeypatch, value, expected):
    monkeypatch.setenv("PII_MASTER_KEY", value)
    assert module.load_keyring().active_key.key_bytes == expected


@pytest.mark.parametrize("value", [None, "short"])
def test_missing_and_short_current_keys_fail(monkeypatch, value):
    if value is not None:
        monkeypatch.setenv("PII_MASTER_KEY", value)
    with pytest.raises(RuntimeError):
        module.load_keyring()


def test_rotated_key_forms_whitespace_and_missing_entries(monkeypatch, caplog):
    monkeypatch.setenv("PII_MASTER_KEY", "ab" * 32)
    monkeypatch.setenv("PII_ROTATED_KEYS", "hex, , utf8, long, missing")
    monkeypatch.setenv("PII_KEY_hex", "cd" * 32)
    monkeypatch.setenv("PII_KEY_utf8", "x" * 32)
    monkeypatch.setenv("PII_KEY_long", "z" * 64)
    ring = module.load_keyring()
    assert ring.get_key("hex").key_bytes == bytes.fromhex("cd" * 32)
    assert ring.get_key("utf8").key_bytes == b"x" * 32
    assert ring.get_key("long").key_bytes == b"z" * 64
    assert ring.get_key("missing") is None
    assert "missing" in caplog.text
    assert "cd" * 32 not in caplog.text
