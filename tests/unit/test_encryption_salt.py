"""Deployment salt and envelope context bind software AES-GCM derivation."""

import pytest
from cryptography.exceptions import InvalidTag

from src.sar.encryption import decrypt_pii, derive_key, encrypt_pii


def test_configured_salt_is_stable_and_separates_deployments(monkeypatch):
    master = b"synthetic-master-key-material-32!"
    monkeypatch.setenv("HKDF_SALT", "synthetic-deployment-a")
    key = derive_key(master, b"synthetic-envelope")
    assert len(key) == 32
    assert key == derive_key(master, b"synthetic-envelope")
    nonce, ciphertext = encrypt_pii(b"synthetic-private-payload", key, "synthetic-envelope")
    assert decrypt_pii(nonce, ciphertext, key, "synthetic-envelope") == b"synthetic-private-payload"
    monkeypatch.setenv("HKDF_SALT", "synthetic-deployment-b")
    other = derive_key(master, b"synthetic-envelope")
    assert other != key
    with pytest.raises(InvalidTag):
        decrypt_pii(nonce, ciphertext, other, "synthetic-envelope")
    monkeypatch.setenv("HKDF_SALT", "synthetic-deployment-a")
    assert derive_key(master, b"different-envelope") != key


@pytest.mark.parametrize("salt", [None, ""])
def test_missing_or_empty_salt_warns_and_preserves_legacy_derivation(monkeypatch, salt):
    if salt is None:
        monkeypatch.delenv("HKDF_SALT", raising=False)
    else:
        monkeypatch.setenv("HKDF_SALT", salt)
    with pytest.warns(UserWarning, match="HKDF_SALT environment variable is not set"):
        legacy = derive_key(b"a" * 32, b"synthetic-context")
    monkeypatch.setenv("HKDF_SALT", "zk-travel-rule-v1")
    assert derive_key(b"a" * 32, b"synthetic-context") == legacy
