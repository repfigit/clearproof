"""Deployment salt and envelope context bind software AES-GCM derivation."""

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


@pytest.mark.parametrize("salt", [None, "", "  "])
@pytest.mark.parametrize("opt_in", [None, "", "0", "true"])
def test_missing_salt_fails_closed_without_exact_opt_in(monkeypatch, salt, opt_in):
    if salt is None:
        monkeypatch.delenv("HKDF_SALT", raising=False)
    else:
        monkeypatch.setenv("HKDF_SALT", salt)
    if opt_in is None:
        monkeypatch.delenv("ALLOW_INSECURE_HKDF_SALT", raising=False)
    else:
        monkeypatch.setenv("ALLOW_INSECURE_HKDF_SALT", opt_in)
    with pytest.raises(RuntimeError, match="HKDF_SALT is required"):
        derive_key(b"a" * 32, b"synthetic-context")


def test_explicit_demo_opt_in_and_operator_migration_preserve_retained_ciphertext(monkeypatch):
    master, context = b"a" * 32, b"synthetic-context"
    historical = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"zk-travel-rule-v1", info=context).derive(master)
    nonce, ciphertext = encrypt_pii(b"synthetic-retained-payload", historical, "synthetic-envelope")
    monkeypatch.delenv("HKDF_SALT", raising=False)
    monkeypatch.setenv("ALLOW_INSECURE_HKDF_SALT", "1")
    assert derive_key(master, context) == historical
    assert (
        decrypt_pii(nonce, ciphertext, derive_key(master, context), "synthetic-envelope")
        == b"synthetic-retained-payload"
    )
    monkeypatch.delenv("ALLOW_INSECURE_HKDF_SALT")
    monkeypatch.setenv("HKDF_SALT", "zk-travel-rule-v1")
    assert (
        decrypt_pii(nonce, ciphertext, derive_key(master, context), "synthetic-envelope")
        == b"synthetic-retained-payload"
    )


@pytest.mark.parametrize("salt", ["ab" * 32, "é-synthetic-salt", "  preserved-padding  "])
def test_configured_salt_keeps_utf8_encoding_and_takes_precedence_over_demo_opt_in(monkeypatch, salt):
    monkeypatch.setenv("HKDF_SALT", salt)
    monkeypatch.setenv("ALLOW_INSECURE_HKDF_SALT", "1")
    expected = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt.encode("utf-8"), info=b"context").derive(b"a" * 32)
    assert derive_key(b"a" * 32, b"context") == expected
