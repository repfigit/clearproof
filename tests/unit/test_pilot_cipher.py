"""Storage AEAD binds all routing metadata and authenticates each revision."""

import pytest

from src.storage.keyring import KeyRing, KeyVersion
from src.storage.pilot_cipher import RecordCipher, RecordIntegrityError


def make_cipher(key=b"a" * 32):
    return RecordCipher(KeyRing(KeyVersion("v1", key, 0)))


@pytest.mark.parametrize(
    "field", ["tenant", "kind", "record_id", "revision", "key_id", "content_tag", "nonce", "ciphertext"]
)
def test_authenticated_metadata_and_ciphertext(field):
    cipher = make_cipher()
    args = {"tenant": "tenant-a", "kind": "credential", "record_id": "record-1"}
    row = {**cipher.seal(**args, revision=1, value={"private": "synthetic"}), "revision": 1}
    if field in args:
        args[field] = "changed"
    elif field == "revision":
        row[field] = 2
    elif field in ("key_id", "content_tag"):
        row[field] = "0" * 64
    else:
        row[field] = bytes([row[field][0] ^ 1]) + row[field][1:]
    with pytest.raises(RecordIntegrityError):
        cipher.open(**args, row=row)


def test_random_nonce_tenant_tags_and_copied_key_material():
    key = KeyVersion("v1", b"a" * 32, 0)
    ring = KeyRing(key)
    cipher = RecordCipher(ring)
    first = cipher.seal("tenant-a", "credential", "record-1", 1, {"x": 1})
    second = cipher.seal("tenant-a", "credential", "record-1", 1, {"x": 1})
    other = cipher.seal("tenant-b", "credential", "record-1", 1, {"x": 1})
    assert first["nonce"] != second["nonce"] and first["ciphertext"] != second["ciphertext"]
    assert first["content_tag"] == second["content_tag"] != other["content_tag"]
    key.key_bytes = b"b" * 32
    assert cipher.open("tenant-a", "credential", "record-1", {**first, "revision": 1}) == {"x": 1}
    with pytest.raises(ValueError):
        make_cipher(b"short")


@pytest.mark.parametrize("value", [None, [], "synthetic", 1])
def test_seal_requires_record_object(value):
    with pytest.raises(ValueError, match="^Stored record must be an object$"):
        make_cipher().seal("tenant-a", "credential", "record-1", 1, value)


def test_cipher_requires_active_key_in_inventory():
    from types import SimpleNamespace

    ring = SimpleNamespace(all_versions=[KeyVersion("old", b"a" * 32, 0)], active_key=KeyVersion("new", b"b" * 32, 1))
    with pytest.raises(ValueError, match="^Active storage key is unavailable$"):
        RecordCipher(ring)


@pytest.mark.parametrize("raw", [b"[]", b'{ "x": 1 }', b'{"x":1,"x":1}', b'{"z":1,"a":2}'])
def test_authenticated_but_noncanonical_plaintext_rejects(raw):
    row, cipher = authenticated_row(raw)
    with pytest.raises(RecordIntegrityError, match="^Stored record is not canonical$"):
        cipher.open("tenant-a", "credential", "record-1", row)


def authenticated_row(plaintext, *, wrong_tag=False):
    """Craft an AEAD-valid synthetic row to reach post-decryption integrity checks."""
    import hashlib
    import hmac

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    cipher = make_cipher()
    kid = cipher.key_id(b"a" * 32)
    tag = hmac.new(cipher._derive(kid, "tenant-a", "content-tag"), plaintext, hashlib.sha256).hexdigest()
    if wrong_tag:
        tag = "00" * 32
    nonce = b"synthetic-iv" + b"!"
    aad = cipher._aad("tenant-a", "credential", "record-1", 1, kid, tag)
    ciphertext = AESGCM(cipher._derive(kid, "tenant-a", "encryption")).encrypt(nonce, plaintext, aad)
    return dict(key_id=kid, content_tag=tag, nonce=nonce, ciphertext=ciphertext, revision=1), cipher


def test_content_tag_is_checked_even_for_authenticated_ciphertext():
    row, cipher = authenticated_row(b'{"x":1}', wrong_tag=True)
    with pytest.raises(RecordIntegrityError, match="^Stored record content authentication failed$"):
        cipher.open("tenant-a", "credential", "record-1", row)


@pytest.mark.parametrize("raw", [b"{", b"\xff"])
def test_authenticated_invalid_json_fails_with_bounded_error(raw):
    row, cipher = authenticated_row(raw)
    with pytest.raises(RecordIntegrityError, match="^Stored record authentication failed$"):
        cipher.open("tenant-a", "credential", "record-1", row)
