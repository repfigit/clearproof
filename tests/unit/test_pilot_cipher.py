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
