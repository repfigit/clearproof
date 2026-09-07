"""Encrypted operator input is scoped before authorization signature validation."""

from dataclasses import replace

import pytest

from src.protocol.information_approval import InformationApproval, SignedInformationApproval
from src.services.authorization_input import SealedAuthorizationInformation
from src.storage.keyring import KeyRing, KeyVersion
from src.storage.pilot_cipher import RecordCipher, RecordIntegrityError


def cipher(key=b"a" * 32):
    return RecordCipher(KeyRing(KeyVersion("current", key, 0)))


def approval():
    return SignedInformationApproval(
        approval=InformationApproval(
            tenant_id="tenant-a",
            transfer_digest="aa" * 32,
            context_digest="bb" * 32,
            credential_id="cc" * 32,
            payload_digest="dd" * 32,
            source_id="synthetic",
            source_evidence_digest="ee" * 32,
            signed_at=1000,
            expires_at=2000,
            key_id="ff" * 32,
        ),
        signature="00" * 64,
    )  # Deliberately unverified; seal must not imply approval.


def test_encrypted_input_roundtrip_scope_and_key_rotation():
    private = b"synthetic private input".ljust(32768, b" ")
    sealed = SealedAuthorizationInformation.seal(
        cipher(),
        tenant_id="tenant-a",
        target_id="transfer-a",
        pii=private,
        approval=approval(),
    )
    raw, signed = sealed.open(cipher(), tenant_id="tenant-a", target_id="transfer-a")
    assert raw == private and signed == approval()
    assert private not in sealed.row["ciphertext"] and "synthetic" not in repr(sealed)
    for tenant, target, key in [
        ("foreign", "transfer-a", b"a" * 32),
        ("tenant-a", "transfer-b", b"a" * 32),
        ("tenant-a", "transfer-a", b"b" * 32),
    ]:
        with pytest.raises(RecordIntegrityError):
            sealed.open(cipher(key), tenant_id=tenant, target_id=target)
    rotated = RecordCipher(KeyRing(KeyVersion("new", b"b" * 32, 1), [KeyVersion("old", b"a" * 32, 0)]))
    assert sealed.open(rotated, tenant_id="tenant-a", target_id="transfer-a")[0] == private
    changed = replace(sealed, row={**sealed.row, "ciphertext": b"x" * len(sealed.row["ciphertext"])})
    with pytest.raises(RecordIntegrityError):
        changed.open(cipher(), tenant_id="tenant-a", target_id="transfer-a")


def test_operator_input_bounds_and_profile_reject():
    for private in (b"", b"x" * 32769, "unencoded"):
        with pytest.raises(ValueError):
            SealedAuthorizationInformation.seal(
                cipher(),
                tenant_id="tenant-a",
                target_id="transfer-a",
                pii=private,
                approval=approval(),
            )
    row = cipher().seal("tenant-a", "authorization-input", "transfer-a", 1, {"schema_version": "unknown"})
    with pytest.raises(ValueError):
        SealedAuthorizationInformation({**row, "revision": 1}).open(
            cipher(),
            tenant_id="tenant-a",
            target_id="transfer-a",
        )
