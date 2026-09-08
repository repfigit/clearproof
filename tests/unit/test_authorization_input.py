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


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": 2},
        {"revision": None},
        {"ciphertext": "not-bytes"},
        {"ciphertext": b"x" * 15},
        {"ciphertext": b"x" * 65553},
    ],
)
def test_encrypted_input_rejects_invalid_outer_record(changes):
    sealed = SealedAuthorizationInformation.seal(
        cipher(), tenant_id="tenant-a", target_id="transfer-a", pii=b"synthetic", approval=approval()
    )
    changed = replace(sealed, row={**sealed.row, **changes})
    with pytest.raises(ValueError, match="Invalid encrypted authorization information"):
        changed.open(cipher(), tenant_id="tenant-a", target_id="transfer-a")


def encrypted_value(value):
    row = cipher().seal("tenant-a", "authorization-input", "transfer-a", 1, value)
    return SealedAuthorizationInformation({**row, "revision": 1})


def valid_value():
    return {
        "schema_version": "clearproof-authorization-input-v1",
        "payload_base64_chunks": ["YQ=="],
        "approval": approval().model_dump(mode="json"),
    }


@pytest.mark.parametrize("mutation", ["schema", "missing", "extra"])
def test_authenticated_input_requires_exact_supported_profile(mutation):
    value = valid_value()
    if mutation == "schema":
        value["schema_version"] = "unsupported"
    elif mutation == "missing":
        del value["approval"]
    else:
        value["unexpected"] = "synthetic"
    with pytest.raises(ValueError, match="Unsupported authorization information"):
        encrypted_value(value).open(cipher(), tenant_id="tenant-a", target_id="transfer-a")


@pytest.mark.parametrize(
    "chunks",
    [None, "YQ==", [], ["YQ=="] * 12, [False], [""], ["YQ==", "YQ=="]],
)
def test_authenticated_input_rejects_invalid_chunk_framing(chunks):
    value = {**valid_value(), "payload_base64_chunks": chunks}
    sealed = encrypted_value(value)
    with pytest.raises(ValueError, match="Invalid encrypted information chunks"):
        sealed.open(cipher(), tenant_id="tenant-a", target_id="transfer-a")


def test_authenticated_input_rejects_noncanonical_base64_pad_bits():
    # Both decode to b"a"; only YQ== has canonical zero padding bits.
    value = {**valid_value(), "payload_base64_chunks": ["YR=="]}
    with pytest.raises(ValueError, match="Noncanonical information encoding"):
        encrypted_value(value).open(cipher(), tenant_id="tenant-a", target_id="transfer-a")


def test_authenticated_input_rejects_decoded_size_beyond_limit():
    import base64

    encoded = base64.b64encode(b"x" * 32769).decode("ascii")
    chunks = [encoded[index : index + 4096] for index in range(0, len(encoded), 4096)]
    assert len(chunks) == 11
    value = {**valid_value(), "payload_base64_chunks": chunks}
    with pytest.raises(ValueError, match="Invalid authorization information size"):
        encrypted_value(value).open(cipher(), tenant_id="tenant-a", target_id="transfer-a")


@pytest.mark.parametrize("size", [1, 3072, 3073, 32768])
def test_authorization_input_round_trips_chunk_boundaries(size):
    private = b"s" * size  # Synthetic content only; no personal records.
    sealed = SealedAuthorizationInformation.seal(
        cipher(), tenant_id="tenant-a", target_id="transfer-a", pii=private, approval=approval()
    )
    assert sealed.open(cipher(), tenant_id="tenant-a", target_id="transfer-a") == (private, approval())


def test_oversized_chunk_is_rejected_before_encrypted_record_creation():
    value = {**valid_value(), "payload_base64_chunks": ["A" * 4097]}
    with pytest.raises(ValueError, match="Unsupported canonical record value"):
        encrypted_value(value)
