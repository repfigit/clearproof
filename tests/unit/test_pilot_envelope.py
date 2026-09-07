"""Synthetic recipient authority, real HPKE and independent metadata checks."""

import copy
import json
from pathlib import Path

import pytest

from src.protocol.transfer import Transfer, VerificationContext
from src.sar.hpke_envelope import generate_keypair
from src.sar.pilot_envelope import (
    RecipientAuthority,
    RecipientTrustStore,
    open_pilot_envelope,
    seal_pilot_envelope,
)


@pytest.fixture
def case():
    fixture = json.loads((Path(__file__).parents[2] / "specs/fixtures/transfer-v1.json").read_text())
    value = fixture["records"][0]["value"]
    transfer = Transfer.model_validate(
        {
            **value,
            "beneficiary": {**value["beneficiary"], "kind": "vasp", "vasp_did": "did:web:recipient.example"},
        }
    )
    context = VerificationContext.model_validate(
        {
            **fixture["records"][1]["value"],
            "transfer_digest": transfer.digest,
        }
    )
    now = context.evaluated_at
    private, public = generate_keypair()
    authority = RecipientAuthority(
        tenant_id=transfer.tenant_id,
        chain_id=int(context.deployment_chain_id),
        registry_address=context.deployment_address,
        recipient_did=transfer.beneficiary.vasp_did,
        public_key=public.hex(),
        not_before=now,
        not_after=now + 60,
    )
    binding = {
        "tenant_id": transfer.tenant_id,
        "transfer_digest": transfer.digest,
        "context_digest": context.digest,
        "proof_digest": "ab" * 32,
        "recipient_did": authority.recipient_did,
        "recipient_key_id": authority.key_id,
        "sealed_at": now,
    }
    return transfer, context, now, private, authority, binding


def sealed(case):
    transfer, context, now, _, authority, _ = case
    return seal_pilot_envelope(
        b"synthetic-information-only",
        RecipientTrustStore([authority]),
        authority.key_id,
        transfer,
        context,
        proof_digest="ab" * 32,
        now=now,
    )


def test_roundtrip_and_rotation_overlap(case):
    transfer, context, now, private, authority, binding = case
    envelope = sealed(case)
    assert open_pilot_envelope(envelope, private, expected_binding=binding) == b"synthetic-information-only"
    other_private, public = generate_keypair()
    other = RecipientAuthority.model_validate({**authority.model_dump(), "public_key": public.hex()})
    trust = RecipientTrustStore([authority, other])
    rotated = seal_pilot_envelope(
        b"synthetic-information-only",
        trust,
        other.key_id,
        transfer,
        context,
        proof_digest="ab" * 32,
        now=now,
    )
    assert (
        open_pilot_envelope(
            rotated,
            other_private,
            expected_binding={**binding, "recipient_key_id": other.key_id},
        )
        == b"synthetic-information-only"
    )
    with pytest.raises(ValueError):
        open_pilot_envelope(envelope, other_private, expected_binding=binding)
    with pytest.raises(ValueError):
        RecipientTrustStore([other]).select(authority.key_id, transfer, context, now=now)
    assert open_pilot_envelope(envelope, private, expected_binding=binding) == b"synthetic-information-only"


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "foreign"),
        ("chain_id", 999),
        ("registry_address", "0x" + "99" * 20),
        ("recipient_did", "did:web:other.example"),
    ],
)
def test_authority_scope_rejects(case, field, value):
    transfer, context, now, _, authority, _ = case
    bad = RecipientAuthority.model_validate({**authority.model_dump(), field: value})
    with pytest.raises(ValueError, match="authority"):
        seal_pilot_envelope(
            b"synthetic", RecipientTrustStore([bad]), bad.key_id, transfer, context, proof_digest="ab" * 32, now=now
        )


@pytest.mark.parametrize("offset", [-1, 60])
def test_key_validity_rejects(case, offset):
    transfer, context, now, _, authority, _ = case
    with pytest.raises(ValueError, match="authority"):
        RecipientTrustStore([authority]).select(authority.key_id, transfer, context, now=now + offset)


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "transfer_digest",
        "context_digest",
        "proof_digest",
        "recipient_did",
        "recipient_key_id",
        "sealed_at",
    ],
)
def test_binding_substitution_rejects(case, field):
    _, _, _, private, _, binding = case
    envelope = sealed(case)
    changed = copy.deepcopy(envelope)
    changed["binding"][field] = "substituted"
    with pytest.raises(ValueError):
        open_pilot_envelope(changed, private, expected_binding=binding)
    with pytest.raises(ValueError):
        open_pilot_envelope(envelope, private, expected_binding={**binding, field: "substituted"})


@pytest.mark.parametrize("field", ["kid", "aad", "ct_chunks", "enc", "kem", "kdf", "aead", "v"])
def test_hpke_metadata_and_ciphertext_tamper(case, field):
    _, _, _, private, _, binding = case
    envelope = sealed(case)
    envelope["hpke"][field] = "invalid"
    with pytest.raises(ValueError):
        open_pilot_envelope(envelope, private, expected_binding=binding)


def test_no_key_or_plaintext_fallback(case):
    transfer, context, now, _, authority, _ = case
    with pytest.raises(ValueError):
        RecipientAuthority.model_validate({**authority.model_dump(), "public_key": "00" * 32})
    for plaintext in (b"", b"x" * 32769, "synthetic"):
        with pytest.raises(ValueError):
            seal_pilot_envelope(
                plaintext,
                RecipientTrustStore([authority]),
                authority.key_id,
                transfer,
                context,
                proof_digest="ab" * 32,
                now=now,
            )


def test_bounded_payload_digest_and_valid_base64_tamper(case):
    from src.protocol.canonical import record_digest

    transfer, context, now, private, authority, binding = case
    envelope = seal_pilot_envelope(
        b"x" * 32768,
        RecipientTrustStore([authority]),
        authority.key_id,
        transfer,
        context,
        proof_digest="ab" * 32,
        now=now,
    )
    assert len(record_digest("clearproof/pilot-envelope/v1", envelope)) == 64
    assert open_pilot_envelope(envelope, private, expected_binding=binding) == b"x" * 32768
    chunks = envelope["hpke"]["ct_chunks"]
    chunks[0] = ("A" if chunks[0][0] != "A" else "B") + chunks[0][1:]
    with pytest.raises(ValueError, match="decryption failed"):
        open_pilot_envelope(envelope, private, expected_binding=binding)
