"""TAIP presentation serialization preserves proof claims and unsigned status."""

import json

import pytest

from src.protocol.bridges.taip10_bridge import TAIP10Bridge


@pytest.mark.parametrize(
    "generated,expires,issued_iso,expires_iso",
    [
        (0, 300, "1970-01-01T00:00:00+00:00", "1970-01-01T00:05:00+00:00"),
        (86400, 172800, "1970-01-02T00:00:00+00:00", "1970-01-03T00:00:00+00:00"),
    ],
)
def test_presentation_preserves_claims_and_utc_times(
    sample_compliance_proof, generated, expires, issued_iso, expires_iso
):
    signals = sample_compliance_proof.public_signals.copy()
    signals[1] = "1"
    proof = sample_compliance_proof.model_copy(
        update={
            "proof_generated_at": generated,
            "proof_expires_at": expires,
            "sar_review_flag": True,
            "public_signals": signals,
        }
    )
    before = proof.model_dump()
    issuer = "did:web:synthetic-issuer.example"
    presentation = TAIP10Bridge().build_verifiable_presentation(proof, issuer)
    assert presentation["holder"] == issuer
    assert presentation["type"] == ["VerifiablePresentation", "TravelRuleCompliance"]
    assert len(presentation["verifiableCredential"]) == 1
    credential = presentation["verifiableCredential"][0]
    assert credential["issuer"] == issuer
    assert credential["type"] == ["VerifiableCredential", "ZKComplianceProof"]
    assert credential["issuanceDate"] == issued_iso
    assert credential["expirationDate"] == expires_iso
    assert (
        credential["@context"]
        == presentation["@context"]
        == [
            "https://www.w3.org/2018/credentials/v1",
            "https://tap.rsvp/taip-10/v1",
        ]
    )
    assert credential["credentialSubject"] == {
        key: before[key]
        for key in (
            "proof_id",
            "transfer_id",
            "groth16_proof",
            "public_signals",
            "verification_key",
            "jurisdiction",
            "amount_tier",
        )
    }
    # Only the separate advisory metadata is omitted. Public signals are passed
    # through intact, so this test makes no claim of SAR-signal confidentiality.
    assert "sar_review_flag" not in credential["credentialSubject"]
    assert "encrypted_sar_payload" not in credential["credentialSubject"]
    assert presentation["proof"] == {
        "type": "Ed25519Signature2020",
        "created": issued_iso,
        "verificationMethod": issuer + "#key-1",
        "proofPurpose": "authentication",
        "proofValue": "",
    }
    assert json.loads(json.dumps(presentation)) == presentation
    assert proof.model_dump() == before
