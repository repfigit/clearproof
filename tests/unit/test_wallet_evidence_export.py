"""Evidence export renders stored attestations into supervisor-readable records."""

import pytest

from src.services.wallet_evidence_export import eba_limb_for, export_evidence

LIMB_D_QUOTE = (
    "requesting the customer to digitally sign a specific message into the account and wallet software with the "
    "key corresponding to that address;"
)
LIMB_E_QUOTE = (
    "other suitable technical means as long as they allow for reliable and secure assessment and the CASP is "
    "fully satisfied that it knows who owns or controls the address."
)


def v1_attestation():
    return {
        "schema_version": "clearproof-wallet-attestation-v1",
        "attestation_id": "cd" * 32,
        "challenge": {
            "schema_version": "clearproof-wallet-challenge-v1",
            "tenant_id": "tenant-1",
            "actor_id": "actor-1",
            "credential": {
                "schema_version": "clearproof-credential-v1",
                "tenant_id": "tenant-1",
                "credential_nonce": "ab" * 32,
                "issuer_did": "did:web:issuer.example",
                "subject_wallet": "0x" + "11" * 20,
                "holder_commitment": "123456789",
                "jurisdiction": "DE",
                "kyc_tier": 2,
                "sanctions_clear": True,
                "issued_at": 900,
                "expires_at": 90000,
            },
            "chain_id": 1,
            "registry_address": "0x" + "22" * 20,
            "nonce": "cd" * 32,
            "timestamp": 1100,
            "expires_at": 1400,
        },
        "signature": "0x" + "5e" * 65,
        "issued_at": 1200,
        "expires_at": 88800,
    }


def v2_attestation():
    return {
        **v1_attestation(),
        "schema_version": "clearproof-wallet-attestation-v2",
        "verification_method": "eoa",
        "siwe_message": "example.com wants you to sign in with your Ethereum account:\n0x" + "11" * 20,
        "delegation_status": None,
    }


def delegation_history():
    return [
        {"checked_at": 1000, "delegated": False, "delegate": None, "reason": "no 7702 delegation at check"},
        {"checked_at": 2000, "delegated": True, "delegate": "0x" + "33" * 20, "reason": "7702 delegate set"},
    ]


def test_v1_exports_eoa_with_private_key_limb():
    record = export_evidence(v1_attestation())
    assert record["record_version"] == "clearproof-evidence-export-v1"
    assert record["schema_version"] == "clearproof-wallet-attestation-v1"
    assert record["subject_address"] == "0x" + "11" * 20
    assert record["verification_method"] == "eoa"
    assert record["eba_limb"]["paragraph"] == "83(d)"
    assert record["eba_limb"]["quote"] == LIMB_D_QUOTE
    assert record["signature"] == "0x" + "5e" * 65
    assert record["challenge_issued_at"] == 1100
    assert record["challenge_expires_at"] == 1400
    assert record["verified_at"] == 1200
    assert record["attestation_expires_at"] == 88800
    # A v1 record stores no rendered message text; the exporter must not fabricate one.
    assert record["challenge"] is None
    assert record["generated_at"] is None


def test_v2_with_siwe_message_and_delegation_history_exports_all_sections():
    record = export_evidence(v2_attestation(), delegation_history=delegation_history())
    assert record["challenge"] == v2_attestation()["siwe_message"]
    assert record["verification_method"] == "eoa"
    assert record["eba_limb"]["paragraph"] == "83(d)"
    assert record["delegation"]["history"] == delegation_history()
    assert record["delegation"]["status"]["delegated"] is True
    assert record["delegation"]["status"]["checked_at"] == 2000
    assert record["delegation"]["status"]["delegate"] == "0x" + "33" * 20
    assert record["delegation"]["recorded_status"] is None
    assert record["credential"]["credential_nonce"] == "ab" * 32
    assert record["credential"]["issuer_did"] == "did:web:issuer.example"
    assert record["tenant_id"] == "tenant-1" and record["actor_id"] == "actor-1"
    assert record["chain_id"] == 1 and record["registry_address"] == "0x" + "22" * 20


@pytest.mark.parametrize("method", ["erc-1271", "erc-6492", "ERC-1271"])
def test_contract_wallet_methods_map_to_other_suitable_means_limb(method):
    limb = eba_limb_for(method)
    assert limb["paragraph"] == "83(e)"
    assert limb["quote"] == LIMB_E_QUOTE
    assert "uncertain" in limb["note"]


def test_delegation_history_out_of_order_uses_newest_checked_at_as_status():
    history = list(reversed(delegation_history()))
    record = export_evidence(v2_attestation(), delegation_history=history)
    assert record["delegation"]["status"]["checked_at"] == 2000
    assert [entry["checked_at"] for entry in record["delegation"]["history"]] == [2000, 1000]


def test_absent_delegation_history_exports_null_section_not_fabrication():
    record = export_evidence(v1_attestation(), delegation_history=None)
    assert record["delegation"] is None


def test_credential_ref_is_linked_not_merged():
    reference = {"credential_id": "ab" * 32, "extension_commitment": "42"}
    record = export_evidence(v1_attestation(), credential_ref=reference)
    assert record["credential"]["reference"] == reference
    assert record["credential"]["credential_nonce"] == "ab" * 32


@pytest.mark.parametrize("method", ["satoshi-test", "screen-recording", ""])
def test_unknown_verification_method_raises(method):
    with pytest.raises(ValueError, match="Unknown wallet verification method"):
        eba_limb_for(method)
    attestation = {**v2_attestation(), "verification_method": method}
    with pytest.raises(ValueError, match="Unknown wallet verification method"):
        export_evidence(attestation)


def test_non_string_method_raises():
    with pytest.raises(ValueError, match="must be a string"):
        eba_limb_for(83)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda a: a.pop("schema_version"),
        lambda a: a.update({"schema_version": "clearproof-wallet-attestation-v3"}),
        lambda a: a.pop("challenge"),
        lambda a: a["challenge"].pop("credential"),
        lambda a: a["challenge"]["credential"].pop("subject_wallet"),
        lambda a: a["challenge"]["credential"].update({"subject_wallet": ""}),
        lambda a: a.pop("signature"),
        lambda a: a.update({"signature": "0x" + "5E" * 65}),
        lambda a: a.update({"signature": "0x" + "5e" * 64}),
        lambda a: a.pop("issued_at"),
        lambda a: a.update({"issued_at": "1200"}),
        lambda a: a["challenge"].update({"timestamp": None}),
    ],
)
def test_malformed_attestations_fail_closed(mutate):
    with pytest.raises(ValueError):
        export_evidence(mutate(v1_attestation()))


def test_v2_without_method_fails_closed_rather_than_guessing():
    attestation = v2_attestation()
    for key in ("verification_method", "method", "wallet_verification_method"):
        attestation.pop(key, None)
    with pytest.raises(ValueError, match="verification method"):
        export_evidence(attestation)


@pytest.mark.parametrize(
    "entry",
    ["not-a-dict", {}, {"checked_at": "2000", "delegated": True}, {"checked_at": 2000, "delegated": "yes"}],
)
def test_malformed_delegation_history_entries_fail_closed(entry):
    with pytest.raises(ValueError, match="[Dd]elegation history"):
        export_evidence(v2_attestation(), delegation_history=[entry])


def test_delegation_history_rejects_non_list():
    with pytest.raises(ValueError, match="must be a list"):
        export_evidence(v2_attestation(), delegation_history={"checked_at": 2000})


def test_delegation_history_normalizes_delegate_and_reason_types():
    exported = export_evidence(
        v2_attestation(),
        delegation_history=[
            {"checked_at": 2000, "delegated": True, "delegate": "0x" + "3" * 40, "reason": "malformed indicator"},
            {"checked_at": 1000, "delegated": False},
        ],
    )
    assert exported["delegation"]["status"]["delegate"] == "0x" + "3" * 40
    with pytest.raises(ValueError, match="boolean delegated"):
        export_evidence(v2_attestation(), delegation_history=[{"checked_at": 2000, "delegated": "yes"}])
    with pytest.raises(ValueError, match="string or null delegate"):
        export_evidence(v2_attestation(), delegation_history=[{"checked_at": 2000, "delegated": True, "delegate": 1}])


def test_v1_method_defaults_to_eoa_when_omitted():
    attestation = v1_attestation()
    attestation.pop("verification_method", None)
    exported = export_evidence(attestation)
    assert exported["eba_limb"]["paragraph"] == "83(d)"


def test_non_dict_attestation_and_credential_ref_fail_closed():
    with pytest.raises(ValueError, match="must be an object"):
        export_evidence("attestation")
    with pytest.raises(ValueError, match="must be an object"):
        export_evidence(v1_attestation(), credential_ref=["cb" * 32])
