"""Malformed jurisdiction signals cannot establish a VASP jurisdiction match."""

import pytest

from src.prover.tier_mapping import encode_jurisdiction, jurisdiction_matches_vasp


@pytest.mark.parametrize("length", [0, 6, 15])
def test_jurisdiction_match_requires_complete_signal_inventory(sample_compliance_proof, length):
    assert not jurisdiction_matches_vasp(sample_compliance_proof.public_signals[:length], "US")


@pytest.mark.parametrize("value", [None, "not-decimal", float("inf"), float("nan"), "-1", "65536", "0", "30067"])
def test_jurisdiction_match_rejects_invalid_numeric_or_ascii_encoding(sample_compliance_proof, value):
    signals = list(sample_compliance_proof.public_signals)
    signals[6] = value
    assert not jurisdiction_matches_vasp(signals, "US")


def test_jurisdiction_match_compares_expected_identity_case_insensitively(sample_compliance_proof):
    signals = list(sample_compliance_proof.public_signals)
    signals[6] = str(encode_jurisdiction("US"))
    assert jurisdiction_matches_vasp(signals, "us")
    assert not jurisdiction_matches_vasp(signals, "EU")


@pytest.mark.parametrize("length", [0, 10, 15])
def test_threshold_match_requires_complete_signal_inventory(sample_compliance_proof, length):
    from src.prover.tier_mapping import thresholds_match_jurisdiction

    assert not thresholds_match_jurisdiction(sample_compliance_proof.public_signals[:length])


@pytest.mark.parametrize("index,value", [(6, None), (6, "bad"), (6, "-1"), (6, "0"), (8, None), (9, "bad")])
def test_threshold_match_rejects_malformed_jurisdiction_or_threshold(sample_compliance_proof, index, value):
    from src.prover.tier_mapping import thresholds_match_jurisdiction

    signals = list(sample_compliance_proof.public_signals)
    signals[6] = str(encode_jurisdiction("US"))
    signals[index] = value
    assert not thresholds_match_jurisdiction(signals)
