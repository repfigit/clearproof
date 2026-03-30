"""
Compliance tests for threshold tier mapping.

Thin wrappers that re-export tier tests from the unit test suite
to ensure compliance test coverage includes tier boundary verification.
"""

from __future__ import annotations

import pytest

from src.prover.tier_mapping import compute_tier, JURISDICTION_TIERS


class TestComplianceThresholdTiers:
    """Verify tier boundaries match regulatory thresholds per jurisdiction."""

    @pytest.mark.parametrize(
        "jurisdiction,amount,expected_tier",
        [
            # US (FinCEN BSA / GENIUS Act)
            ("US", 249, 1),
            ("US", 250, 2),
            ("US", 2999, 2),
            ("US", 3000, 3),
            ("US", 9999, 3),
            ("US", 10000, 4),
            # EU (MiCA TFR)
            ("EU", 249, 1),
            ("EU", 250, 2),
            ("EU", 999, 2),
            ("EU", 1000, 3),
            ("EU", 9999, 3),
            ("EU", 10000, 4),
            # SG (MAS Payment Services Act)
            ("SG", 249, 1),
            ("SG", 250, 2),
            ("SG", 1499, 2),
            ("SG", 1500, 3),
            ("SG", 9999, 3),
            ("SG", 10000, 4),
            # AE (UAE VARA)
            ("AE", 249, 1),
            ("AE", 250, 2),
            ("AE", 999, 2),
            ("AE", 1000, 3),
            ("AE", 9999, 3),
            ("AE", 10000, 4),
        ],
    )
    def test_tier_boundaries(self, jurisdiction: str, amount: float, expected_tier: int):
        """Tier boundaries match regulatory thresholds."""
        assert compute_tier(amount, jurisdiction) == expected_tier

    def test_all_jurisdictions_have_required_keys(self):
        """Every jurisdiction entry has tier2, tier3, and tier4 keys."""
        for code, thresholds in JURISDICTION_TIERS.items():
            assert "tier2" in thresholds, f"{code} missing tier2"
            assert "tier3" in thresholds, f"{code} missing tier3"
            assert "tier4" in thresholds, f"{code} missing tier4"

    def test_tier_thresholds_are_monotonic(self):
        """Thresholds are monotonically increasing: tier2 < tier3 < tier4."""
        for code, thresholds in JURISDICTION_TIERS.items():
            assert thresholds["tier2"] < thresholds["tier3"], (
                f"{code}: tier2 ({thresholds['tier2']}) >= tier3 ({thresholds['tier3']})"
            )
            assert thresholds["tier3"] < thresholds["tier4"], (
                f"{code}: tier3 ({thresholds['tier3']}) >= tier4 ({thresholds['tier4']})"
            )

    def test_travel_rule_threshold_exists(self):
        """All jurisdictions define a Travel Rule tier (tier3 >= some positive value)."""
        for code, thresholds in JURISDICTION_TIERS.items():
            assert thresholds["tier3"] > 0, f"{code}: tier3 must be > 0"
