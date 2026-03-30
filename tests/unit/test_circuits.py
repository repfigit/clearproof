"""
Tests for tier_mapping.compute_tier — jurisdiction-specific threshold logic.

Verifies that compute_tier returns the correct tier (1-4) for each
jurisdiction's thresholds as defined in JURISDICTION_TIERS.
"""

from __future__ import annotations

import pytest

from src.prover.tier_mapping import compute_tier, JURISDICTION_TIERS


# ---------------------------------------------------------------------------
# US tiers (FinCEN BSA / GENIUS Act)
#   tier2=250, tier3=3_000, tier4=10_000
# ---------------------------------------------------------------------------

class TestUSTiers:
    def test_tier1_below_250(self):
        assert compute_tier(249, "US") == 1

    def test_tier1_zero(self):
        assert compute_tier(0, "US") == 1

    def test_tier2_at_250(self):
        assert compute_tier(250, "US") == 2

    def test_tier2_below_3000(self):
        assert compute_tier(2999, "US") == 2

    def test_tier3_above_3000(self):
        assert compute_tier(3001, "US") == 3

    def test_tier3_at_3000(self):
        assert compute_tier(3000, "US") == 3

    def test_tier4_above_10000(self):
        assert compute_tier(10001, "US") == 4

    def test_tier4_at_10000(self):
        assert compute_tier(10000, "US") == 4


# ---------------------------------------------------------------------------
# EU tiers (MiCA TFR)
#   tier2=250, tier3=1_000, tier4=10_000
# ---------------------------------------------------------------------------

class TestEUTiers:
    def test_tier1_below_250(self):
        assert compute_tier(249, "EU") == 1

    def test_tier2_below_1000(self):
        assert compute_tier(999, "EU") == 2

    def test_tier2_at_250(self):
        assert compute_tier(250, "EU") == 2

    def test_tier3_above_1000(self):
        assert compute_tier(1001, "EU") == 3

    def test_tier3_at_1000(self):
        assert compute_tier(1000, "EU") == 3

    def test_tier4_above_10000(self):
        assert compute_tier(10001, "EU") == 4

    def test_tier4_at_10000(self):
        assert compute_tier(10000, "EU") == 4


# ---------------------------------------------------------------------------
# SG tiers (MAS Payment Services Act)
#   tier2=250, tier3=1_500, tier4=10_000
# ---------------------------------------------------------------------------

class TestSGTiers:
    def test_tier1_below_250(self):
        assert compute_tier(249, "SG") == 1

    def test_tier2_below_1500(self):
        assert compute_tier(1499, "SG") == 2

    def test_tier3_at_1500(self):
        assert compute_tier(1500, "SG") == 3

    def test_tier3_above_1500(self):
        assert compute_tier(1501, "SG") == 3

    def test_tier4_above_10000(self):
        assert compute_tier(10001, "SG") == 4


# ---------------------------------------------------------------------------
# AE tiers (UAE VARA)
#   tier2=250, tier3=1_000, tier4=10_000
# ---------------------------------------------------------------------------

class TestAETiers:
    def test_tier1_below_250(self):
        assert compute_tier(249, "AE") == 1

    def test_tier2_below_1000(self):
        assert compute_tier(999, "AE") == 2

    def test_tier3_at_1000(self):
        assert compute_tier(1000, "AE") == 3

    def test_tier4_above_10000(self):
        assert compute_tier(10001, "AE") == 4


# ---------------------------------------------------------------------------
# Unknown jurisdiction falls back to DEFAULT
# ---------------------------------------------------------------------------

class TestDefaultFallback:
    def test_unknown_jurisdiction_uses_default(self):
        """Unknown jurisdiction code should fall back to DEFAULT thresholds."""
        # DEFAULT: tier2=250, tier3=1_000, tier4=10_000 (FATF global threshold)
        assert compute_tier(249, "XX") == 1
        assert compute_tier(999, "XX") == 2
        assert compute_tier(1001, "XX") == 3
        assert compute_tier(10001, "XX") == 4

    def test_case_insensitive(self):
        """Jurisdiction codes should be case-insensitive."""
        assert compute_tier(500, "us") == 2
        assert compute_tier(500, "Us") == 2

    def test_default_key_exists(self):
        """The DEFAULT key must exist in JURISDICTION_TIERS."""
        assert "DEFAULT" in JURISDICTION_TIERS
