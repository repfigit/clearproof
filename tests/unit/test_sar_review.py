"""Tests for SAR review flag logic."""

from src.sar.sar_review import evaluate_sar_flags, HIGH_RISK_JURISDICTIONS


class TestSARReviewFlags:
    def test_tier_1_no_flag(self):
        result = evaluate_sar_flags(amount_tier=1, jurisdiction="US")
        assert result.review_flagged is False
        assert result.requires_human_review is False
        assert len(result.flag_reasons) == 0

    def test_tier_2_no_flag(self):
        result = evaluate_sar_flags(amount_tier=2, jurisdiction="SG")
        assert result.review_flagged is False

    def test_tier_3_flags_review(self):
        result = evaluate_sar_flags(amount_tier=3, jurisdiction="US")
        assert result.review_flagged is True
        assert result.requires_human_review is True
        assert any("tier 3" in r for r in result.flag_reasons)

    def test_tier_4_flags_review(self):
        result = evaluate_sar_flags(amount_tier=4, jurisdiction="US")
        assert result.review_flagged is True
        assert any("tier 4" in r for r in result.flag_reasons)

    def test_high_risk_jurisdiction_flags(self):
        for jur in ["IR", "KP", "SY", "CU", "VE"]:
            result = evaluate_sar_flags(amount_tier=1, jurisdiction=jur)
            assert result.review_flagged is True
            assert any("high-risk" in r for r in result.flag_reasons)

    def test_high_risk_jurisdictions_set(self):
        assert "IR" in HIGH_RISK_JURISDICTIONS
        assert "US" not in HIGH_RISK_JURISDICTIONS

    def test_rapid_succession_flag(self):
        result = evaluate_sar_flags(
            amount_tier=1, jurisdiction="US",
            additional_signals={"rapid_succession": True},
        )
        assert result.review_flagged is True
        assert any("rapid_succession" in r for r in result.flag_reasons)

    def test_high_velocity_flag(self):
        result = evaluate_sar_flags(
            amount_tier=1, jurisdiction="US",
            additional_signals={"transfers_last_24h": 15},
        )
        assert result.review_flagged is True
        assert any("15 transfers" in r for r in result.flag_reasons)

    def test_manual_flag(self):
        result = evaluate_sar_flags(
            amount_tier=1, jurisdiction="US",
            additional_signals={"manual_flag": True},
        )
        assert result.review_flagged is True
        assert any("manual_flag" in r for r in result.flag_reasons)

    def test_multiple_reasons_accumulate(self):
        result = evaluate_sar_flags(
            amount_tier=3, jurisdiction="IR",
            additional_signals={"rapid_succession": True},
        )
        assert result.review_flagged is True
        assert len(result.flag_reasons) >= 3

    def test_advisory_only_no_sar_filing(self):
        """SAR review is advisory — the result has no 'filed' field."""
        result = evaluate_sar_flags(amount_tier=4, jurisdiction="KP")
        assert not hasattr(result, "sar_filed")
        assert result.requires_human_review is True
