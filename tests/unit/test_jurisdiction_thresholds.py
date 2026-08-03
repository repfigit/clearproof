"""
AIF-79 — jurisdiction threshold binding.

tier2/3/4_threshold (public signals 8-10) are unconstrained public inputs: the
circuit does not derive them, the prover supplies them. Security comes from
every verifier re-deriving them from the same table. These tests cover both
halves of that: the check itself, and the cross-language agreement that makes
the check meaningful.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.prover.tier_mapping import (
    JURISDICTION_TIERS,
    decode_jurisdiction,
    encode_jurisdiction,
    get_thresholds,
    thresholds_match_jurisdiction,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "config" / "jurisdiction_thresholds.json"
TS_THRESHOLDS = REPO_ROOT / "packages" / "proof" / "src" / "thresholds.ts"


def _config() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def _signals(jurisdiction: str = "US", tier2: int = 250, tier3: int = 3000, tier4: int = 10000) -> list[str]:
    s = ["0"] * 16
    s[6] = str(encode_jurisdiction(jurisdiction))
    s[8] = str(tier2)
    s[9] = str(tier3)
    s[10] = str(tier4)
    return s


class TestJurisdictionEncoding:
    def test_us_encodes_to_big_endian_ascii(self):
        assert encode_jurisdiction("US") == 0x5553

    def test_encoding_is_case_insensitive(self):
        assert encode_jurisdiction("us") == encode_jurisdiction("US")

    def test_roundtrip(self):
        for code in ("US", "EU", "SG", "AE", "GB", "ZZ"):
            assert decode_jurisdiction(encode_jurisdiction(code)) == code

    def test_all_real_codes_fit_in_uint16(self):
        # The on-chain mapping key is uint16; if this ever failed the Solidity
        # table could not represent the code.
        assert encode_jurisdiction("ZZ") <= 0xFFFF

    @pytest.mark.parametrize("value", [-1, 0, 0x3031, 0x10000, 0x4160, 0x2020])
    def test_rejects_non_alpha2(self, value):
        assert decode_jurisdiction(value) is None

    def test_default_key_cannot_collide_with_a_real_code(self):
        # Real codes are always >= 0x4141, so 0 is safe as the default sentinel.
        assert encode_jurisdiction("AA") > 0


class TestThresholdBinding:
    def test_accepts_correct_thresholds(self):
        assert thresholds_match_jurisdiction(_signals("US", 250, 3000, 10000)) is True

    def test_rejects_the_tier1_attack(self):
        # The actual exploit: an arbitrarily high tier2 lands any amount in tier 1,
        # defeating the tier attestation and the SAR review flag.
        assert thresholds_match_jurisdiction(_signals("US", 2**63, 3000, 10000)) is False

    def test_rejects_thresholds_borrowed_from_another_jurisdiction(self):
        # EU tier3 (1000) submitted while claiming US (3000).
        assert thresholds_match_jurisdiction(_signals("US", 250, 1000, 10000)) is False

    def test_rejects_malformed_jurisdiction_code(self):
        s = _signals("US")
        s[6] = "12345678"
        assert thresholds_match_jurisdiction(s) is False

    def test_rejects_short_signal_array(self):
        assert thresholds_match_jurisdiction(["0"] * 15) is False

    def test_rejects_non_numeric_signals(self):
        s = _signals("US")
        s[8] = "not-a-number"
        assert thresholds_match_jurisdiction(s) is False

    def test_unregistered_jurisdiction_uses_the_default_table(self):
        default = JURISDICTION_TIERS["DEFAULT"]
        assert thresholds_match_jurisdiction(
            _signals("GB", default["tier2"], default["tier3"], default["tier4"])
        ) is True
        # US thresholds must not be accepted under a code that resolves to DEFAULT.
        assert thresholds_match_jurisdiction(_signals("GB", 250, 3000, 10000)) is False


class TestCrossLanguageParity:
    """
    The three verifier implementations must agree. If they drift, a proof
    verifies off-chain and reverts on-chain (or worse, the reverse).
    """

    def test_python_matches_canonical_config(self):
        cfg = _config()
        for code, expected in cfg["jurisdictions"].items():
            assert get_thresholds(code) == expected, f"Python disagrees with config for {code}"
        assert JURISDICTION_TIERS["DEFAULT"] == cfg["default"]

    def test_python_has_no_extra_jurisdictions(self):
        cfg = _config()
        python_codes = set(JURISDICTION_TIERS) - {"DEFAULT"}
        assert python_codes == set(cfg["jurisdictions"]), "Python table and config have diverged"

    def test_typescript_matches_canonical_config(self):
        """
        Parsed rather than executed so the Python suite stays free of a Node
        dependency. The Vitest suite asserts the same thing from the TS side.
        """
        source = TS_THRESHOLDS.read_text()
        cfg = _config()

        for code, expected in cfg["jurisdictions"].items():
            needle = (
                f"{code}: {{ tier2: {expected['tier2']}, "
                f"tier3: {expected['tier3']}, tier4: {expected['tier4']} }}"
            )
            assert needle in source, f"TypeScript table missing or wrong for {code}: expected {needle!r}"

        default = cfg["default"]
        for key, value in default.items():
            assert f"{key}: {value}," in source, f"TypeScript DEFAULT_THRESHOLDS missing {key}: {value}"

    def test_thresholds_are_strictly_ordered(self):
        """Mirrors the ThresholdsNotOrdered guard in setJurisdictionThresholds."""
        cfg = _config()
        tables = list(cfg["jurisdictions"].values()) + [cfg["default"]]
        for t in tables:
            assert t["tier2"] < t["tier3"] < t["tier4"], f"Unordered thresholds: {t}"

    def test_thresholds_fit_in_uint64(self):
        """The on-chain struct packs these as uint64."""
        cfg = _config()
        for t in list(cfg["jurisdictions"].values()) + [cfg["default"]]:
            for value in t.values():
                assert 0 <= value < 2**64

    def test_default_is_at_least_as_strict_as_every_registered_jurisdiction(self):
        """
        AIF-97 — the default thresholds are the fail-to-strictest fallback for
        unregistered jurisdiction codes. A lower tier escalates to Travel Rule
        sooner, so `default.tierN <= jurisdiction.tierN` for every tier means
        the prover cannot profit from claiming an unknown code: the fallback
        is never looser than a registered jurisdiction.

        If a new jurisdiction is added with a stricter threshold than the
        default, this test fails and the config must be amended — either the
        new jurisdiction's thresholds are raised, or the default is lowered
        to maintain the invariant.
        """
        cfg = _config()
        default = cfg["default"]
        for code, thresholds in cfg["jurisdictions"].items():
            for tier in ("tier2", "tier3", "tier4"):
                assert default[tier] <= thresholds[tier], (
                    f"Default {tier} ({default[tier]}) is stricter than {code} {tier} "
                    f"({thresholds[tier]}). The fail-to-strictest invariant is violated."
                )
