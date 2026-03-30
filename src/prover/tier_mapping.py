"""
Jurisdiction-specific tier mapping.

Tier is computed off-chain by the originating VASP; the circuit only
verifies the tier value is in the valid range {1, 2, 3, 4}.

Tier definitions:
  Tier 1 (small):  amount < tier2 threshold → full privacy, no proof needed
  Tier 2 (medium): tier2 ≤ amount < tier3    → compliance proof required
  Tier 3 (large):  tier3 ≤ amount < tier4    → Travel Rule mandatory
  Tier 4 (high):   amount ≥ tier4            → SAR review flag

Per-jurisdiction thresholds (USD equivalents):
  US  — FinCEN BSA / GENIUS Act
  EU  — MiCA TFR
  SG  — MAS Payment Services Act
  AE  — VARA (UAE)
"""

from __future__ import annotations

# Thresholds in USD (or USD-equivalent).
# Keys: tier2 = lower bound of tier 2, tier3 = lower bound of tier 3, etc.
JURISDICTION_TIERS: dict[str, dict[str, int]] = {
    "US": {"tier2": 250, "tier3": 3_000, "tier4": 10_000},
    "EU": {"tier2": 250, "tier3": 1_000, "tier4": 10_000},
    "SG": {"tier2": 250, "tier3": 1_500, "tier4": 10_000},
    "AE": {"tier2": 250, "tier3": 1_000, "tier4": 10_000},  # UAE (VARA)
    "DEFAULT": {"tier2": 250, "tier3": 3_000, "tier4": 10_000},
}


def compute_tier(amount_usd: float, jurisdiction: str) -> int:
    """
    Return the compliance tier (1–4) for a given amount and jurisdiction.

    Args:
        amount_usd: Transfer amount in USD (or USD-equivalent).
        jurisdiction: ISO 3166-1 alpha-2 country code (e.g. ``"US"``, ``"SG"``).

    Returns:
        Integer tier from 1 (smallest / most private) to 4 (largest / SAR flag).
    """
    thresholds = JURISDICTION_TIERS.get(
        jurisdiction.upper(), JURISDICTION_TIERS["DEFAULT"]
    )
    if amount_usd < thresholds["tier2"]:
        return 1
    elif amount_usd < thresholds["tier3"]:
        return 2
    elif amount_usd < thresholds["tier4"]:
        return 3
    else:
        return 4
