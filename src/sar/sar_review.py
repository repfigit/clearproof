"""
SAR review flag logic.

IMPORTANT: FinCEN SAR filing is activity-based, not amount-based.
This module generates review flags for human compliance officers.
It does NOT automatically file SARs.

Review triggers (configurable per VASP policy):
  - amount_tier >= 3 (large transfer, warrants review)
  - Rapid successive transfers from same wallet
  - Jurisdiction risk scoring
  - Manual flag from compliance officer
  - Pattern-based anomaly detection (future)

The compliance officer makes the final SAR filing decision.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

__all__ = ["SARReviewResult", "evaluate_sar_flags"]

# High-risk jurisdictions per FATF/OFAC guidance
HIGH_RISK_JURISDICTIONS: frozenset[str] = frozenset({
    "IR",  # Iran
    "KP",  # North Korea
    "SY",  # Syria
    "CU",  # Cuba
    "VE",  # Venezuela
})


class SARReviewResult(BaseModel):
    """
    Result of SAR flag evaluation.

    This is ADVISORY — it flags transfers for human compliance officer
    review. It does NOT automatically file a SAR.
    """

    review_flagged: bool = Field(
        ..., description="True if the transfer warrants human review"
    )
    flag_reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons the transfer was flagged",
    )
    requires_human_review: bool = Field(
        ..., description="True if a human compliance officer must review"
    )


def evaluate_sar_flags(
    amount_tier: int,
    jurisdiction: str,
    additional_signals: Optional[dict] = None,
) -> SARReviewResult:
    """
    Evaluate whether a transfer should be flagged for SAR review.

    Returns a SARReviewResult — the human compliance officer makes the
    final decision on whether to file a SAR.

    Args:
        amount_tier: Transfer tier (1-4). Tier >= 3 triggers review.
        jurisdiction: ISO 3166-1 alpha-2 country code.
        additional_signals: Optional dict with extra risk signals:
            - rapid_succession (bool): Multiple transfers in short window
            - manual_flag (bool): Compliance officer manual flag
            - transfers_last_24h (int): Velocity count

    Returns:
        SARReviewResult with flag status and reasons.
    """
    if additional_signals is None:
        additional_signals = {}

    reasons: list[str] = []

    # Tier-based flag (not automatic SAR -- just a review trigger)
    if amount_tier >= 4:
        reasons.append(
            f"high_value_tier: tier {amount_tier} exceeds $10,000 threshold"
        )
    elif amount_tier >= 3:
        reasons.append(
            f"high_value_tier: tier {amount_tier} exceeds Travel Rule threshold"
        )

    # Rapid succession flag
    if additional_signals.get("rapid_succession", False):
        reasons.append("rapid_succession: multiple transfers in short time window")

    velocity = additional_signals.get("transfers_last_24h", 0)
    if velocity > 10:
        reasons.append(
            f"rapid_succession: {velocity} transfers in last 24h"
        )

    # Jurisdiction risk flag
    if jurisdiction.upper() in HIGH_RISK_JURISDICTIONS:
        reasons.append(f"unusual_jurisdiction: {jurisdiction} is high-risk")

    # Manual compliance officer flag
    if additional_signals.get("manual_flag", False):
        reasons.append("manual_flag: flagged by compliance officer")

    flagged = len(reasons) > 0

    return SARReviewResult(
        review_flagged=flagged,
        flag_reasons=reasons,
        requires_human_review=flagged,
    )
