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
    "DEFAULT": {"tier2": 250, "tier3": 1_000, "tier4": 10_000},  # FATF $1,000 global threshold
}

# Reserved sentinel used on-chain for the FATF default. Real jurisdiction codes
# are the big-endian ASCII value of two uppercase letters, so they always fall in
# [0x4141, 0x5A5A]; 0 can never collide with one.
DEFAULT_JURISDICTION_KEY = 0


def get_thresholds(jurisdiction: str) -> dict[str, int]:
    """
    Return the tier thresholds for a jurisdiction.

    This is the single accessor for threshold values. Callers must not index
    ``JURISDICTION_TIERS`` directly with their own fallback, because a fallback
    that differs between the prover and the verifier produces proofs that verify
    in one place and fail in another.

    Unknown jurisdictions resolve to ``DEFAULT`` (the FATF $1,000 global
    threshold). That fallback is deliberate and is mirrored on-chain, so it is
    not a silent divergence — but see AIF-79 for the open question of whether
    unregistered jurisdictions should be rejected outright.

    Args:
        jurisdiction: ISO 3166-1 alpha-2 country code, any case.

    Returns:
        Mapping with ``tier2``, ``tier3`` and ``tier4`` lower bounds.
    """
    return JURISDICTION_TIERS.get(jurisdiction.upper(), JURISDICTION_TIERS["DEFAULT"])


def encode_jurisdiction(code: str) -> int:
    """Encode an alpha-2 code the way the circuit carries it: big-endian ASCII."""
    return int.from_bytes(code.upper().encode("ascii"), byteorder="big")


def decode_jurisdiction(value: int) -> str | None:
    """
    Inverse of :func:`encode_jurisdiction`.

    Returns ``None`` when ``value`` is not two uppercase ASCII letters, so a
    caller can reject a malformed ``jurisdiction_code`` public signal rather
    than guessing at thresholds for it.
    """
    if not 0 <= value <= 0xFFFF:
        return None
    hi, lo = (value >> 8) & 0xFF, value & 0xFF
    if not (0x41 <= hi <= 0x5A and 0x41 <= lo <= 0x5A):
        return None
    return chr(hi) + chr(lo)


def thresholds_match_jurisdiction(public_signals: list[str]) -> bool:
    """
    Check that public signals 8-10 carry the thresholds this verifier expects
    for the jurisdiction named in public signal 6.

    The circuit takes the thresholds as *unconstrained* public inputs, so the
    prover picks them. Without this check a prover can submit an arbitrarily
    high ``tier2_threshold`` and land any amount in tier 1, defeating both the
    tier attestation and the SAR review flag.
    """
    if len(public_signals) < 16:
        return False
    try:
        jurisdiction = decode_jurisdiction(int(public_signals[6]))
        submitted = (int(public_signals[8]), int(public_signals[9]), int(public_signals[10]))
    except (TypeError, ValueError):
        return False
    if jurisdiction is None:
        return False

    expected = get_thresholds(jurisdiction)
    return submitted == (expected["tier2"], expected["tier3"], expected["tier4"])


def compute_tier(amount_usd: float, jurisdiction: str) -> int:
    """
    Return the compliance tier (1–4) for a given amount and jurisdiction.

    Args:
        amount_usd: Transfer amount in USD (or USD-equivalent).
        jurisdiction: ISO 3166-1 alpha-2 country code (e.g. ``"US"``, ``"SG"``).

    Returns:
        Integer tier from 1 (smallest / most private) to 4 (largest / SAR flag).
    """
    thresholds = get_thresholds(jurisdiction)
    if amount_usd < thresholds["tier2"]:
        return 1
    elif amount_usd < thresholds["tier3"]:
        return 2
    elif amount_usd < thresholds["tier4"]:
        return 3
    else:
        return 4
