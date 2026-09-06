"""Exact integer witness inputs for the pilot valuation and private tier predicates."""

from src.protocol.transfer import Transfer, uint128


def valuation_witness(transfer: Transfer) -> dict[str, str]:
    transfer = Transfer.model_validate(transfer)
    numerator, denominator = int(transfer.valuation.numerator), int(transfer.valuation.denominator)
    quotient, remainder = divmod(int(transfer.amount_base_units) * numerator, denominator)
    if quotient != int(transfer.usd_cents):
        raise ValueError("Transfer valuation differs from exact integer quotient")
    return {
        "amount_base_units": transfer.amount_base_units,
        "numerator": str(numerator),
        "denominator": str(denominator),
        "usd_cents": str(quotient),
        "remainder": str(remainder),
    }


def private_tier_witness(usd_cents: str, thresholds: tuple[str, str, str]) -> dict:
    amount = int(uint128(usd_cents))
    if type(thresholds) is not tuple or len(thresholds) != 3:
        raise ValueError("Three ordered policy thresholds are required")
    bounds = tuple(int(uint128(value)) for value in thresholds)
    if amount <= 0 or not 0 < bounds[0] < bounds[1] < bounds[2]:
        raise ValueError("Amount and ordered policy thresholds must be positive")
    return {
        "usd_cents": usd_cents,
        "thresholds": list(thresholds),
        "tier": str(1 + sum(amount >= bound for bound in bounds)),
    }
