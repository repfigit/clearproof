"""Circuit-facing projection of validated private transfer/context records."""

from dataclasses import dataclass, field

from src.protocol.canonical import record_digest
from src.protocol.credential import digest_limbs, scalar
from src.protocol.transfer import AssetRegistry, Transfer, VerificationContext, asset_chain, uint128
from src.prover.generated_signals import (
    AUTHORIZATION_NULLIFIER_DOMAIN_TAG,
    AUTHORIZATION_SCOPE_DOMAIN_TAG,
    PROJECTION_DOMAIN_TAG,
    PROJECTION_FIELD_COUNT,
    PROJECTION_FIELD_WIDTHS,
)
from src.prover.generated_signals import (
    FIELD_NAMES as FIELD_NAMES,
)
from src.prover.pilot_valuation import private_tier_witness, valuation_witness
from src.registry.poseidon import poseidon_hash


def hex_limbs(value: str) -> tuple[int, int]:
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError("Expected 32-byte digest")
    return int.from_bytes(raw[:16], "big"), int.from_bytes(raw[16:], "big")


@dataclass(frozen=True)
class TransferProjection:
    fields: tuple[int, ...] = field(repr=False)
    remainder: str = field(repr=False)

    def __post_init__(self):
        if type(self.fields) is not tuple or len(self.fields) != PROJECTION_FIELD_COUNT:
            raise ValueError("Projection requires a 48-field tuple")
        for index, value in enumerate(self.fields):
            if type(value) is not int or not 0 <= value < 2 ** PROJECTION_FIELD_WIDTHS[index]:
                raise ValueError("Projection field is outside its integer range")
        if type(self.remainder) is not str:
            raise ValueError("Projection remainder must be a canonical integer string")
        uint128(self.remainder)

    @property
    def commitment(self) -> str:
        # __post_init__ validates the 48-field tuple; frozen instances preserve it.
        state = PROJECTION_DOMAIN_TAG
        for offset in range(0, PROJECTION_FIELD_COUNT, 8):
            state = poseidon_hash([state, *self.fields[offset : offset + 8]])
        return str(state)

    @property
    def authorization_scope(self) -> str:
        return str(
            poseidon_hash([AUTHORIZATION_SCOPE_DOMAIN_TAG, *self.fields[4:10], self.fields[26], self.fields[27]])
        )

    def nullifier(self, holder_secret: str) -> str:
        return str(
            poseidon_hash(
                [AUTHORIZATION_NULLIFIER_DOMAIN_TAG, scalar(holder_secret, nonzero=True), int(self.authorization_scope)]
            )
        )

    def witness(self) -> dict:
        return {
            "transfer_fields": [str(value) for value in self.fields],
            "valuation_remainder": self.remainder,
            "projection_commitment": self.commitment,
        }


def project_transfer(
    transfer: Transfer, context: VerificationContext, registry: AssetRegistry, thresholds: tuple[str, str, str]
) -> TransferProjection:
    transfer = Transfer.model_validate(transfer)
    context = VerificationContext.model_validate(context)
    transfer.validate_catalog(registry)
    context.check_transfer(transfer)
    asset = registry.get(transfer.asset_id)
    value = valuation_witness(transfer)
    tier = private_tier_witness(transfer.usd_cents, thresholds)
    originator, beneficiary, quote = transfer.originator, transfer.beneficiary, transfer.valuation
    fields = (
        *hex_limbs(transfer.digest),
        *hex_limbs(context.digest),
        *digest_limbs(transfer.tenant_id),
        *digest_limbs(transfer.transfer_id),
        *hex_limbs(transfer.nonce),
        int(originator.wallet, 16),
        int(beneficiary.wallet, 16),
        asset_chain(transfer.asset_id),
        int(transfer.asset_id.rsplit(":", 1)[1], 16),
        asset.decimals,
        int(transfer.amount_base_units),
        int(quote.numerator),
        int(quote.denominator),
        int(transfer.usd_cents),
        quote.observed_at,
        quote.expires_at,
        transfer.created_at,
        transfer.expires_at,
        context.evaluated_at,
        context.max_transfer_age_seconds,
        int.from_bytes(transfer.jurisdiction.encode("ascii"), "big"),
        int(context.deployment_chain_id),
        int(context.deployment_address, 16),
        *hex_limbs(transfer.policy_digest),
        *hex_limbs(transfer.asset_registry_digest),
        *(int(item) for item in thresholds),
        int(tier["tier"]),
        *(digest_limbs(originator.vasp_did) if originator.vasp_did else (0, 0)),
        int(originator.kind == "vasp"),
        *(digest_limbs(beneficiary.vasp_did) if beneficiary.vasp_did else (0, 0)),
        int(beneficiary.kind == "vasp"),
        *digest_limbs(quote.source_id),
        *hex_limbs(quote.source_evidence_digest),
        *hex_limbs(record_digest("clearproof/valuation/v1", quote.model_dump(mode="json"))),
    )
    return TransferProjection(fields, value["remainder"])
