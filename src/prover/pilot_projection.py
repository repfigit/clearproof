"""Circuit-facing projection of validated private transfer/context records."""

from dataclasses import dataclass, field

from src.protocol.canonical import record_digest
from src.protocol.credential import digest_limbs, scalar
from src.protocol.transfer import AssetRegistry, Transfer, VerificationContext, asset_chain, uint128
from src.prover.pilot_valuation import private_tier_witness, valuation_witness
from src.registry.poseidon import poseidon_hash

FIELD_NAMES = (
    "transfer_digest_hi",
    "transfer_digest_lo",
    "context_digest_hi",
    "context_digest_lo",
    "tenant_hi",
    "tenant_lo",
    "transfer_id_hi",
    "transfer_id_lo",
    "nonce_hi",
    "nonce_lo",
    "originator_wallet",
    "beneficiary_wallet",
    "asset_chain",
    "asset_contract",
    "asset_decimals",
    "amount_base_units",
    "valuation_numerator",
    "valuation_denominator",
    "usd_cents",
    "valuation_observed_at",
    "valuation_expires_at",
    "transfer_created_at",
    "transfer_expires_at",
    "evaluated_at",
    "max_transfer_age",
    "jurisdiction",
    "deployment_chain",
    "deployment_address",
    "policy_digest_hi",
    "policy_digest_lo",
    "catalog_digest_hi",
    "catalog_digest_lo",
    "threshold_2",
    "threshold_3",
    "threshold_4",
    "private_tier",
    "originator_did_hi",
    "originator_did_lo",
    "originator_is_vasp",
    "beneficiary_did_hi",
    "beneficiary_did_lo",
    "beneficiary_is_vasp",
    "valuation_source_hi",
    "valuation_source_lo",
    "valuation_evidence_hi",
    "valuation_evidence_lo",
    "valuation_digest_hi",
    "valuation_digest_lo",
)


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
        if type(self.fields) is not tuple or len(self.fields) != 48:
            raise ValueError("Projection requires a 48-field tuple")
        widths = {
            10: 160,
            11: 160,
            12: 64,
            13: 160,
            14: 5,
            19: 53,
            20: 53,
            21: 53,
            22: 53,
            23: 53,
            24: 17,
            25: 16,
            26: 64,
            27: 160,
            35: 3,
            38: 1,
            41: 1,
        }
        for index, value in enumerate(self.fields):
            if type(value) is not int or not 0 <= value < 2 ** widths.get(index, 128):
                raise ValueError("Projection field is outside its integer range")
        if type(self.remainder) is not str:
            raise ValueError("Projection remainder must be a canonical integer string")
        uint128(self.remainder)

    @property
    def commitment(self) -> str:
        if len(self.fields) != 48:
            raise ValueError("Projection requires exactly 48 fields")
        state = 201
        for offset in range(0, 48, 8):
            state = poseidon_hash([state, *self.fields[offset : offset + 8]])
        return str(state)

    @property
    def authorization_scope(self) -> str:
        return str(poseidon_hash([202, *self.fields[4:10], self.fields[26], self.fields[27]]))

    def nullifier(self, holder_secret: str) -> str:
        return str(poseidon_hash([203, scalar(holder_secret, nonzero=True), int(self.authorization_scope)]))

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
