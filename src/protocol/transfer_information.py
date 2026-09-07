"""Strict local pilot information profile; not an IVMS101 wire implementation."""

import unicodedata
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator

from src.protocol.transfer import Hex32, Participant, Record, Transfer, UInt128, VerificationContext
from src.prover.pilot_artifacts import strict_json

MAX_INFORMATION_BYTES = 32768
Text100 = Annotated[str, StringConstraints(min_length=1, max_length=100)]
Country = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]


def meaningful(value: str) -> str:
    if not value.strip() or any(unicodedata.category(char) in ("Cc", "Cs") for char in value):
        raise ValueError("Expected nonblank text without control characters")
    return value


class InformationAddress(Record):
    lines: tuple[Annotated[str, StringConstraints(min_length=1, max_length=70)], ...] = Field(
        min_length=1, max_length=7
    )
    country: Country

    @field_validator("lines")
    @classmethod
    def valid_lines(cls, values):
        for value in values:
            meaningful(value)
        return values


class NaturalPersonInformation(Record):
    kind: Literal["natural_person"]
    name: Text100
    address: InformationAddress

    _name = field_validator("name")(meaningful)


class LegalPersonInformation(Record):
    kind: Literal["legal_person"]
    legal_name: Text100
    address: InformationAddress
    country_of_registration: Country

    _name = field_validator("legal_name")(meaningful)


class PartyInformation(Record):
    participant: Participant
    person: Annotated[NaturalPersonInformation | LegalPersonInformation, Field(discriminator="kind")]


class TransferInformation(Record):
    schema_version: Literal["clearproof-transfer-information-v1"]
    transfer_digest: Hex32
    context_digest: Hex32
    asset_id: str = Field(min_length=1, max_length=100)
    amount_base_units: UInt128
    originator: PartyInformation
    beneficiary: PartyInformation


def validate_transfer_information(raw: bytes, transfer: Transfer, context: VerificationContext) -> None:
    """Validate in memory, without returning or logging parsed personal fields.

    The caller encrypts the original bytes after validation. Source truth,
    jurisdiction-specific sufficiency and sender authority require other checks.
    """
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_INFORMATION_BYTES:
            raise ValueError("Invalid information size")
        strict_json(raw, limit=MAX_INFORMATION_BYTES)
        information = TransferInformation.model_validate_json(raw)
        context.check_transfer(transfer)
        if (
            information.transfer_digest != transfer.digest
            or information.context_digest != context.digest
            or information.asset_id != transfer.asset_id
            or information.amount_base_units != transfer.amount_base_units
            or information.originator.participant != transfer.originator
            or information.beneficiary.participant != transfer.beneficiary
        ):
            raise ValueError("Information is outside transfer scope")
    except (ValueError, TypeError, RecursionError):
        # Do not expose a Pydantic error object containing personal input values.
        raise ValueError("Invalid or mismatched transfer information") from None
