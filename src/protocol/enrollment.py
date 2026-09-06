"""EOA-signed enrollment consent; not a credential signature verified inside ZK."""

from typing import Literal

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys.exceptions import BadSignature
from pydantic import Field, model_validator

from src.auth.principal import Principal
from src.protocol.credential import PilotCredential
from src.protocol.transfer import Address, Epoch, Record

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class EnrollmentError(ValueError):
    """Enrollment signature, audience, authority or validity was rejected."""


class EnrollmentConsent(Record):
    schema_version: Literal["clearproof-enrollment-v1"] = "clearproof-enrollment-v1"
    credential: PilotCredential
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    consent_expires_at: Epoch

    @model_validator(mode="after")
    def consent_interval(self):
        if not self.credential.issued_at < self.consent_expires_at <= self.credential.issued_at + 600:
            raise ValueError("Enrollment consent must expire within ten minutes of issuance")
        if self.consent_expires_at > self.credential.expires_at or self.registry_address == "0x" + "0" * 40:
            raise ValueError("Invalid enrollment audience or expiry")
        return self

    def signing_message(self):
        # EIP-191 personal_sign over these exact UTF-8 bytes, with an explicit
        # application purpose. Never ask a wallet to sign only an opaque hash.
        return encode_defunct(primitive=b"Clearproof credential enrollment v1\n" + self.canonical_bytes())

    def verify(self, signature: str, *, principal: Principal, chain_id: int, registry_address: str, now: int) -> None:
        consent = EnrollmentConsent.model_validate(self)
        principal = Principal.model_validate(principal)
        principal.require_issuer(consent.credential.issuer_did)
        if principal.tenant_id != consent.credential.tenant_id:
            raise EnrollmentError("Enrollment tenant mismatch")
        if type(chain_id) is not int or consent.chain_id != chain_id or consent.registry_address != registry_address:
            raise EnrollmentError("Enrollment audience mismatch")
        if type(now) is not int or not consent.credential.issued_at <= now < consent.consent_expires_at:
            raise EnrollmentError("Enrollment consent is outside its validity interval")
        # One canonical 65-byte EOA signature format; reject high-s malleability.
        # Contract-wallet/EIP-1271 enrollment needs a separate supported profile.
        try:
            if type(signature) is not str or len(signature) != 132 or not signature.startswith("0x"):
                raise ValueError("format")
            raw = bytes.fromhex(signature[2:])
            if signature != "0x" + raw.hex() or raw[64] not in (27, 28):
                raise ValueError("format")
            r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big")
            if not 1 <= r < _SECP256K1_N or not 1 <= s <= _SECP256K1_N // 2:
                raise ValueError("scalar")
            recovered = Account.recover_message(consent.signing_message(), signature=raw).lower()
            if recovered != consent.credential.subject_wallet:
                raise ValueError("signer")
        except (ValueError, TypeError, IndexError, BadSignature) as exc:
            raise EnrollmentError("Enrollment signature is invalid") from exc
