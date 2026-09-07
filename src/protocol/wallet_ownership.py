"""Versioned EOA wallet evidence; signatures are verified outside the ZK circuit."""

from typing import Literal

from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import Field, model_validator

from src.protocol.canonical import record_digest
from src.protocol.credential import PilotCredential, Scalar, scalar
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record
from src.registry.poseidon import BN254_SCALAR_FIELD, poseidon_hash

CHALLENGE_TTL = 300
ATTESTATION_TTL = 86400
EXTENSION_DOMAIN = 111
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class WalletOwnershipError(ValueError):
    """Wallet evidence failed context, validity or signature checks."""


class WalletChallenge(Record):
    schema_version: Literal["clearproof-wallet-challenge-v1"] = "clearproof-wallet-challenge-v1"
    tenant_id: OpaqueId
    actor_id: OpaqueId
    credential: PilotCredential
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    nonce: Hex32
    timestamp: Epoch
    expires_at: Epoch

    @model_validator(mode="after")
    def context(self):
        if self.tenant_id != self.credential.tenant_id or self.expires_at != self.timestamp + CHALLENGE_TTL:
            raise ValueError("Invalid wallet challenge binding or TTL")
        if self.nonce == "0" * 64 or self.registry_address == "0x" + "0" * 40:
            raise ValueError("Wallet challenge requires a nonzero nonce and registry")
        if not self.credential.issued_at <= self.timestamp < self.credential.expires_at:
            raise ValueError("Credential is not current at challenge issuance")
        return self

    def message(self) -> str:
        # Explicit human-readable purpose followed by canonical structured fields.
        return "Clearproof wallet ownership verification v1\n" + self.canonical_bytes().decode("utf-8")

    def verify_signature(self, signature: str) -> None:
        try:
            if type(signature) is not str or len(signature) != 132 or not signature.startswith("0x"):
                raise ValueError("format")
            raw = bytes.fromhex(signature[2:])
            if signature != "0x" + raw.hex() or raw[64] not in (27, 28):
                raise ValueError("format")
            r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big")
            if not 1 <= r < SECP256K1_N or not 1 <= s <= SECP256K1_N // 2:
                raise ValueError("scalar")
            signer = Account.recover_message(encode_defunct(text=self.message()), signature=raw).lower()
            if signer != self.credential.subject_wallet:
                raise ValueError("signer")
        except Exception as exc:
            raise WalletOwnershipError("Invalid wallet ownership signature") from exc


class WalletAttestation(Record):
    schema_version: Literal["clearproof-wallet-attestation-v1"] = "clearproof-wallet-attestation-v1"
    attestation_id: Hex32
    challenge: WalletChallenge
    signature: str = Field(pattern=r"^0x[0-9a-f]{130}$", min_length=132, max_length=132)
    issued_at: Epoch
    expires_at: Epoch

    @model_validator(mode="after")
    def interval(self):
        if not self.challenge.timestamp <= self.issued_at < self.challenge.expires_at:
            raise ValueError("Attestation issued outside the challenge validity interval")
        if self.expires_at != self.issued_at + ATTESTATION_TTL:
            raise ValueError("Attestation must have a 24-hour TTL")
        if self.attestation_id != self.challenge.nonce:
            raise ValueError("Attestation identifier must bind the consumed challenge")
        return self

    @property
    def digest_scalar(self) -> str:
        digest = record_digest("clearproof/wallet-attestation/v1", self.model_dump(mode="json"))
        return str(int(digest, 16) % BN254_SCALAR_FIELD)


class WalletCredentialExtension(Record):
    """Staged six-field commitment; existing credential/proof formats are unchanged."""

    schema_version: Literal["clearproof-wallet-credential-v1"] = "clearproof-wallet-credential-v1"
    credential_commitment: Scalar
    attestation_digest: Scalar
    issued_at: Epoch
    expires_at: Epoch
    wallet_ownership_verified: bool

    @model_validator(mode="after")
    def valid_fields(self):
        scalar(self.credential_commitment, nonzero=True)
        scalar(self.attestation_digest, nonzero=True)
        if self.expires_at <= self.issued_at:
            raise ValueError("Extension requires a positive validity interval")
        return self

    def fields(self) -> list[int]:
        return [
            EXTENSION_DOMAIN,
            scalar(self.credential_commitment),
            scalar(self.attestation_digest),
            self.issued_at,
            self.expires_at,
            int(self.wallet_ownership_verified),
        ]

    @property
    def commitment(self) -> str:
        return str(poseidon_hash(self.fields()))

    def witness(self, *, evaluated_at: int) -> dict:
        if type(evaluated_at) is not int or not self.issued_at <= evaluated_at < self.expires_at:
            raise WalletOwnershipError("Extension is outside its validity interval")
        if not self.wallet_ownership_verified:
            raise WalletOwnershipError("Wallet ownership is not verified")
        return {
            "fields": [str(x) for x in self.fields()],
            "extension_commitment": self.commitment,
            "expected_credential_commitment": self.credential_commitment,
            "expected_attestation_digest": self.attestation_digest,
            "evaluated_at": str(evaluated_at),
        }
