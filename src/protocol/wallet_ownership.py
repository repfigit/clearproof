"""Versioned EOA wallet evidence; signatures are verified outside the ZK circuit."""

from datetime import datetime, timezone
from typing import Annotated, Literal, Union

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address
from pydantic import Field, model_validator
from siwe import SiweMessage

from src.protocol.canonical import record_digest
from src.protocol.credential import PilotCredential, Scalar, scalar
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record
from src.registry.poseidon import BN254_SCALAR_FIELD, poseidon_hash

CHALLENGE_TTL = 300
ATTESTATION_TTL = 86400
EXTENSION_DOMAIN = 111
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

SIWE_STATEMENT = "Sign to verify control of this wallet for an EU TFR wallet-ownership attestation (Clearproof)."


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


def _iso(epoch: int) -> str:
    """Render a Unix epoch as the ISO-8601 instant SIWE messages require (UTC, Z suffix)."""
    if type(epoch) is not int or not 0 <= epoch < 2**53:
        raise ValueError("Invalid SIWE timestamp")
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def siwe_message(
    *,
    domain: str,
    address: str,
    chain_id: int,
    nonce: str,
    issued_at: int,
    expiration_time: int,
    resource: str,
) -> str:
    """Render the deterministic EIP-4361 message for a wallet-ownership challenge.

    Assembled explicitly (not via the siwe library's renderer) so the TypeScript
    helper in @clearproof/proof can reproduce it byte for byte without a runtime
    dependency; tests parse the result with the siwe library to prove it is a
    well-formed EIP-4361 message. Field order and blank-line placement follow
    the EIP-4361 ABNF: domain/address block, statement, URI/Version/Chain-ID/
    Nonce/Issued-At, then optional Expiration-Time and Resources.
    """
    statement = SIWE_STATEMENT
    for name, value in (("domain", domain), ("address", address), ("statement", statement)):
        if not value or "\n" in value:
            raise ValueError(f"Invalid SIWE {name}")
    # EIP-4361 requires the EIP-55 checksummed address in the message header;
    # recovery still compares the lowercase recovered signer against the
    # credential's lowercase subject wallet.
    rendered_address = to_checksum_address(address)
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{rendered_address}\n"
        "\n"
        f"{statement}\n"
        "\n"
        f"URI: https://{domain}/wallet/ownership\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {_iso(issued_at)}\n"
        f"Expiration Time: {_iso(expiration_time)}\n"
        "Resources:\n"
        f"- {resource}"
    )


class WalletChallengeV2(Record):
    """SIWE (ERC-4361) wallet challenge: same bindings as v1, EIP-4361 message.

    The signature is still EIP-191 personal_sign over the exact rendered SIWE
    message (that is how wallets sign EIP-4361 text), so recovery semantics,
    low-s enforcement and the 65-byte format are shared with v1. The SIWE
    fields (domain, nonce, chain-id, issued-at, expiration-time) make the
    challenge itself a supervisor-readable attestation record.
    """

    schema_version: Literal["clearproof-wallet-challenge-v2"] = "clearproof-wallet-challenge-v2"
    tenant_id: OpaqueId
    actor_id: OpaqueId
    credential: PilotCredential
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    nonce: Hex32
    timestamp: Epoch
    expires_at: Epoch
    siwe_domain: str = Field(min_length=1, max_length=253)
    siwe_resource: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def context(self):
        if self.tenant_id != self.credential.tenant_id or self.expires_at != self.timestamp + CHALLENGE_TTL:
            raise ValueError("Invalid wallet challenge binding or TTL")
        if self.nonce == "0" * 64 or self.registry_address == "0x" + "0" * 40:
            raise ValueError("Wallet challenge requires a nonzero nonce and registry")
        if not self.credential.issued_at <= self.timestamp < self.credential.expires_at:
            raise ValueError("Credential is not current at challenge issuance")
        if "\n" in self.siwe_domain or self.siwe_domain != self.siwe_domain.strip():
            raise ValueError("Invalid SIWE domain")
        return self

    def message(self) -> str:
        return siwe_message(
            domain=self.siwe_domain,
            address=self.credential.subject_wallet,
            chain_id=self.chain_id,
            nonce=self.nonce,
            issued_at=self.timestamp,
            expiration_time=self.expires_at,
            resource=self.siwe_resource,
        )

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
            message = self.message()
            # Parse with the reference SIWE implementation and confirm the
            # rendered fields round-trip: this proves the message we sign is a
            # well-formed EIP-4361 record with the exact challenge bindings.
            parsed = SiweMessage.from_message(message)
            if (
                parsed.nonce != self.nonce
                or parsed.domain != self.siwe_domain
                or int(parsed.chain_id) != self.chain_id
                or parsed.address.lower() != self.credential.subject_wallet.lower()
            ):
                raise ValueError("siwe fields")
            signer = Account.recover_message(encode_defunct(text=message), signature=raw).lower()
            if signer != self.credential.subject_wallet.lower():
                raise ValueError("signer")
        except WalletOwnershipError:
            raise
        except Exception as exc:
            raise WalletOwnershipError("Invalid wallet ownership signature") from exc


def _delegation_record(
    checked: bool, delegated: bool | None, delegate: str | None, checked_at: int, reason: str | None
):
    return {
        "checked": checked,
        "delegated": delegated,
        "delegate": delegate,
        "checked_at": checked_at,
        "reason": reason,
    }


class WalletAttestationV2(Record):
    """SIWE-era attestation: embeds the exact signed message and delegation status."""

    schema_version: Literal["clearproof-wallet-attestation-v2"] = "clearproof-wallet-attestation-v2"
    attestation_id: Hex32
    challenge: WalletChallengeV2
    # v2 signatures may be ERC-1271/ERC-6492 blobs (arbitrary length) when the
    # subject wallet is a smart account; the verification method is recorded.
    signature: str = Field(pattern=r"^0x[0-9a-fA-F]+$", min_length=4, max_length=8192)
    method: Literal["eoa", "erc-1271", "erc-6492"] = "eoa"
    issued_at: Epoch
    expires_at: Epoch
    delegation: dict = Field(
        description="Delegation status at verification time: {checked, delegated, delegate, checked_at, reason}"
    )

    @model_validator(mode="after")
    def valid(self):
        if not self.challenge.timestamp <= self.issued_at < self.challenge.expires_at:
            raise ValueError("Attestation issued outside the challenge validity interval")
        if self.expires_at != self.issued_at + ATTESTATION_TTL:
            raise ValueError("Attestation must have a 24-hour TTL")
        if self.attestation_id != self.challenge.nonce:
            raise ValueError("Attestation identifier must bind the consumed challenge")
        delegation = self.delegation
        if set(delegation) - {"checked", "delegated", "delegate", "checked_at", "reason"} or not isinstance(
            delegation.get("checked"), bool
        ):
            raise ValueError("Invalid delegation status record")
        if self.method != "eoa" and len(bytes.fromhex(self.signature[2:])) == 65:
            raise ValueError("Smart-account attestations must not carry a 65-byte EOA signature")
        return self

    @property
    def digest_scalar(self) -> str:
        digest = record_digest("clearproof/wallet-attestation/v2", self.model_dump(mode="json"))
        return str(int(digest, 16) % BN254_SCALAR_FIELD)


AnyWalletChallenge = Annotated[Union[WalletChallenge, WalletChallengeV2], Field(discriminator="schema_version")]
AnyWalletAttestation = Annotated[Union[WalletAttestation, WalletAttestationV2], Field(discriminator="schema_version")]


def load_challenge(record: dict) -> AnyWalletChallenge:
    """Validate a stored challenge record of either schema version."""
    if record.get("schema_version") == "clearproof-wallet-challenge-v2":
        return WalletChallengeV2.model_validate(record)
    return WalletChallenge.model_validate(record)


def load_attestation(record: dict) -> AnyWalletAttestation:
    """Validate a stored attestation record of either schema version."""
    if record.get("schema_version") == "clearproof-wallet-attestation-v2":
        return WalletAttestationV2.model_validate(record)
    return WalletAttestation.model_validate(record)
