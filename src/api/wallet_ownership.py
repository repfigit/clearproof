"""
EU TFR self-hosted wallet ownership verification (EIP-191).

Implements challenge-response flow per Regulation 2023/1113:
  1. API issues challenge: (wallet_address, vasp_did, timestamp, nonce)
  2. User signs with EIP-191 personal_sign
  3. API verifies signature, creates attestation record
  4. Attestation stored with expiry; revoked/expired rejected

NOTE: This implementation stages AFTER ADR 0002 curve decision.
The circuit change (wallet_ownership_verified constraint) merges but
the production trusted-setup ceremony waits for both ADR 0002 + this.
"""

from __future__ import annotations

import secrets
import time
from typing import Optional

from eth_account.messages import encode_defunct
from pydantic import BaseModel, Field
from web3 import Web3


class WalletOwnershipChallenge(BaseModel):
    """Challenge issued by the API for wallet ownership proof."""

    wallet_address: str = Field(..., description="Ethereum wallet address (0x-prefixed)")
    vasp_did: str = Field(..., description="VASP DID requesting verification")
    timestamp: int = Field(..., description="Unix timestamp of challenge issuance")
    nonce: str = Field(..., description="Cryptographic nonce (32 bytes hex)")
    expires_at: int = Field(..., description="Challenge expiry (timestamp + TTL)")


class WalletOwnershipAttestation(BaseModel):
    """Successful wallet ownership verification record."""

    attestation_id: str = Field(..., description="Unique attestation identifier")
    wallet_address: str = Field(..., description="Verified wallet address")
    vasp_did: str = Field(..., description="VASP DID that requested verification")
    timestamp: int = Field(..., description="Unix timestamp of verification")
    nonce: str = Field(..., description="Nonce from the challenge")
    signature: str = Field(..., description="EIP-191 signature (0x-prefixed hex)")
    expires_at: int = Field(..., description="Attestation expiry (timestamp + TTL)")
    revoked: bool = Field(default=False, description="Whether attestation has been revoked")


class WalletOwnershipVerifier:
    """
    EIP-191 wallet ownership verification.

    Challenges are stored in-memory (MVP); production should use persistent storage.
    """

    # Challenge TTL: 5 minutes
    CHALLENGE_TTL_SECONDS = 300

    # Attestation TTL: 24 hours
    ATTESTATION_TTL_SECONDS = 86400

    def __init__(self) -> None:
        self._pending_challenges: dict[str, WalletOwnershipChallenge] = {}  # nonce -> challenge
        self._attestations: dict[str, WalletOwnershipAttestation] = {}  # attestation_id -> attestation
        self._wallet_attestations: dict[str, list[str]] = {}  # wallet_address -> [attestation_id, ...]

    def create_challenge(self, wallet_address: str, vasp_did: str) -> WalletOwnershipChallenge:
        """
        Issue a new wallet ownership challenge.

        Args:
            wallet_address: Ethereum wallet address (0x-prefixed)
            vasp_did: VASP DID requesting verification

        Returns:
            WalletOwnershipChallenge with nonce and expiry
        """
        # Normalize wallet address
        wallet_address = Web3.to_checksum_address(wallet_address)

        now = int(time.time())
        nonce = secrets.token_hex(32)
        expires_at = now + self.CHALLENGE_TTL_SECONDS

        challenge = WalletOwnershipChallenge(
            wallet_address=wallet_address,
            vasp_did=vasp_did,
            timestamp=now,
            nonce=nonce,
            expires_at=expires_at,
        )

        self._pending_challenges[nonce] = challenge
        return challenge

    def verify_signature(
        self,
        challenge: WalletOwnershipChallenge,
        signature: str,
    ) -> Optional[str]:
        """
        Verify an EIP-191 signature against a challenge.

        Args:
            challenge: The challenge that was signed
            signature: EIP-191 signature (0x-prefixed hex)

        Returns:
            Recovered signer address if valid, None if invalid
        """
        try:
            # Construct the message that was signed
            # Format: (wallet_address, vasp_did, timestamp, nonce)
            message = (
                f"ClearProof Wallet Ownership Verification\n"
                f"Wallet: {challenge.wallet_address}\n"
                f"VASP: {challenge.vasp_did}\n"
                f"Timestamp: {challenge.timestamp}\n"
                f"Nonce: {challenge.nonce}"
            )

            # Encode for EIP-191 personal_sign
            message_hash = encode_defunct(text=message)

            # Recover signer address
            signer = Web3().eth.account.recover_message(message_hash, signature=signature)

            # Check if recovered address matches challenge wallet
            if Web3.to_checksum_address(signer) == challenge.wallet_address:
                return signer

            return None

        except Exception:
            # Signature verification failed (malformed signature, wrong chain, etc.)
            return None

    def create_attestation(
        self,
        challenge: WalletOwnershipChallenge,
        signature: str,
    ) -> WalletOwnershipAttestation:
        """
        Create an attestation record after successful signature verification.

        Args:
            challenge: The verified challenge
            signature: The valid EIP-191 signature

        Returns:
            WalletOwnershipAttestation record
        """
        import uuid

        attestation_id = str(uuid.uuid4())
        now = int(time.time())
        expires_at = now + self.ATTESTATION_TTL_SECONDS

        attestation = WalletOwnershipAttestation(
            attestation_id=attestation_id,
            wallet_address=challenge.wallet_address,
            vasp_did=challenge.vasp_did,
            timestamp=now,
            nonce=challenge.nonce,
            signature=signature,
            expires_at=expires_at,
            revoked=False,
        )

        self._attestations[attestation_id] = attestation

        # Track attestations by wallet
        if challenge.wallet_address not in self._wallet_attestations:
            self._wallet_attestations[challenge.wallet_address] = []
        self._wallet_attestations[challenge.wallet_address].append(attestation_id)

        # Remove the used challenge (single-use)
        if challenge.nonce in self._pending_challenges:
            del self._pending_challenges[challenge.nonce]

        return attestation

    def get_pending_challenge(self, nonce: str) -> Optional[WalletOwnershipChallenge]:
        """Retrieve a pending challenge by nonce (non-consuming read)."""
        challenge = self._pending_challenges.get(nonce)
        if challenge is None:
            return None

        # Check if expired
        now = int(time.time())
        if now > challenge.expires_at:
            # Expired challenge, remove it
            del self._pending_challenges[nonce]
            return None

        return challenge

    def consume_pending_challenge(self, nonce: str) -> Optional[WalletOwnershipChallenge]:
        """Atomically retrieve and remove a pending challenge by nonce."""
        challenge = self._pending_challenges.pop(nonce, None)
        if challenge is None:
            return None

        now = int(time.time())
        if now > challenge.expires_at:
            return None

        return challenge

    def get_attestation(self, attestation_id: str) -> Optional[WalletOwnershipAttestation]:
        """Retrieve an attestation by ID."""
        return self._attestations.get(attestation_id)

    def get_active_attestation(self, wallet_address: str) -> Optional[WalletOwnershipAttestation]:
        """
        Get the most recent active (non-expired, non-revoked) attestation for a wallet.

        Args:
            wallet_address: Wallet address to check

        Returns:
            Most recent active attestation, or None if no active attestation exists
        """
        wallet_address = Web3.to_checksum_address(wallet_address)
        attestation_ids = self._wallet_attestations.get(wallet_address, [])

        now = int(time.time())
        
        # Iterate in reverse to get most recently created first
        for att_id in reversed(attestation_ids):
            att = self._attestations.get(att_id)
            if att and not att.revoked and now <= att.expires_at:
                return att

        return None

    def revoke_attestation(self, attestation_id: str) -> bool:
        """
        Revoke an attestation.

        Args:
            attestation_id: Attestation to revoke

        Returns:
            True if revoked, False if not found
        """
        attestation = self._attestations.get(attestation_id)
        if attestation is None:
            return False

        attestation.revoked = True
        return True

    def is_attestation_valid(self, attestation_id: str) -> bool:
        """
        Check if an attestation is currently valid (not expired, not revoked).

        Args:
            attestation_id: Attestation to check

        Returns:
            True if valid, False otherwise
        """
        attestation = self._attestations.get(attestation_id)
        if attestation is None:
            return False

        now = int(time.time())
        return not attestation.revoked and now <= attestation.expires_at


# Module-level singleton (matches pattern in credential.py)
_verifier = WalletOwnershipVerifier()
