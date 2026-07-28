"""
Tests for EU TFR wallet ownership verification (EIP-191).

Covers:
- Challenge generation and expiry
- Signature verification (valid, wrong signer, expired, replayed)
- Attestation creation, validation, and revocation
- Integration with credential model
"""

import os
import time

# Set required env vars BEFORE importing anything from src.api.* to prevent
# src/api/__init__.py from caching empty API_KEY at module load time.
# This matches the pattern in tests/integration/test_api_endpoints.py.
os.environ.setdefault("PII_MASTER_KEY", "a" * 64)
os.environ.setdefault("AUTH_MODE", "api-key")
os.environ.setdefault("API_KEY", "test-api-key-for-integration")

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

from src.api.wallet_ownership import WalletOwnershipVerifier
from src.registry.credential_registry import zkKYCCredential


@pytest.fixture
def verifier():
    """Fresh wallet ownership verifier instance."""
    return WalletOwnershipVerifier()


@pytest.fixture
def test_wallet():
    """Generate a test Ethereum account."""
    account = Account.create()
    return {
        "address": account.address,
        "private_key": account.key,
        "account": account,
    }


@pytest.fixture
def sample_challenge_data():
    """Sample challenge parameters."""
    return {
        "wallet_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        "vasp_did": "did:web:test-vasp.example.com",
    }


class TestChallengeGeneration:
    """Test challenge creation and management."""

    def test_create_challenge(self, verifier, test_wallet):
        """Challenge is created with correct fields."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        assert challenge.wallet_address == Web3.to_checksum_address(test_wallet["address"])
        assert challenge.vasp_did == "did:web:test.example.com"
        assert challenge.timestamp > 0
        assert len(challenge.nonce) == 64  # 32 bytes hex
        assert challenge.expires_at > challenge.timestamp

    def test_challenge_expiry(self, verifier, test_wallet):
        """Challenge expires after TTL."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        # Challenge should be retrievable immediately
        retrieved = verifier.get_pending_challenge(challenge.nonce)
        assert retrieved is not None
        assert retrieved.nonce == challenge.nonce

        # Simulate expiry by manipulating internal state
        verifier._pending_challenges[challenge.nonce].expires_at = int(time.time()) - 1

        # Now it should be gone
        expired = verifier.get_pending_challenge(challenge.nonce)
        assert expired is None

    def test_challenge_single_use(self, verifier, test_wallet):
        """Challenge is removed after use."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        # Create a mock attestation to consume the challenge
        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)
        signature = signed.signature.hex()

        verifier.create_attestation(challenge, signature)

        # Challenge should be gone
        assert verifier.get_pending_challenge(challenge.nonce) is None


class TestSignatureVerification:
    """Test EIP-191 signature verification."""

    def test_valid_signature(self, verifier, test_wallet):
        """Valid signature is accepted."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        # Sign the challenge message
        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)
        signature = signed.signature.hex()

        # Verify signature
        signer = verifier.verify_signature(challenge, signature)
        assert signer is not None
        assert Web3.to_checksum_address(signer) == challenge.wallet_address

    def test_wrong_signer(self, verifier, test_wallet):
        """Signature from wrong wallet is rejected."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        # Create a different account
        other_account = Account.create()

        # Sign with wrong account
        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = other_account.sign_message(message_hash)
        signature = signed.signature.hex()

        # Verify should fail
        signer = verifier.verify_signature(challenge, signature)
        assert signer is None

    def test_malformed_signature(self, verifier, test_wallet):
        """Malformed signature is rejected."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        # Try to verify garbage
        signer = verifier.verify_signature(challenge, "0xdeadbeef")
        assert signer is None

    def test_tampered_message(self, verifier, test_wallet):
        """Signature over different message is rejected."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        # Sign a different message
        different_message = "This is not the challenge message"
        message_hash = encode_defunct(text=different_message)
        signed = test_wallet["account"].sign_message(message_hash)
        signature = signed.signature.hex()

        # Verify should fail
        signer = verifier.verify_signature(challenge, signature)
        assert signer is None


class TestAttestation:
    """Test attestation creation and management."""

    def test_create_attestation(self, verifier, test_wallet):
        """Attestation is created after successful verification."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)

        attestation = verifier.create_attestation(challenge, signed.signature.hex())

        assert attestation.attestation_id is not None
        assert attestation.wallet_address == challenge.wallet_address
        assert attestation.vasp_did == challenge.vasp_did
        assert attestation.nonce == challenge.nonce
        assert attestation.revoked is False
        assert attestation.expires_at > attestation.timestamp

    def test_attestation_validity(self, verifier, test_wallet):
        """Attestation validity checks work correctly."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)

        attestation = verifier.create_attestation(challenge, signed.signature.hex())

        # Should be valid initially
        assert verifier.is_attestation_valid(attestation.attestation_id) is True

        # Revoke it
        verifier.revoke_attestation(attestation.attestation_id)

        # Should no longer be valid
        assert verifier.is_attestation_valid(attestation.attestation_id) is False

    def test_attestation_expiry(self, verifier, test_wallet):
        """Expired attestation is not valid."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)

        attestation = verifier.create_attestation(challenge, signed.signature.hex())

        # Manually expire it
        verifier._attestations[attestation.attestation_id].expires_at = int(time.time()) - 1

        assert verifier.is_attestation_valid(attestation.attestation_id) is False

    def test_get_active_attestation(self, verifier, test_wallet):
        """Get most recent active attestation for wallet."""
        wallet_address = test_wallet["address"]

        # Create multiple attestations
        for i in range(3):
            challenge = verifier.create_challenge(wallet_address, "did:web:test.example.com")
            message = (
                f"ClearProof Wallet Ownership Verification\n"
                f"Wallet: {challenge.wallet_address}\n"
                f"VASP: {challenge.vasp_did}\n"
                f"Timestamp: {challenge.timestamp}\n"
                f"Nonce: {challenge.nonce}"
            )
            message_hash = encode_defunct(text=message)
            signed = test_wallet["account"].sign_message(message_hash)
            verifier.create_attestation(challenge, signed.signature.hex())
            time.sleep(0.01)  # Ensure different timestamps

        # Get active attestation
        active = verifier.get_active_attestation(wallet_address)
        assert active is not None

        # Should be the most recent one
        all_attestations = verifier._wallet_attestations.get(
            Web3.to_checksum_address(wallet_address), []
        )
        assert len(all_attestations) == 3
        assert active.attestation_id == all_attestations[-1]

    def test_revoke_attestation(self, verifier, test_wallet):
        """Attestation can be revoked."""
        challenge = verifier.create_challenge(test_wallet["address"], "did:web:test.example.com")

        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)

        attestation = verifier.create_attestation(challenge, signed.signature.hex())

        # Revoke it
        result = verifier.revoke_attestation(attestation.attestation_id)
        assert result is True

        # Should be marked as revoked
        retrieved = verifier.get_attestation(attestation.attestation_id)
        assert retrieved.revoked is True

        # Should not be valid
        assert verifier.is_attestation_valid(attestation.attestation_id) is False

    def test_revoke_nonexistent_attestation(self, verifier):
        """Revoking nonexistent attestation returns False."""
        result = verifier.revoke_attestation("nonexistent-id")
        assert result is False


class TestCredentialIntegration:
    """Test integration with credential model."""

    def test_credential_with_wallet_ownership(self, test_wallet):
        """Credential can include wallet_ownership_verified field."""
        now = int(time.time())
        credential = zkKYCCredential(
            issuer_did="did:web:test.example.com",
            subject_wallet=test_wallet["address"],
            jurisdiction="DE",
            kyc_tier="retail",
            sanctions_clear=True,
            issued_at=now,
            expires_at=now + 86400,
            wallet_ownership_verified=True,
        )

        assert credential.wallet_ownership_verified is True

        # Field should be included in commitment
        field_ints = credential._field_ints()
        assert len(field_ints) == 6
        assert field_ints[5] == 1  # wallet_ownership_verified

    def test_credential_without_wallet_ownership(self, test_wallet):
        """Credential defaults to wallet_ownership_verified=False."""
        now = int(time.time())
        credential = zkKYCCredential(
            issuer_did="did:web:test.example.com",
            subject_wallet=test_wallet["address"],
            jurisdiction="US",
            kyc_tier="retail",
            sanctions_clear=True,
            issued_at=now,
            expires_at=now + 86400,
        )

        assert credential.wallet_ownership_verified is False

        # Field should be 0 in commitment
        field_ints = credential._field_ints()
        assert field_ints[5] == 0

    def test_commitment_differs_with_wallet_ownership(self, test_wallet):
        """Commitment changes based on wallet_ownership_verified."""
        now = int(time.time())

        cred_without = zkKYCCredential(
            issuer_did="did:web:test.example.com",
            subject_wallet=test_wallet["address"],
            jurisdiction="US",
            kyc_tier="retail",
            sanctions_clear=True,
            issued_at=now,
            expires_at=now + 86400,
            wallet_ownership_verified=False,
        )

        cred_with = zkKYCCredential(
            issuer_did="did:web:test.example.com",
            subject_wallet=test_wallet["address"],
            jurisdiction="US",
            kyc_tier="retail",
            sanctions_clear=True,
            issued_at=now,
            expires_at=now + 86400,
            wallet_ownership_verified=True,
        )

        # Commitments should differ
        assert cred_without._field_ints() != cred_with._field_ints()


class TestEndToEndFlow:
    """Test complete challenge -> sign -> verify -> attestation flow."""

    def test_complete_flow(self, verifier, test_wallet):
        """Full wallet ownership verification flow."""
        wallet_address = test_wallet["address"]
        vasp_did = "did:web:test-vasp.example.com"

        # Step 1: Issue challenge
        challenge = verifier.create_challenge(wallet_address, vasp_did)
        assert challenge is not None

        # Step 2: Sign challenge
        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)

        # Step 3: Verify signature
        signer = verifier.verify_signature(challenge, signed.signature.hex())
        assert signer is not None
        assert Web3.to_checksum_address(signer) == challenge.wallet_address

        # Step 4: Create attestation
        attestation = verifier.create_attestation(challenge, signed.signature.hex())
        assert attestation is not None
        assert attestation.wallet_address == challenge.wallet_address
        assert attestation.vasp_did == vasp_did

        # Step 5: Verify attestation is valid
        assert verifier.is_attestation_valid(attestation.attestation_id) is True

        # Step 6: Can retrieve active attestation
        active = verifier.get_active_attestation(wallet_address)
        assert active is not None
        assert active.attestation_id == attestation.attestation_id

        # Step 7: Challenge is consumed
        assert verifier.get_pending_challenge(challenge.nonce) is None

    def test_flow_with_revocation(self, verifier, test_wallet):
        """Flow including attestation revocation."""
        wallet_address = test_wallet["address"]
        vasp_did = "did:web:test-vasp.example.com"

        # Complete verification
        challenge = verifier.create_challenge(wallet_address, vasp_did)
        message = (
            f"ClearProof Wallet Ownership Verification\n"
            f"Wallet: {challenge.wallet_address}\n"
            f"VASP: {challenge.vasp_did}\n"
            f"Timestamp: {challenge.timestamp}\n"
            f"Nonce: {challenge.nonce}"
        )
        message_hash = encode_defunct(text=message)
        signed = test_wallet["account"].sign_message(message_hash)
        attestation = verifier.create_attestation(challenge, signed.signature.hex())

        # Verify it's active
        assert verifier.is_attestation_valid(attestation.attestation_id) is True
        assert verifier.get_active_attestation(wallet_address) is not None

        # Revoke it
        verifier.revoke_attestation(attestation.attestation_id)

        # Should no longer be valid or active
        assert verifier.is_attestation_valid(attestation.attestation_id) is False
        assert verifier.get_active_attestation(wallet_address) is None
