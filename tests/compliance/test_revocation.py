"""
Compliance tests for credential revocation.

Tests that revoked credentials are properly blocked by the
CredentialRegistry, preventing them from being used for proof generation.
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from src.registry.credential_registry import CredentialRegistry, zkKYCCredential


@pytest.fixture
def _mock_poseidon():
    """Patch Poseidon hash to avoid requiring Node.js."""
    async def fake_poseidon(inputs):
        return str(sum(int(x) for x in inputs))

    with patch(
        "src.registry.credential_registry._poseidon_hash",
        side_effect=fake_poseidon,
    ):
        yield


class TestCredentialRevocation:
    @pytest.mark.asyncio
    async def test_revoked_credential_is_blocked(
        self, _mock_poseidon, sample_credential: dict
    ):
        """A revoked credential is marked as revoked in the registry."""
        registry = CredentialRegistry()
        credential = zkKYCCredential(**sample_credential)

        # Issue the credential
        commitment = await registry.issue(credential)
        assert commitment is not None
        assert not registry.is_revoked(credential.credential_id)

        # Revoke the credential
        registry.revoke(credential.credential_id)

        # Verify it is now blocked
        assert registry.is_revoked(credential.credential_id)

        # The credential object itself is also marked revoked
        stored = registry.get(credential.credential_id)
        assert stored is not None
        assert stored.revoked is True

    @pytest.mark.asyncio
    async def test_revoke_unknown_credential_raises(self, _mock_poseidon):
        """Revoking an unknown credential raises KeyError."""
        registry = CredentialRegistry()

        with pytest.raises(KeyError, match="Unknown credential"):
            registry.revoke("nonexistent-id")

    @pytest.mark.asyncio
    async def test_commitment_survives_revocation(
        self, _mock_poseidon, sample_credential: dict
    ):
        """The Poseidon commitment remains accessible after revocation."""
        registry = CredentialRegistry()
        credential = zkKYCCredential(**sample_credential)

        commitment = await registry.issue(credential)
        registry.revoke(credential.credential_id)

        # Commitment should still be retrievable
        assert registry.get_commitment(credential.credential_id) == commitment

    @pytest.mark.asyncio
    async def test_issue_and_get(self, _mock_poseidon, sample_credential: dict):
        """Issued credentials can be retrieved by ID."""
        registry = CredentialRegistry()
        credential = zkKYCCredential(**sample_credential)

        await registry.issue(credential)

        retrieved = registry.get(credential.credential_id)
        assert retrieved is not None
        assert retrieved.issuer_did == credential.issuer_did
        assert retrieved.subject_wallet == credential.subject_wallet

    def test_get_nonexistent_returns_none(self):
        """Getting a non-existent credential returns None."""
        registry = CredentialRegistry()
        assert registry.get("does-not-exist") is None

    def test_get_commitment_nonexistent_raises(self):
        """Getting commitment for non-existent credential raises KeyError."""
        registry = CredentialRegistry()
        with pytest.raises(KeyError, match="No commitment"):
            registry.get_commitment("does-not-exist")
