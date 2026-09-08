"""Issuer tree inputs must name a usable deployment before touching tenant state."""

from unittest.mock import Mock

import pytest

from src.services.issuance_tree import IssuanceTreeContext, build_issuance_tree
from src.storage.pilot import PilotTransaction


@pytest.mark.asyncio
async def test_zero_registry_rejected_before_transaction_access():
    valid = {
        "issuer_did": "did:web:issuer.example",
        "chain_id": 1,
        "registry_address": "0x" + "12" * 20,
        "now": 100,
        "depth": 8,
    }
    assert IssuanceTreeContext(**valid).model_dump() == valid
    tx = Mock(spec=PilotTransaction)
    invalid = {**valid, "registry_address": "0x" + "00" * 20}
    with pytest.raises(ValueError, match="Invalid issuance tree context"):
        await build_issuance_tree(tx, **invalid)
    assert tx.mock_calls == []
    assert IssuanceTreeContext(**valid).model_dump() == valid
