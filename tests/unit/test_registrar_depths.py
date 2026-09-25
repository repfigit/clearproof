"""Registrar tree-depth configuration is validated before any storage access."""

import pytest

from src.auth.principal import Principal
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, ISSUER_TREE_DEPTH
from src.services.registrar import PilotRegistrar

PRINCIPAL = Principal(tenant_id="tenant-a", actor_id="registrar", roles=("tenant:admin", "evidence:decrypt"))
ISSUERS = ("did:web:a.example", "did:web:b.example", "did:web:c.example")


def construct(**depths):
    # Storage, trust and signer are unused: validation must fail before touching them.
    return PilotRegistrar(
        None, None, PRINCIPAL, None, None, issuers=ISSUERS, chain_id=31337, registry_address="0x" + "1" * 40, **depths
    )


def test_defaults_follow_the_current_profile_depths():
    registrar = construct()
    assert (registrar._issuance_depth, registrar._issuer_depth) == (ISSUANCE_TREE_DEPTH, ISSUER_TREE_DEPTH)


@pytest.mark.parametrize("issuer_depth", [0, 33, True, "20", 1])
def test_invalid_or_too_small_issuer_depth_rejected(issuer_depth):
    # Depth 1 holds two leaves, fewer than the three configured issuers.
    with pytest.raises(ValueError, match="^Issuer tree depth must be 1–32 and fit the configured issuers$"):
        construct(issuer_depth=issuer_depth)


@pytest.mark.parametrize("issuance_depth", [0, 33])
def test_invalid_issuance_depth_rejected(issuance_depth):
    with pytest.raises(ValueError):
        construct(issuance_depth=issuance_depth)
