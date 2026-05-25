"""ZK Travel Rule — Local proving infrastructure."""

from .snarkjs_prover import SnarkJSProver
from .tier_mapping import JURISDICTION_TIERS, compute_tier
from .verifier import verify_proof

__all__ = [
    "SnarkJSProver",
    "verify_proof",
    "JURISDICTION_TIERS",
    "compute_tier",
]
