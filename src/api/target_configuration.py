"""Load operator-owned inspection and authorization targets at API startup.

The pilot inspect, evaluate, observe and authorize routes read their trust from
``app.state.pilot_inspection_targets`` and ``app.state.pilot_authorization_targets``.
These loaders fill that state from operator code, the same way
``PILOT_PROVING_FACTORY`` supplies proving targets:

- ``PILOT_INSPECTION_FACTORY=module:callable`` returns a mapping from
  ``(tenant_id, target_id)`` to ``InspectionTarget``.
- ``PILOT_AUTHORIZATION_FACTORY=module:callable`` returns the same shape with
  ``AuthorizationTarget`` values.

Each callable accepts ``(Database, RecordCipher)`` and may be asynchronous. It
is trusted deployment code: the reference comes only from the process
environment, never from a request. An unset variable leaves the capability
unconfigured (routes answer 503); a set variable that fails to load stops
startup, so a misconfigured deployment never serves with partial trust.
"""

import os

from src.api.routes.authorization import AuthorizationTarget
from src.api.routes.pilot_proof import InspectionTarget
from src.policy.fact_approval import FactTrustStore
from src.protocol.decision_attestation import DecisionSigner
from src.protocol.information_approval import InformationTrustStore
from src.prover.pilot_verifier import PilotPairingVerifier
from src.sar.pilot_envelope import RecipientTrustStore
from src.services.authorization_input import SealedAuthorizationInformation
from src.services.proof_inspection import CurrentStatementConfiguration
from src.services.proving_configuration import FACTORY_REFERENCE, call_operator_factory


def _check_inspection_target(tenant_id: str, target: InspectionTarget) -> None:
    config = target.configuration
    if not isinstance(config, CurrentStatementConfiguration):
        raise ValueError("configuration")
    if (config.context.tenant_id, config.transfer.tenant_id, config.root_pins.tenant_id) != (tenant_id,) * 3:
        raise ValueError("scope")
    if not isinstance(target.verifier, PilotPairingVerifier):
        raise ValueError("verifier")
    target.verifier.artifacts.check_artifact_context(config.context)
    if target.fact_trust is not None and not isinstance(target.fact_trust, FactTrustStore):
        raise ValueError("fact trust")


def _check_authorization_target(tenant_id: str, target: AuthorizationTarget) -> None:
    _check_inspection_target(tenant_id, target)
    authorities = (
        (target.fact_trust, FactTrustStore),
        (target.information, SealedAuthorizationInformation),
        (target.information_trust, InformationTrustStore),
        (target.decision_signer, DecisionSigner),
        (target.recipient_trust, RecipientTrustStore),
        (target.recipient_key_id, str),
    )
    if not all(isinstance(value, expected) for value, expected in authorities) or not target.recipient_key_id:
        raise ValueError("authority")


async def _load(variable: str, label: str, target_type: type, check, db, cipher) -> dict:
    factory = os.getenv(variable, "")
    if not factory:
        return {}
    if db is None or not FACTORY_REFERENCE.fullmatch(factory):
        raise RuntimeError(f"Invalid operator {label} factory configuration")
    try:
        targets = await call_operator_factory(factory, db, cipher)
        for (tenant_id, _), target in targets.items():
            # Exact type: an AuthorizationTarget is not accepted as an inspection
            # target, so signing and recipient authority stay out of read-only routes.
            if type(target) is not target_type:
                raise ValueError("target")
            check(tenant_id, target)
        return targets
    except Exception:
        raise RuntimeError(f"Operator {label} configuration could not be loaded") from None


async def load_inspection_targets(db, cipher) -> dict:
    """Targets for the read-only inspect, evaluate, observe and readiness routes."""
    return await _load("PILOT_INSPECTION_FACTORY", "inspection", InspectionTarget, _check_inspection_target, db, cipher)


async def load_authorization_targets(db, cipher) -> dict:
    """Targets for ``POST /pilot/proof/authorize``, which consumes an authorization."""
    return await _load(
        "PILOT_AUTHORIZATION_FACTORY", "authorization", AuthorizationTarget, _check_authorization_target, db, cipher
    )
