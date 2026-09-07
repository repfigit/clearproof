"""Independent current root checks for the pilot proof profile; no consumption."""

from dataclasses import dataclass

from pydantic import Field, model_validator

from src.protocol.discovery_profile import parse_target
from src.protocol.root_snapshot import RootSnapshot, RootTrustError, RootTrustStore, SignedRootSnapshot
from src.protocol.transfer import Address, Hex32, OpaqueId, Record, VerificationContext


class CurrentRootPins(Record):
    """Operator/current-state configuration. Never accept these pins from a proof request."""

    tenant_id: OpaqueId
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    issuer_did: str = Field(max_length=512)
    issuance_digest: Hex32
    issuer_digest: Hex32
    sanctions_digest: Hex32

    @model_validator(mode="after")
    def scope(self):
        if int(self.registry_address, 16) == 0 or parse_target(self.issuer_did).did != self.issuer_did:
            raise ValueError("Invalid current root scope")
        return self


@dataclass(frozen=True)
class VerifiedPilotRoots:
    issuance: RootSnapshot
    issuers: RootSnapshot
    sanctions: RootSnapshot
    checked_at: int


def verify_pilot_roots(
    *,
    trust: RootTrustStore,
    pins: CurrentRootPins,
    context: VerificationContext,
    issuance: SignedRootSnapshot,
    issuers: SignedRootSnapshot,
    sanctions: SignedRootSnapshot,
    now: int,
) -> VerifiedPilotRoots:
    """Verify exact current heads at both proof evaluation and verifier time.

    A valid signature does not make a head current. Pins must be read from a
    separately trusted source, consistently with the eventual consumption
    transaction. This function checks neither revocation nor holder membership.
    """
    pins = CurrentRootPins.model_validate(pins)
    context = VerificationContext.model_validate(context)
    if (
        type(now) is not int
        or not context.evaluated_at <= now <= 2**53 - 1
        or context.proof_profile != "pilot-transfer-v2"
        or (context.tenant_id, context.deployment_chain_id, context.deployment_address)
        != (pins.tenant_id, str(pins.chain_id), pins.registry_address)
        or (context.issuance_snapshot_digest, context.issuer_snapshot_digest, context.sanctions_snapshot_digest)
        != (pins.issuance_digest, pins.issuer_digest, pins.sanctions_digest)
    ):
        raise RootTrustError("Root pins do not match the pilot verification context")
    verified = []
    for signed, kind, expected in (
        (issuance, "issuance-root", pins.issuance_digest),
        (issuers, "issuer-root", pins.issuer_digest),
        (sanctions, "sanctions-root", pins.sanctions_digest),
    ):
        snapshot = trust.verify_current(
            signed,
            now=now,
            expected_digest=expected,
            tenant_id=pins.tenant_id,
            chain_id=pins.chain_id,
            registry_address=pins.registry_address,
            kind=kind,
        )
        trust.verify_historical(signed, evaluated_at=context.evaluated_at)
        if snapshot.tree_depth != 8 or (kind == "issuance-root" and snapshot.issuer_did != pins.issuer_did):
            raise RootTrustError("Root does not match the pilot tree or credential issuer")
        verified.append(snapshot)
    return VerifiedPilotRoots(*verified, checked_at=now)
