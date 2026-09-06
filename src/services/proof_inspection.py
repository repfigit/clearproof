"""Tenant-transactional current proof inspection; never consumes authorization."""

from dataclasses import dataclass, fields

from src.auth.principal import Principal
from src.policy.model import PolicyTrustStore
from src.protocol.root_snapshot import RootTrustError, RootTrustStore, SignedRootSnapshot, root_scope_id
from src.protocol.transfer import AssetRegistry, Transfer, VerificationContext
from src.protocol.valuation_approval import SignedValuationApproval, ValuationTrustStore
from src.prover.pilot_current import inspect_current_statement
from src.prover.pilot_roots import CurrentRootPins
from src.prover.pilot_verifier import PairingInspection, PilotPairingVerifier
from src.services.enrollment import load_unrevoked_enrollment
from src.storage.database import Database
from src.storage.pilot import PilotStore
from src.storage.pilot_cipher import RecordCipher


@dataclass(frozen=True, repr=False)
class CurrentStatementConfiguration:
    """Authenticated server configuration and records, never a proof request DTO."""

    transfer: Transfer
    context: VerificationContext
    registry: AssetRegistry
    policy_trust: PolicyTrustStore
    valuation_approval: SignedValuationApproval
    valuation_trust: ValuationTrustStore
    root_trust: RootTrustStore
    root_pins: CurrentRootPins
    issuance: SignedRootSnapshot
    issuers: SignedRootSnapshot
    sanctions: SignedRootSnapshot


class ProofInspectionService:
    def __init__(
        self,
        db: Database,
        cipher: RecordCipher,
        principal: Principal,
        verifier: PilotPairingVerifier,
        configuration: CurrentStatementConfiguration,
    ):
        self._principal = Principal.model_validate(principal)
        if not isinstance(configuration, CurrentStatementConfiguration):
            raise ValueError("Expected server statement configuration")
        self._inputs = {field.name: getattr(configuration, field.name) for field in fields(configuration)}
        self._context = VerificationContext.model_validate(configuration.context)
        self._pins = CurrentRootPins.model_validate(configuration.root_pins)
        if self._context.tenant_id != self._principal.tenant_id or self._pins.tenant_id != self._principal.tenant_id:
            raise ValueError("Statement configuration tenant mismatch")
        self._store = PilotStore(db, cipher, self._principal)
        self._verifier = verifier

    async def inspect(self, credential_id: str, proof: bytes, signals: list[str], *, now: int) -> PairingInspection:
        """Hold the existing tenant lock across current-state reads and pairing.

        This serializes with supported enrollment/revocation/root writers. Other
        trust inventories are operator configuration; this is not their activation
        or historical authority mechanism. No record or consumption is written.
        """
        self._principal.require("proof:inspect")
        self._principal.require("evidence:decrypt")
        async with self._store.transaction() as tx:
            credential = await load_unrevoked_enrollment(
                tx,
                credential_id,
                chain_id=self._pins.chain_id,
                registry_address=self._pins.registry_address,
                now=now,
            )
            for name in ("issuance", "issuers", "sanctions"):
                signed = SignedRootSnapshot.model_validate(self._inputs[name])
                head = await tx.read(signed.snapshot.kind, root_scope_id(signed.snapshot))
                if head is None:
                    raise RootTrustError("Current root is not retained in this tenant")
                retained = SignedRootSnapshot.model_validate(head.value)
                if head.revision != signed.snapshot.revision or retained != signed:
                    raise RootTrustError("Retained root head differs from configured current approval")
            return await inspect_current_statement(
                self._verifier, proof, signals=signals, credential=credential, now=now, **self._inputs
            )
