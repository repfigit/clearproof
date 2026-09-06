"""Tenant-transactional current proof inspection; never consumes authorization."""

import hashlib
from dataclasses import dataclass, fields

from src.auth.principal import Principal
from src.policy.evaluator import PolicyEvaluation, PolicyFact, PolicyFacts, evaluate_policy
from src.policy.fact_approval import FactTrustStore
from src.policy.model import PolicyTrustError, PolicyTrustStore
from src.protocol.root_snapshot import RootTrustError, RootTrustStore, SignedRootSnapshot, root_scope_id
from src.protocol.transfer import AssetRegistry, Transfer, VerificationContext
from src.protocol.valuation_approval import SignedValuationApproval, ValuationTrustStore
from src.prover.pilot_current import inspect_current_statement
from src.prover.pilot_roots import CurrentRootPins
from src.prover.pilot_verifier import PairingInspection, PilotPairingVerifier, public_signals
from src.services.enrollment import load_unrevoked_enrollment
from src.services.fact_evidence import load_current_facts
from src.services.policy_activation import activation_scope, load_active_policy
from src.storage.database import Database
from src.storage.pilot import PilotStore, PilotTransaction
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

        This serializes with supported enrollment/revocation/root/policy writers.
        Other trust inventories remain operator configuration; this is not an
        independent historical authority. No record or consumption is written.
        """
        self._principal.require("proof:inspect")
        self._principal.require("evidence:decrypt")
        signals = public_signals(signals)
        async with self._store.transaction() as tx:
            return await self._inspect_transaction(tx, credential_id, proof, signals, now=now)

    async def _inspect_transaction(self, tx: PilotTransaction, credential_id, proof, signals, *, now):
        configured_policy = self._inputs["policy_trust"].for_transfer(
            self._inputs["transfer"], self._context, tenant_id=self._principal.tenant_id, now=now
        )
        active_policy = await load_active_policy(
            tx, activation_scope(configured_policy), now=now, evaluated_at=self._context.evaluated_at
        )
        if active_policy.digest != configured_policy.digest:
            raise PolicyTrustError("Configured policy is not the active tenant selection")
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

    async def evaluate(
        self,
        credential_id: str,
        proof: bytes,
        signals: list[str],
        fact_ids: tuple[str, ...],
        *,
        fact_trust: FactTrustStore,
        now: int,
    ) -> tuple[PairingInspection, PolicyEvaluation | None]:
        """Read-only policy report using server-selected fact trust; never consume.

        A failed cryptographic check yields no policy decision. Fact trust is
        server configuration, not accepted from a public evaluation request.
        """
        for role in ("proof:inspect", "policy:read", "evidence:decrypt"):
            self._principal.require(role)
        signals = public_signals(signals)
        async with self._store.transaction() as tx:
            external = await load_current_facts(
                tx,
                fact_trust,
                fact_ids,
                transfer=self._inputs["transfer"],
                context=self._context,
                now=now,
            )
            inspection = await self._inspect_transaction(tx, credential_id, proof, signals, now=now)
            if not inspection.cryptographic_valid:
                return inspection, None
            derived = tuple(
                PolicyFact(
                    predicate=predicate,
                    value=True,
                    observed_at=now,
                    expires_at=int(signals[5]),
                    evidence_digest=hashlib.sha256(proof).hexdigest(),
                )
                for predicate in ("credential_valid", "sanctions_clear", "valuation_authenticated", "proof_valid")
            )
            facts = PolicyFacts(
                tenant_id=self._principal.tenant_id,
                transfer_digest=self._context.transfer_digest,
                facts=(*external.facts, *derived),
            )
            policy = self._inputs["policy_trust"].for_transfer(
                self._inputs["transfer"],
                self._context,
                tenant_id=self._principal.tenant_id,
                now=now,
            )
            return inspection, evaluate_policy(policy, self._inputs["transfer"], self._context, facts, now=now)
