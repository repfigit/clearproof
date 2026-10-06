"""Owned synthetic tenant provisioning for actual proving-job acceptance."""

import hashlib
import os
import shutil
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account

from src.auth.principal import Principal
from src.policy.diff import PolicyCase
from src.policy.evaluator import PolicyFacts
from src.protocol.enrollment import EnrollmentConsent
from src.protocol.root_snapshot import SignedRootSnapshot, root_scope_id
from src.protocol.transfer import VerificationContext
from src.prover.pilot_prover import PilotProver
from src.prover.pilot_roots import CurrentRootPins
from src.registry.pilot_sanctions import PilotSanctionsTree
from src.services.enrollment import EnrollmentService
from src.services.policy_activation import PolicyActivationRequest, PolicyActivationService
from src.services.policy_review import PolicyReviewRequest, PolicyReviewService, ReviewedCase
from src.services.proof_inspection import CurrentStatementConfiguration
from src.services.proof_jobs import ProofJobService, ProvingTarget
from src.services.registrar import PilotRegistrar
from src.services.root_publication import RootPublicationService
from src.storage.pilot import PilotStore
from tests.integration.test_pilot_storage import ROLES, cipher
from tests.unit.test_pilot_compliance import synthetic_case


async def provision(db):
    root = Path(os.environ["CLEARPROOF_PILOT_TEST_ARTIFACTS"])
    runtime = Path(__file__).parents[2] / "node_modules/snarkjs/build/snarkjs.min.js"
    prover = PilotProver.load(
        root,
        trusted_digest=(root / "development-manifest-pin.txt").read_text().strip(),
        bundle_path=runtime,
        bundle_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
        node=Path(shutil.which("node")),
    )
    _, _, inputs = synthetic_case(
        artifact_manifest_digest=prover.verifier.artifacts.manifest.digest,
        with_trust=True,
        evaluated_at=int(time.time()),
    )
    credential, now = inputs.pop("credential"), inputs.pop("now")
    operator = Principal(
        tenant_id=credential.tenant_id,
        actor_id="job-operator",
        roles=(*ROLES, "policy:activate", "policy:read"),
        issuer_dids=(credential.issuer_did,),
    )
    who = Principal(
        tenant_id=operator.tenant_id, actor_id="job-holder", roles=("proof:generate", "policy:read", "evidence:decrypt")
    )
    pins = inputs["root_pins"]
    consent = EnrollmentConsent(
        credential=credential,
        chain_id=pins.chain_id,
        registry_address=pins.registry_address,
        consent_expires_at=min(credential.issued_at + 600, credential.expires_at),
    )
    wallet = Account.from_key(bytes([8]) * 32)
    await EnrollmentService(
        db, cipher(), operator, chain_id=pins.chain_id, registry_address=pins.registry_address
    ).enroll(
        consent,
        "0x" + wallet.sign_message(consent.signing_message()).signature.hex(),
        idempotency_key="enroll",
        now=credential.issued_at,
    )
    await PilotRegistrar(
        db,
        cipher(),
        operator,
        inputs["root_trust"],
        Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32),
        issuers=(credential.issuer_did,),
        chain_id=pins.chain_id,
        registry_address=pins.registry_address,
    ).refresh(expected_revision=0, idempotency_key="registrar", now=now, ttl=credential.expires_at - now)
    store = PilotStore(db, cipher(), operator)
    async with store.transaction() as tx:
        for name in ("issuance", "issuers"):
            snapshot = inputs[name].snapshot
            inputs[name] = SignedRootSnapshot.model_validate(await tx.get(snapshot.kind, root_scope_id(snapshot)))
    inputs["root_pins"] = CurrentRootPins.model_validate(
        {
            **pins.model_dump(),
            "issuance_digest": inputs["issuance"].snapshot.digest,
            "issuer_digest": inputs["issuers"].snapshot.digest,
        }
    )
    inputs["context"] = VerificationContext.model_validate(
        {
            **inputs["context"].model_dump(),
            "issuance_snapshot_digest": inputs["issuance"].snapshot.digest,
            "issuer_snapshot_digest": inputs["issuers"].snapshot.digest,
        }
    )
    await RootPublicationService(db, cipher(), operator, inputs["root_trust"]).publish(
        inputs["sanctions"], idempotency_key="sanctions", now=now
    )
    policy = inputs["policy_trust"].for_transfer(
        inputs["transfer"], inputs["context"], tenant_id=operator.tenant_id, now=now
    )
    case = PolicyCase(
        case_id="job-acceptance",
        transfer=inputs["transfer"],
        context=inputs["context"],
        facts=PolicyFacts(tenant_id=operator.tenant_id, transfer_digest=inputs["transfer"].digest, facts=()),
        evaluated_at=now,
    )
    await PolicyReviewService(db, cipher(), operator).approve(
        PolicyReviewRequest(policy=policy, cases=(ReviewedCase(case=case, expected="INDETERMINATE"),)),
        idempotency_key="review",
        now=now,
    )
    await PolicyActivationService(db, cipher(), operator).activate(
        PolicyActivationRequest(policy_digest=policy.digest), idempotency_key="activate", now=now
    )
    target = ProvingTarget(CurrentStatementConfiguration(**inputs), prover, PilotSanctionsTree([]))
    targets = {(who.tenant_id, "synthetic-target"): target}
    return ProofJobService(db, cipher(), targets), who, operator, credential
