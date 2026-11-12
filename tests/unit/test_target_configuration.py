"""Inspection and authorization targets load from operator code, scoped and exception-redacted."""

import shutil
import sys
from dataclasses import fields, replace
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from src.api import target_configuration as loader
from src.api.routes.authorization import AuthorizationTarget
from src.api.routes.pilot_proof import InspectionTarget
from src.policy.fact_approval import FactTrustStore
from src.protocol.decision_attestation import DecisionSigner
from src.protocol.information_approval import InformationTrustStore
from src.prover.pilot_verifier import PilotPairingVerifier
from src.sar.pilot_envelope import RecipientTrustStore
from src.services.authorization_input import SealedAuthorizationInformation
from src.services.proof_inspection import CurrentStatementConfiguration
from tests.unit.test_pilot_current import current_case as current_case  # noqa: F401

CASES = {
    "inspection": ("PILOT_INSPECTION_FACTORY", loader.load_inspection_targets),
    "authorization": ("PILOT_AUTHORIZATION_FACTORY", loader.load_authorization_targets),
}


def placeholder(cls):
    """An instance for type checks only; the loader never calls into these authorities."""
    return object.__new__(cls)


@pytest.fixture
def targets(current_case):
    case = current_case
    config = CurrentStatementConfiguration(**{f.name: case[f.name] for f in fields(CurrentStatementConfiguration)})
    verifier = PilotPairingVerifier(case["artifacts"], b"SYNTHETIC-UNUSED-RUNTIME", Path(shutil.which("node")))
    inspection = InspectionTarget(config, verifier)
    authorization = AuthorizationTarget(
        configuration=config,
        verifier=verifier,
        fact_trust=placeholder(FactTrustStore),
        information=placeholder(SealedAuthorizationInformation),
        information_trust=placeholder(InformationTrustStore),
        decision_signer=placeholder(DecisionSigner),
        recipient_trust=placeholder(RecipientTrustStore),
        recipient_key_id="recipient-key-1",
    )
    return config.context.tenant_id, {"inspection": inspection, "authorization": authorization}


@pytest.fixture(params=sorted(CASES))
def factory(request, targets, monkeypatch):
    kind = request.param
    variable, load = CASES[kind]
    tenant_id, by_kind = targets
    module = ModuleType("synthetic_target_factory")
    mapping = {(tenant_id, "target-a"): by_kind[kind]}
    module.configure = lambda db, cipher: mapping
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv(variable, module.__name__ + ":configure")
    return SimpleNamespace(
        kind=kind, variable=variable, load=load, module=module, mapping=mapping, tenant_id=tenant_id, by_kind=by_kind
    )


def use(factory, target, key=None):
    factory.module.configure = lambda db, cipher: {key or (factory.tenant_id, "target-a"): target}


async def test_absent_factory_does_not_import_or_require_storage(factory, monkeypatch):
    monkeypatch.delenv(factory.variable)
    assert await factory.load(None, None) == {}


async def test_sync_and_async_factory_receive_storage_and_cipher(factory):
    db, cipher, seen = object(), object(), []
    mapping = factory.mapping

    def configure(*args):
        seen.append(args)
        return mapping

    factory.module.configure = configure
    assert await factory.load(db, cipher) is mapping

    async def configure_async(*args):
        seen.append(args)
        return mapping

    factory.module.configure = configure_async
    assert await factory.load(db, cipher) is mapping
    assert seen == [(db, cipher)] * 2


@pytest.mark.parametrize("value", ["bad-reference", "a:b:c", "../private.py:run"])
async def test_invalid_factory_reference(factory, monkeypatch, value):
    monkeypatch.setenv(factory.variable, value)
    with pytest.raises(RuntimeError, match=f"^Invalid operator {factory.kind} factory configuration$"):
        await factory.load(object(), None)


async def test_configured_factory_requires_connected_storage(factory):
    with pytest.raises(RuntimeError, match="^Invalid operator"):
        await factory.load(None, None)


@pytest.mark.parametrize("value", [{}, [], None, {"wrong": None}, {("a",): None}, {("a", "b"): None}])
async def test_bad_mapping_is_rejected_with_a_fixed_message(factory, value):
    factory.module.configure = lambda db, cipher: value
    with pytest.raises(RuntimeError, match=f"^Operator {factory.kind} configuration could not be loaded$"):
        await factory.load(object(), None)


@pytest.mark.parametrize(
    "attack",
    [
        "identifier",
        "capacity",
        "exception",
        "foreign-tenant-key",
        "configuration-type",
        "verifier-type",
        "artifact-context",
        "fact-trust-type",
        "other-target-kind",
    ],
)
async def test_scope_type_artifact_and_inventory_checks(factory, attack):
    target = factory.mapping[(factory.tenant_id, "target-a")]

    def fail(*args):
        raise ValueError("SYNTHETIC-PRIVATE-DETAIL")

    if attack == "identifier":
        use(factory, target, ("PRIVATE EMAIL", "target-a"))
    elif attack == "capacity":
        factory.module.configure = lambda db, cipher: {(factory.tenant_id, f"target-{n}"): target for n in range(257)}
    elif attack == "exception":
        factory.module.configure = fail
    elif attack == "foreign-tenant-key":
        use(factory, target, ("tenant-other", "target-a"))
    elif attack == "configuration-type":
        use(factory, replace(target, configuration=SimpleNamespace()))
    elif attack == "verifier-type":
        use(factory, replace(target, verifier=SimpleNamespace(artifacts=target.verifier.artifacts)))
    elif attack == "artifact-context":
        artifacts = SimpleNamespace(check_artifact_context=fail)
        use(factory, replace(target, verifier=replace(target.verifier, artifacts=artifacts)))
    elif attack == "fact-trust-type":
        use(factory, replace(target, fact_trust=SimpleNamespace()))
    else:
        # Signing and recipient authority must not ride into read-only routes, and a
        # read-only target cannot stand in for an authorization target.
        other = "authorization" if factory.kind == "inspection" else "inspection"
        use(factory, factory.by_kind[other])
    with pytest.raises(RuntimeError, match=f"^Operator {factory.kind} configuration could not be loaded$") as raised:
        await factory.load(object(), None)
    assert "SYNTHETIC-PRIVATE-DETAIL" not in str(raised.value) and raised.value.__cause__ is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("fact_trust", None),
        ("information", SimpleNamespace()),
        ("information_trust", SimpleNamespace()),
        ("decision_signer", SimpleNamespace()),
        ("recipient_trust", SimpleNamespace()),
        ("recipient_key_id", ""),
        ("recipient_key_id", 7),
    ],
)
async def test_authorization_target_requires_every_authority(targets, monkeypatch, field, value):
    tenant_id, by_kind = targets
    module = ModuleType("synthetic_authorization_factory")
    module.configure = lambda db, cipher: {(tenant_id, "target-a"): replace(by_kind["authorization"], **{field: value})}
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv("PILOT_AUTHORIZATION_FACTORY", module.__name__ + ":configure")
    with pytest.raises(RuntimeError, match="^Operator authorization configuration could not be loaded$"):
        await loader.load_authorization_targets(object(), None)


async def test_inspection_target_accepts_optional_fact_trust(targets, monkeypatch):
    tenant_id, by_kind = targets
    target = replace(by_kind["inspection"], fact_trust=placeholder(FactTrustStore))
    module = ModuleType("synthetic_inspection_factory")
    module.configure = lambda db, cipher: {(tenant_id, "target-a"): target}
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv("PILOT_INSPECTION_FACTORY", module.__name__ + ":configure")
    assert (await loader.load_inspection_targets(object(), None))[(tenant_id, "target-a")] is target
