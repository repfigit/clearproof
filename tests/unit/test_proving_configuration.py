"""Operator configuration import is bounded, scoped and exception-redacted."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from src.services.proof_jobs import ProvingTarget
from src.services.proving_configuration import load_proving_targets


@pytest.fixture
def factory(monkeypatch):
    module = ModuleType("synthetic_proving_factory")
    configuration = SimpleNamespace(
        context=SimpleNamespace(tenant_id="tenant-a"),
        transfer=SimpleNamespace(tenant_id="tenant-a"),
        sanctions=SimpleNamespace(snapshot=SimpleNamespace(root="1")),
    )
    artifacts = SimpleNamespace(check_artifact_context=lambda context: None)
    target = ProvingTarget(
        configuration, SimpleNamespace(verifier=SimpleNamespace(artifacts=artifacts)), SimpleNamespace(root="1")
    )
    targets = {("tenant-a", "target-a"): target}
    module.configure = lambda db, cipher: targets
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv("PILOT_PROVING_FACTORY", module.__name__ + ":configure")
    return module, targets, target


async def test_absent_operator_factory_does_not_import_or_require_storage(monkeypatch):
    monkeypatch.delenv("PILOT_PROVING_FACTORY", raising=False)
    assert await load_proving_targets(None, None) == {}


async def test_sync_and_async_operator_factory(factory):
    module, targets, _ = factory
    assert await load_proving_targets(object(), object()) is targets

    async def configure(db, cipher):
        return targets

    module.configure = configure
    assert await load_proving_targets(object(), object()) is targets


@pytest.mark.parametrize("value", ["bad-reference", "a:b:c", "../private.py:run"])
async def test_invalid_factory_reference(value, monkeypatch):
    monkeypatch.setenv("PILOT_PROVING_FACTORY", value)
    with pytest.raises(RuntimeError, match="Invalid operator"):
        await load_proving_targets(object(), None)


async def test_configured_factory_requires_connected_storage(factory):
    with pytest.raises(RuntimeError, match="Invalid operator"):
        await load_proving_targets(None, None)


@pytest.mark.parametrize("value", [{}, [], None, {"wrong": None}, {("a",): None}, {("a", "b"): None}])
async def test_bad_mapping_and_private_factory_exceptions_are_sanitized(factory, value):
    module, _, _ = factory
    module.configure = lambda db, cipher: value
    with pytest.raises(RuntimeError, match="^Operator proving configuration could not be loaded$"):
        await load_proving_targets(object(), None)


@pytest.mark.parametrize(
    "attack", ["identifier", "context-tenant", "transfer-tenant", "artifact", "sanctions", "exception", "capacity"]
)
async def test_target_scope_artifact_and_inventory_checks(factory, attack):
    module, targets, target = factory
    if attack == "identifier":
        module.configure = lambda db, cipher: {("PRIVATE EMAIL", "target"): target}
    elif attack == "context-tenant":
        target.configuration.context.tenant_id = "tenant-b"
    elif attack == "transfer-tenant":
        target.configuration.transfer.tenant_id = "tenant-b"
    elif attack == "sanctions":
        target.sanctions.root = "2"
    elif attack == "capacity":
        module.configure = lambda db, cipher: {("tenant-a", f"target-{n}"): target for n in range(257)}
    else:

        def fail(*args):
            raise ValueError("SYNTHETIC-PRIVATE-DETAIL")

        if attack == "artifact":
            target.prover.verifier.artifacts.check_artifact_context = fail
        else:
            module.configure = fail
    with pytest.raises(RuntimeError, match="^Operator proving configuration could not be loaded$"):
        await load_proving_targets(object(), None)
