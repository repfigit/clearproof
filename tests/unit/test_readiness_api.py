# SPDX-License-Identifier: Apache-2.0
"""Configuration checks do not pair proofs, spawn provers or consume authorization."""

import asyncio
import contextlib
import shutil
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from src.api.routes import readiness as route
from src.auth.principal import Principal, TenantPrincipalDependency
from src.protocol.valuation_approval import ValuationApproval, ValuationAuthority, ValuationTrustStore, sign_valuation
from src.prover.pilot_native_prover import PilotNativeProver
from src.prover.pilot_prover import PilotProver
from src.prover.pilot_verifier import PilotPairingVerifier
from src.services.proof_inspection import CurrentStatementConfiguration
from src.services.proof_jobs import ProvingTarget
from src.storage.keyring import KeyRing, KeyVersion
from tests.unit.test_pilot_current import current_case as current_case  # noqa: F401


@pytest.fixture
async def api(current_case, tmp_path, monkeypatch):
    case = current_case
    config = CurrentStatementConfiguration(**{f.name: case[f.name] for f in fields(CurrentStatementConfiguration)})
    verifier = PilotPairingVerifier(case["artifacts"], b"SYNTHETIC-UNUSED-RUNTIME", Path(shutil.which("node")))
    root = tmp_path / "bundle"
    prover = PilotProver(verifier, root)
    who = Principal(tenant_id=config.context.tenant_id, actor_id="operator-a", roles=("usage:read",))
    cur = SimpleNamespace(
        execute=AsyncMock(),
        fetchone=AsyncMock(return_value=(1,)),
        fetchall=AsyncMock(return_value=[(n,) for n in range(1, route.SCHEMA_VERSION + 1)]),
    )

    @contextlib.asynccontextmanager
    async def cursor():
        yield cur

    @contextlib.asynccontextmanager
    async def transaction():
        yield

    conn = SimpleNamespace(cursor=cursor, transaction=transaction)

    @contextlib.asynccontextmanager
    async def connection():
        yield conn

    database = SimpleNamespace(is_ready=True, connection=connection)
    app = FastAPI()
    app.include_router(route.router)
    app.state.db = database
    app.state.pilot_inspection_targets = {(who.tenant_id, "target-a"): route.InspectionTarget(config, verifier)}
    app.state.pilot_proving_targets = {
        (who.tenant_id, "target-a"): ProvingTarget(config, prover, SimpleNamespace(root=config.sanctions.snapshot.root))
    }
    app.dependency_overrides[TenantPrincipalDependency] = lambda: who
    monkeypatch.setattr(route, "load_keyring", lambda: KeyRing(KeyVersion("current", b"a" * 32, 0)))
    monkeypatch.setattr(route.time, "time", lambda: case["now"])
    monkeypatch.setattr(PilotPairingVerifier, "inspect", AsyncMock(side_effect=AssertionError("Unexpected pairing")))
    monkeypatch.setattr(PilotProver, "prove", AsyncMock(side_effect=AssertionError("Unexpected proving")))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://synthetic.local") as client:
        yield SimpleNamespace(
            client=client,
            app=app,
            who=who,
            config=config,
            cur=cur,
            database=database,
            prover=prover,
            verifier=verifier,
            now=case["now"],
            root=root,
        )


@pytest.mark.parametrize("capability", ["inspection", "proving"])
async def test_ready_is_minimized_scoped_readonly_configuration_report(api, capability):
    response = await api.client.get(f"/pilot/readiness/{capability}/target-a")
    assert response.status_code == 200
    body = response.json()
    assert body["checks"] == dict(database=True, migration_history=True, storage_key=True, target_configuration=True)
    assert body["scope"] == "configured-target-preflight"
    assert body["authorization_consumed"] is body["current_state_checked"] is body["production_eligible"] is False
    assert response.headers["Cache-Control"] == "no-store"
    assert api.who.tenant_id not in response.text
    assert api.config.context.deployment_address not in response.text
    statements = api.cur.execute.call_args_list
    assert statements[0].args == ("SET TRANSACTION READ ONLY",)
    assert statements[1].args == ("SET LOCAL statement_timeout = '1500ms'",)
    assert statements[-1].args[-1] == (route.SCHEMA_VERSION + 1,)
    assert not any(word in str(statements).upper() for word in ("INSERT", "UPDATE", "DELETE"))
    api.verifier.inspect.assert_not_called()
    api.prover.prove.assert_not_called()


@pytest.mark.parametrize("capability", ["inspection", "proving"])
async def test_valuation_signed_after_evaluation_is_not_ready_even_if_valid_now(api, monkeypatch, capability):
    config = api.config
    evaluated_at = config.context.evaluated_at
    now = evaluated_at + 2
    key = Ed25519PrivateKey.generate()
    authority = ValuationAuthority(
        public_key=key.public_key().public_bytes_raw().hex(),
        tenant_id=api.who.tenant_id,
        asset_registry_digest=config.registry.digest,
        asset_ids=(config.transfer.asset_id,),
        source_ids=(config.transfer.valuation.source_id,),
        not_before=config.transfer.valuation.observed_at,
        not_after=config.transfer.valuation.expires_at,
        max_quote_lifetime_seconds=600,
        max_observation_age_seconds=300,
    )
    approval = sign_valuation(
        ValuationApproval(
            tenant_id=api.who.tenant_id,
            asset_registry_digest=config.registry.digest,
            valuation=config.transfer.valuation,
            signed_at=evaluated_at + 1,
            key_id=authority.key_id,
        ),
        key,
    )
    trust = ValuationTrustStore([authority])
    assert (
        trust.verify_for_transfer(approval, config.transfer, config.registry, tenant_id=api.who.tenant_id, now=now)
        == approval.approval
    )
    with pytest.raises(ValueError, match="outside its validity interval"):
        trust.verify_for_transfer(
            approval, config.transfer, config.registry, tenant_id=api.who.tenant_id, now=evaluated_at
        )
    config = replace(config, valuation_approval=approval, valuation_trust=trust)
    api.app.state.pilot_inspection_targets[(api.who.tenant_id, "target-a")] = route.InspectionTarget(
        config, api.verifier
    )
    target = api.app.state.pilot_proving_targets[(api.who.tenant_id, "target-a")]
    api.app.state.pilot_proving_targets[(api.who.tenant_id, "target-a")] = replace(target, configuration=config)
    monkeypatch.setattr(route.time, "time", lambda: now)
    response = await api.client.get(f"/pilot/readiness/{capability}/target-a")
    assert response.status_code == 503 and response.json()["checks"]["target_configuration"] is False
    api.verifier.inspect.assert_not_called()
    api.prover.prove.assert_not_called()


async def test_missing_role_query_selectors_and_malformed_paths_fail_before_database(api):
    assert (await api.client.get("/pilot/readiness/inspection/target-a?tenant=other")).status_code == 422
    assert (await api.client.get("/pilot/readiness/unknown/target-a")).status_code == 422
    assert (await api.client.get("/pilot/readiness/inspection/invalid!id")).status_code == 422
    api.app.dependency_overrides[TenantPrincipalDependency] = lambda: Principal(
        tenant_id=api.who.tenant_id, actor_id="operator-a", roles=("tenant:admin",)
    )
    assert (await api.client.get("/pilot/readiness/inspection/target-a")).status_code == 403
    api.cur.execute.assert_not_called()


async def test_missing_authentication_is_rejected_before_preflight(api):
    api.app.dependency_overrides.clear()
    assert (await api.client.get("/pilot/readiness/inspection/target-a")).status_code == 401
    api.cur.execute.assert_not_called()


def test_generated_openapi_describes_both_report_statuses(api):
    schema = api.app.openapi()
    responses = schema["paths"]["/pilot/readiness/{capability}/{target_id}"]["get"]["responses"]
    for status in ("200", "503"):
        assert responses[status]["content"]["application/json"]["schema"]["$ref"].endswith("/ReadinessReport")


@pytest.mark.parametrize("versions", [[], [(1,)], [(n,) for n in range(1, route.SCHEMA_VERSION + 2)], [(2,)]])
async def test_missing_old_future_and_gapped_schema_is_not_ready(api, versions):
    api.cur.fetchall.return_value = versions
    response = await api.client.get("/pilot/readiness/inspection/target-a")
    assert response.status_code == 503
    assert response.json()["checks"]["database"] is True
    assert response.json()["checks"]["migration_history"] is False


@pytest.mark.parametrize("failure", ["absent", "closed", "ping", "exception", "timeout"])
async def test_database_outage_and_timeout_are_bounded_and_redacted(api, failure, monkeypatch):
    if failure == "absent":
        api.app.state.db = None
    elif failure == "closed":
        api.database.is_ready = False
    elif failure == "ping":
        api.cur.fetchone.return_value = (0,)
    elif failure == "exception":
        api.cur.execute.side_effect = RuntimeError("SYNTHETIC-PRIVATE-DSN")
    else:
        timeout = asyncio.timeout
        monkeypatch.setattr(route.asyncio, "timeout", lambda seconds: timeout(0.01))

        # An async side effect is required so AsyncMock awaits the delay.
        async def stall(*args):
            await asyncio.sleep(1)

        api.cur.execute.side_effect = stall
    response = await api.client.get("/pilot/readiness/inspection/target-a")
    assert response.status_code == 503
    assert response.json()["checks"]["migration_history"] is False
    assert "PRIVATE" not in response.text


@pytest.mark.parametrize("failure", ["keyring", "open", "mismatch"])
async def test_key_failure_does_not_expose_secret_or_generate_a_replacement(api, monkeypatch, failure):
    if failure == "keyring":

        def fail():
            raise RuntimeError("SYNTHETIC-PRIVATE-KEY")

        monkeypatch.setattr(route, "load_keyring", fail)
    elif failure == "open":

        def fail(*args):
            raise RuntimeError("SYNTHETIC-PRIVATE-KEY")

        monkeypatch.setattr(route.RecordCipher, "open", fail)
    else:
        monkeypatch.setattr(route.RecordCipher, "open", lambda *args: {})
    response = await api.client.get("/pilot/readiness/inspection/target-a")
    assert response.status_code == 503 and response.json()["checks"]["storage_key"] is False
    assert "PRIVATE" not in response.text


@pytest.mark.parametrize("failure", ["none", "subclass", "large", "missing", "type", "config", "foreign", "verifier"])
async def test_unavailable_or_cross_tenant_configuration_is_not_disclosed(api, failure):
    targets = api.app.state.pilot_inspection_targets
    target = targets[(api.who.tenant_id, "target-a")]
    if failure == "none":
        api.app.state.pilot_inspection_targets = None
    elif failure == "subclass":

        class Mapping(dict):
            pass

        api.app.state.pilot_inspection_targets = Mapping(targets)
    elif failure == "large":
        api.app.state.pilot_inspection_targets = {(api.who.tenant_id, f"target-{i}"): target for i in range(257)}
    elif failure == "missing":
        targets.clear()
    elif failure == "type":
        targets[(api.who.tenant_id, "target-a")] = object()
    elif failure == "config":
        targets[(api.who.tenant_id, "target-a")] = route.InspectionTarget(None, api.verifier)
    elif failure == "foreign":
        api.app.dependency_overrides[TenantPrincipalDependency] = lambda: Principal(
            tenant_id="foreign-tenant", actor_id="operator-a", roles=("usage:read",)
        )
    else:
        targets[(api.who.tenant_id, "target-a")] = route.InspectionTarget(api.config, object())
    response = await api.client.get("/pilot/readiness/inspection/target-a")
    assert response.status_code == 503 and response.json()["checks"]["target_configuration"] is False
    assert api.who.tenant_id not in response.text


@pytest.mark.parametrize(
    "failure",
    ["tenant", "artifact", "expired", "valuation", "root", "node-relative", "node-missing", "node-permission"],
)
async def test_stale_or_untrusted_target_rejects_readiness(api, failure, tmp_path, monkeypatch):
    config = api.config
    if failure == "tenant":
        config = replace(
            config,
            transfer=type(config.transfer).model_validate(
                {**config.transfer.model_dump(), "tenant_id": "foreign-tenant"}
            ),
        )
    elif failure == "artifact":
        config = replace(
            config,
            context=type(config.context).model_validate(
                {
                    **config.context.model_dump(),
                    "artifact_manifest_digest": "0000000000000000000000000000000000000000000000000000000000000000",
                }
            ),
        )
    elif failure == "expired":
        monkeypatch.setattr(route.time, "time", lambda: config.transfer.expires_at)
    elif failure == "valuation":
        config = replace(
            config,
            valuation_approval=type(config.valuation_approval).model_validate(
                {
                    **config.valuation_approval.model_dump(),
                    "signature": "00" * 64,
                }
            ),
        )
    elif failure == "root":
        config = replace(
            config,
            sanctions=type(config.sanctions).model_validate(
                {
                    **config.sanctions.model_dump(),
                    "signature": "00" * 64,
                }
            ),
        )
    else:
        node = tmp_path / "node"
        if failure == "node-relative":
            node = Path("node")
        elif failure == "node-permission":
            node.write_text("synthetic marker")
            node.chmod(0o600)
        verifier = PilotPairingVerifier(api.verifier.artifacts, api.verifier.bundle, node)
        api.app.state.pilot_inspection_targets[(api.who.tenant_id, "target-a")] = route.InspectionTarget(
            config, verifier
        )
    if failure in ("tenant", "artifact", "valuation", "root"):
        api.app.state.pilot_inspection_targets[(api.who.tenant_id, "target-a")] = route.InspectionTarget(
            config, api.verifier
        )
    response = await api.client.get("/pilot/readiness/inspection/target-a")
    assert response.status_code == 503 and response.json()["checks"]["target_configuration"] is False


@pytest.mark.parametrize("failure", ["sanctions", "type", "missing", "size"])
async def test_unusable_proving_target_is_not_ready(api, failure):
    target = api.app.state.pilot_proving_targets[(api.who.tenant_id, "target-a")]
    if failure == "sanctions":
        target.sanctions.root = "0"
    elif failure == "type":
        api.app.state.pilot_proving_targets[(api.who.tenant_id, "target-a")] = ProvingTarget(
            api.config, SimpleNamespace(verifier=api.verifier), target.sanctions
        )
    else:
        path = api.root / api.verifier.artifacts.manifest.wasm.filename
        if failure == "missing":
            path.unlink()
        else:
            path.write_bytes(b"modified length")
    response = await api.client.get("/pilot/readiness/proving/target-a")
    assert response.status_code == 503 and response.json()["checks"]["target_configuration"] is False


@pytest.mark.parametrize("binary", ["valid", "relative", "missing", "permission"])
async def test_native_runtime_metadata_check_never_spawns_the_binary(api, binary, tmp_path):
    path = tmp_path / "native"
    if binary == "relative":
        path = Path("native")
    elif binary != "missing":
        path.write_bytes(b"synthetic executable marker")
        path.chmod(0o700 if binary == "valid" else 0o600)
    target = api.app.state.pilot_proving_targets[(api.who.tenant_id, "target-a")]
    native = PilotNativeProver(api.prover, path, "ab" * 32, (0,))
    api.app.state.pilot_proving_targets[(api.who.tenant_id, "target-a")] = ProvingTarget(
        api.config, native, target.sanctions
    )
    response = await api.client.get("/pilot/readiness/proving/target-a")
    assert response.status_code == (200 if binary == "valid" else 503)
