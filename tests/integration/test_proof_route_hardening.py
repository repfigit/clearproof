"""Legacy /proof route hardening: subject binding, verification policy, idempotency and caching.

ZK is mocked throughout; no circuit compilation or Node.js is required.
"""

import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

SUBJECT = "0x" + "ab" * 20
BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


@pytest.fixture
def route(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "synthetic-api-key")
    from src.api.routes import proof

    monkeypatch.setattr(proof, "_artifact_cache", {})
    return proof


class FakeStore:
    def __init__(self):
        self.check_idempotency = AsyncMock(return_value=None)
        self.nullifier_exists = AsyncMock(return_value=False)
        self.store = AsyncMock()
        self.add_nullifier = AsyncMock(return_value=True)
        self.record_idempotency = AsyncMock()


class FakeDatabase:
    def __init__(self):
        self.locks = []

    @asynccontextmanager
    async def transaction(self):
        database = self

        class Connection:
            async def execute(self, statement, params):
                database.locks.append(params)

        class Transaction:
            @asynccontextmanager
            async def connection(self):
                yield Connection()

        yield Transaction()


@pytest.fixture
def harness(route, monkeypatch):
    """Fully mocked generation environment with an injected issuer registry."""
    from src.sar.hpke_envelope import generate_keypair
    from src.storage import credentials, proofs

    now = int(time.time())
    credential = SimpleNamespace(
        revoked=False,
        sanctions_clear=True,
        issuer_did="did:web:issuer.example",
        kyc_tier="retail",
        issued_at=now - 10,
        expires_at=now + 3600,
        subject_wallet=SUBJECT,
        jurisdiction="US",
    )
    path = {"siblings": ["0"] * 3, "indices": [0] * 3}
    issuer_registry = SimpleNamespace(
        get_root=Mock(return_value="77"), generate_membership_witness=AsyncMock(return_value=path)
    )
    tree = SimpleNamespace(
        root="55",
        generate_nonmembership_witness=AsyncMock(
            return_value={"left_neighbor": 0, "right_neighbor": 9, "left_path": path, "right_path": path}
        ),
    )
    store = FakeStore()
    credential_store = SimpleNamespace(upsert=AsyncMock())
    audit = SimpleNamespace(append=AsyncMock())
    monkeypatch.setattr(proofs, "ProofStore", Mock(return_value=store))
    monkeypatch.setattr(credentials, "CredentialStore", Mock(return_value=credential_store))
    monkeypatch.setattr(route, "PersistentAuditLog", Mock(return_value=audit))
    monkeypatch.setattr(route, "_check_sanctions_staleness", AsyncMock())
    monkeypatch.setattr(route.SanctionsMerkleTree, "load", Mock(return_value=tree))
    monkeypatch.setattr(route, "_hash_wallet", AsyncMock(return_value="123"))
    monkeypatch.setattr(route, "_poseidon_hash", AsyncMock(return_value="456"))
    monkeypatch.setattr(route, "_load_vk", Mock(return_value={"vk": 1}))
    monkeypatch.setattr(route, "_resolve_recipient_key", AsyncMock(return_value=generate_keypair()[1]))
    monkeypatch.setattr(route._audit_log, "append", Mock())
    prover = AsyncMock(return_value=({"pi_a": []}, ["1"] * 16))
    monkeypatch.setattr(route._prover, "fullprove", prover)
    monkeypatch.delenv("DOMAIN_CONTRACT_HASH", raising=False)
    monkeypatch.delenv("DOMAIN_CHAIN_ID", raising=False)

    state = SimpleNamespace(issuer_registry=issuer_registry)
    harness = SimpleNamespace(
        credential=credential,
        registry=SimpleNamespace(get=Mock(return_value=credential), get_commitment=Mock(return_value="123")),
        issuer_registry=issuer_registry,
        tree=tree,
        store=store,
        credential_store=credential_store,
        audit=audit,
        prover=prover,
        db=None,
        state=state,
    )
    monkeypatch.setattr(route, "_get_db", lambda _app: harness.db)

    def make_request(**overrides):
        fields = {
            "credential_id": "synthetic",
            "wallet_address": SUBJECT,
            "amount_usd": 10,
            "asset": "USDC",
            "destination_wallet": "0x" + "2" * 40,
            "jurisdiction": "US",
            "idempotency_key": "retry-key",
        }
        fields.update(overrides)
        return route.ProofGenerateRequest(**fields)

    async def generate(request=None, principal="tenant-a"):
        return await route.generate_proof(
            request or make_request(),
            SimpleNamespace(app=SimpleNamespace(state=state)),
            _auth={"sub": principal},
            _cred_registry=harness.registry,
        )

    harness.make_request = make_request
    harness.generate = generate
    return harness


def inputs(harness):
    return harness.prover.call_args.args[0]


# ---------------------------------------------------------------------------
# Finding 1: credential subject binding
# ---------------------------------------------------------------------------


async def test_generation_rejects_wallet_that_is_not_the_credential_subject(harness):
    with pytest.raises(HTTPException) as error:
        await harness.generate(harness.make_request(wallet_address="0x" + "cd" * 20))
    assert error.value.status_code == 403
    assert "0x" not in error.value.detail
    harness.prover.assert_not_awaited()


async def test_generation_rejects_jurisdiction_that_is_not_the_credential_jurisdiction(harness):
    with pytest.raises(HTTPException) as error:
        await harness.generate(harness.make_request(jurisdiction="GB"))
    assert error.value.status_code == 403
    harness.prover.assert_not_awaited()


async def test_subject_match_is_case_insensitive_and_persists_credential_wallet(harness):
    harness.db = FakeDatabase()
    response = await harness.generate(harness.make_request(wallet_address=SUBJECT.upper().replace("0X", "0x")))
    assert response["status"] == "generated"
    stored = harness.credential_store.upsert.call_args.args[0]
    assert stored.subject_wallet == SUBJECT
    assert stored.jurisdiction == "US"
    harness.tree.generate_nonmembership_witness.assert_awaited_once_with(SUBJECT)
    assert harness.store.record_idempotency.call_args.args[1] == SUBJECT


# ---------------------------------------------------------------------------
# Finding 3: injectable issuer registry and error mapping
# ---------------------------------------------------------------------------


async def test_injected_issuer_registry_is_used(route, harness, monkeypatch):
    fallback = SimpleNamespace(get_root=Mock(side_effect=AssertionError), generate_membership_witness=AsyncMock())
    monkeypatch.setattr(route, "_issuer_registry", fallback)
    await harness.generate()
    harness.issuer_registry.generate_membership_witness.assert_awaited_once_with("did:web:issuer.example")
    assert inputs(harness)["issuer_tree_root"] == "77"
    fallback.generate_membership_witness.assert_not_awaited()


def test_issuer_registry_falls_back_to_module_default(route):
    assert route._get_issuer_registry(None) is route._issuer_registry
    assert route._get_issuer_registry(SimpleNamespace(state=SimpleNamespace())) is route._issuer_registry


async def test_unknown_issuer_is_a_client_error(harness):
    harness.issuer_registry.generate_membership_witness.side_effect = KeyError("unknown")
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 422
    assert error.value.detail == "Credential issuer not authorized"
    harness.prover.assert_not_awaited()


async def test_empty_default_registry_is_not_a_server_error(route, harness):
    harness.state.issuer_registry = None
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 422


@pytest.mark.parametrize("failure", ["prover", "missing", "runtime"])
async def test_prover_failure_is_unavailable_and_logs_type_only(route, harness, caplog, failure):
    exc = {
        "prover": route.ProverError("synthetic-private-marker"),
        "missing": FileNotFoundError("synthetic-private-marker"),
        "runtime": RuntimeError("synthetic-private-marker"),
    }[failure]
    harness.prover.side_effect = exc
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 503
    assert type(exc).__name__ in caplog.text
    assert "synthetic-private-marker" not in caplog.text


# ---------------------------------------------------------------------------
# Finding 7: principal-scoped idempotency and early nullifier check
# ---------------------------------------------------------------------------


def test_idempotency_key_is_scoped_to_principal(route):
    first = route._scoped_idempotency_key("tenant-a", "k")
    assert first == route._scoped_idempotency_key("tenant-a", "k")
    assert first != route._scoped_idempotency_key("tenant-b", "k")
    assert "tenant-a" not in first and first.startswith("proof-idem-v2:")
    assert route._principal_id({"sub": "tenant-a"}) == "tenant-a"
    assert route._principal_id({"sub": ""}) == "unauthenticated"
    assert route._principal_id(None) == "unauthenticated"


def test_fingerprint_covers_salient_fields_and_excludes_pii(route, harness):
    base = harness.make_request()
    assert route._request_fingerprint(base) == route._request_fingerprint(
        harness.make_request(wallet_address=SUBJECT.upper().replace("0X", "0x"), originator_name="Synthetic")
    )
    assert route._request_fingerprint(base) != route._request_fingerprint(harness.make_request(amount_usd=11))
    assert route._request_fingerprint(base) != route._request_fingerprint(harness.make_request(transfer_nonce="n-2"))


async def test_cached_result_requires_same_principal_and_fingerprint(route, harness):
    harness.db = FakeDatabase()
    request = harness.make_request()
    fingerprint = route._request_fingerprint(request)
    harness.store.check_idempotency.return_value = f"{fingerprint}:cached-digest"
    assert await harness.generate(request) == {"status": "already_generated", "result_hash": "cached-digest"}
    harness.store.check_idempotency.assert_awaited_once_with(route._scoped_idempotency_key("tenant-a", "retry-key"))
    harness.prover.assert_not_awaited()


@pytest.mark.parametrize("stored", ["0" * 64 + ":cached-digest", "legacy-unscoped-digest"])
async def test_reused_key_for_a_different_request_conflicts(harness, stored):
    harness.db = FakeDatabase()
    harness.store.check_idempotency.return_value = stored
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 409
    harness.prover.assert_not_awaited()


async def test_other_principal_does_not_see_cached_result(route, harness):
    harness.db = FakeDatabase()
    fingerprint = route._request_fingerprint(harness.make_request())
    owner_key = route._scoped_idempotency_key("tenant-a", "retry-key")
    harness.store.check_idempotency.side_effect = lambda key: f"{fingerprint}:cached" if key == owner_key else None
    response = await harness.generate(principal="tenant-b")
    assert response["status"] == "generated"
    recorded_key, _, recorded_value = harness.store.record_idempotency.call_args.args
    assert recorded_key == route._scoped_idempotency_key("tenant-b", "retry-key")
    assert recorded_value.startswith(f"{fingerprint}:")
    lock = int.from_bytes(hashlib.sha256(recorded_key.encode()).digest()[:8], "big", signed=True)
    assert harness.db.locks == [(lock,)]


async def test_concurrent_duplicate_inside_transaction_returns_or_conflicts(route, harness):
    harness.db = FakeDatabase()
    fingerprint = route._request_fingerprint(harness.make_request())
    harness.store.check_idempotency.side_effect = [None, f"{fingerprint}:raced"]
    assert await harness.generate() == {"status": "already_generated", "result_hash": "raced"}
    harness.store.check_idempotency.side_effect = [None, "f" * 64 + ":raced"]
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 409


async def test_spent_nullifier_fails_before_proving(harness):
    harness.db = FakeDatabase()
    harness.store.nullifier_exists.return_value = True
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 409
    harness.store.nullifier_exists.assert_awaited_once_with("456")
    harness.prover.assert_not_awaited()


async def test_nullifier_insert_race_still_conflicts(harness):
    harness.db = FakeDatabase()
    harness.store.add_nullifier.return_value = False
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 409
    harness.store.record_idempotency.assert_not_awaited()


async def test_transfer_nonce_is_bound_into_nullifier_preimage(route, harness):
    destination = "0x" + "2" * 40
    await harness.generate()
    legacy = int(hashlib.sha256(f"{SUBJECT}:{destination}:10.0".encode()).hexdigest()[:16], 16)
    assert inputs(harness)["transfer_id_hash"] == str(legacy)
    route._poseidon_hash.assert_awaited_with([123, legacy])

    await harness.generate(harness.make_request(transfer_nonce="transfer-7"))
    bound = int(hashlib.sha256(f"{SUBJECT}:{destination}:10.0:transfer-7".encode()).hexdigest()[:16], 16)
    assert inputs(harness)["transfer_id_hash"] == str(bound)
    route._poseidon_hash.assert_awaited_with([123, bound])


# ---------------------------------------------------------------------------
# Finding 8: cached artifacts, one vk read per request
# ---------------------------------------------------------------------------


async def test_verification_key_is_read_once_per_request(route, harness):
    response = await harness.generate()
    route._load_vk.assert_called_once()
    assert response["compliance_proof"]["verification_key"] == json.dumps({"vk": 1})


def test_verification_key_cache_reloads_only_when_file_changes(route, monkeypatch, tmp_path):
    monkeypatch.setenv("CIRCUIT_ARTIFACTS_DIR", str(tmp_path))
    vk = tmp_path / "verification_key.json"
    vk.write_text(json.dumps({"version": 1}))
    reads = Mock(wraps=route._read_vk)
    monkeypatch.setattr(route, "_read_vk", reads)
    assert route._load_vk() == {"version": 1}
    assert route._load_vk() == {"version": 1}
    assert reads.call_count == 1
    vk.write_text(json.dumps({"version": 22}))
    os.utime(vk, ns=(1, 1))
    assert route._load_vk() == {"version": 22}
    assert reads.call_count == 2


def test_sanctions_tree_cache_reloads_only_when_file_changes(route, monkeypatch, tmp_path):
    monkeypatch.setenv("CIRCUIT_ARTIFACTS_DIR", str(tmp_path))
    artifact = tmp_path / "sanctions_tree.json"
    artifact.write_text(json.dumps({"depth": 1, "root": "11", "sorted_leaves": ["0", "1"]}))
    builds = Mock(wraps=route.SanctionsMerkleTree.build_from_file)
    monkeypatch.setattr(route.SanctionsMerkleTree, "build_from_file", builds)
    assert route._load_sanctions_tree().root == "11"
    assert route._load_sanctions_tree().root == "11"
    assert builds.call_count == 1
    artifact.write_text(json.dumps({"depth": 1, "root": "222", "sorted_leaves": ["0", "1"]}))
    os.utime(artifact, ns=(1, 1))
    assert route._load_sanctions_tree().root == "222"
    assert builds.call_count == 2


def test_missing_sanctions_tree_is_not_cached(route, monkeypatch, tmp_path):
    monkeypatch.setenv("CIRCUIT_ARTIFACTS_DIR", str(tmp_path))
    with pytest.raises(RuntimeError, match="Sanctions tree file not found"):
        route._load_sanctions_tree()
    assert route._artifact_cache == {}


# ---------------------------------------------------------------------------
# Finding 9: domain binding configuration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured,expected",
    [
        ("", 0),
        ("0", 0),
        ("12345678901234567890123", 12345678901234567890123),
        ("0xABCDEF1234567890FEDCBA", 0xABCDEF1234567890FEDCBA),
        (str(BN128_R - 1), BN128_R - 1),
    ],
)
async def test_domain_contract_hash_is_used_in_full(harness, monkeypatch, configured, expected):
    monkeypatch.setenv("DOMAIN_CONTRACT_HASH", configured)
    monkeypatch.setenv("DOMAIN_CHAIN_ID", "1")
    await harness.generate()
    assert inputs(harness)["domain_contract_hash"] == str(expected)
    assert inputs(harness)["domain_chain_id"] == "1"


@pytest.mark.parametrize(
    "name,configured",
    [
        ("DOMAIN_CONTRACT_HASH", "abcdef1234567890fedcba"),
        ("DOMAIN_CONTRACT_HASH", "0x"),
        ("DOMAIN_CONTRACT_HASH", "-1"),
        ("DOMAIN_CONTRACT_HASH", "1_000"),
        ("DOMAIN_CONTRACT_HASH", str(BN128_R)),
        ("DOMAIN_CHAIN_ID", "sepolia"),
    ],
)
async def test_malformed_domain_configuration_fails_closed_before_proving(harness, monkeypatch, name, configured):
    monkeypatch.setenv(name, configured)
    with pytest.raises(HTTPException) as error:
        await harness.generate()
    assert error.value.status_code == 503
    assert name in error.value.detail
    harness.prover.assert_not_awaited()


# ---------------------------------------------------------------------------
# Finding 2: verification policy
# ---------------------------------------------------------------------------


def good_signals(now):
    from src.prover.tier_mapping import get_thresholds

    thresholds = get_thresholds("US")
    signals = ["0"] * 16
    signals[0] = "1"
    signals[2], signals[3] = "55", "77"
    signals[4] = "1"
    signals[6] = str(0x5553)
    signals[8:11] = [str(thresholds[k]) for k in ("tier2", "tier3", "tier4")]
    signals[15] = str(now + 300)
    return signals


@pytest.fixture
def verifier(route, monkeypatch):
    verify = AsyncMock(return_value=True)
    monkeypatch.setattr(route._prover, "verify", verify)
    monkeypatch.setattr(route.time, "time", lambda: 1_000_000)
    state = SimpleNamespace(issuer_registry=SimpleNamespace(get_root=Mock(return_value="77")))
    monkeypatch.setattr(route.SanctionsMerkleTree, "load", Mock(return_value=SimpleNamespace(root="55")))

    async def run(signals):
        request = route.ProofVerifyRequest(
            proof_id="synthetic",
            groth16_proof={},
            public_signals=signals,
            expected_amount_tier=1,
            originator_vasp_did="did:web:synthetic.example",
            transfer_timestamp=1,
        )
        return await route.verify_proof(request, SimpleNamespace(app=SimpleNamespace(state=state)))

    return SimpleNamespace(run=run, verify=verify, state=state, now=1_000_000)


async def test_verify_accepts_current_compliant_unexpired_proof(verifier):
    response = await verifier.run(good_signals(verifier.now))
    assert response.valid is True
    assert response.rejection_reasons == []
    assert response.compliance_attestations["sanctions_root_status"] == "current"
    assert response.compliance_attestations["issuer_root_status"] == "current"
    assert response.compliance_attestations["proof_expires_at"] == verifier.now + 300


async def test_verify_rejects_non_compliant_output(verifier):
    signals = good_signals(verifier.now)
    signals[0] = "0"
    response = await verifier.run(signals)
    assert response.valid is False
    assert response.rejection_reasons == ["not_compliant"]


@pytest.mark.parametrize("offset", [0, -1])
async def test_verify_rejects_expired_proof_at_verifier_clock(verifier, offset):
    signals = good_signals(verifier.now)
    signals[15] = str(verifier.now + offset)
    response = await verifier.run(signals)
    assert response.valid is False
    assert response.rejection_reasons == ["proof_expired"]


async def test_verify_rejects_stale_roots(verifier):
    signals = good_signals(verifier.now)
    signals[2], signals[3] = "56", "78"
    response = await verifier.run(signals)
    assert response.valid is False
    assert response.rejection_reasons == ["sanctions_root_stale", "issuer_root_stale"]
    assert response.compliance_attestations["sanctions_root_status"] == "stale"
    assert response.compliance_attestations["issuer_root_status"] == "stale"


async def test_hex_current_roots_are_compared_as_field_elements(route, verifier, monkeypatch):
    monkeypatch.setattr(route.SanctionsMerkleTree, "load", Mock(return_value=SimpleNamespace(root="0x37")))
    verifier.state.issuer_registry.get_root.return_value = "0x4d"
    response = await verifier.run(good_signals(verifier.now))
    assert response.valid is True


@pytest.mark.parametrize("source", ["missing", "unbuilt", "empty-registry"])
async def test_unavailable_current_roots_are_reported_unverified(route, verifier, monkeypatch, source):
    if source == "missing":
        monkeypatch.setattr(route.SanctionsMerkleTree, "load", Mock(side_effect=RuntimeError("no file")))
    elif source == "unbuilt":
        monkeypatch.setattr(route.SanctionsMerkleTree, "load", Mock(return_value=SimpleNamespace(root=None)))
    else:
        verifier.state.issuer_registry.get_root.side_effect = RuntimeError("Registry is empty")
    response = await verifier.run(good_signals(verifier.now))
    assert response.valid is True
    statuses = response.compliance_attestations
    expected_unverified = "issuer_root_status" if source == "empty-registry" else "sanctions_root_status"
    assert statuses[expected_unverified] == "unverified"


@pytest.mark.parametrize("count", [0, 15, 17])
async def test_verify_rejects_wrong_signal_count_before_snarkjs(verifier, count):
    with pytest.raises(HTTPException) as error:
        await verifier.run(["1"] * count)
    assert error.value.status_code == 400
    verifier.verify.assert_not_awaited()


@pytest.mark.parametrize("bad", ["-1", "1.0", "0x10", " 1", "", str(BN128_R), "1" * 79])
async def test_verify_rejects_malformed_signal_before_snarkjs(verifier, bad):
    signals = good_signals(verifier.now)
    signals[7] = bad
    with pytest.raises(HTTPException) as error:
        await verifier.run(signals)
    assert error.value.status_code == 400
    verifier.verify.assert_not_awaited()


async def test_verify_failure_logs_exception_type_only(verifier, caplog):
    caplog.set_level(logging.ERROR)
    verifier.verify.side_effect = ValueError("synthetic-private-marker")
    with pytest.raises(HTTPException) as error:
        await verifier.run(good_signals(verifier.now))
    assert error.value.status_code == 503
    assert "ValueError" in caplog.text
    assert "synthetic-private-marker" not in caplog.text


def test_pilot_route_documents_current_profile(route):
    from src.api.routes import pilot_proof

    assert "pilot-transfer-v3" in pilot_proof.__doc__
    assert "v2" not in pilot_proof.__doc__
