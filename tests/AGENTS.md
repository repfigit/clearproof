# TESTS/ AGENTS.md

**Scope:** The complete test suite — unit, integration, and regulatory compliance layers.

## OVERVIEW
Three-layer pytest suite (2614+ LOC) that validates the ZK Travel Rule engine without requiring real circuit artifacts or Node.js in most paths. Heavy ZK operations are mocked; the `compliance/` layer exercises real regulatory scenarios.

## STRUCTURE
```
tests/
├── conftest.py                 # Single source of truth for fixtures (credentials, proofs, mock prover, env)
├── unit/                       # Pure logic: tier mapping, IVMS101, hash binding, SAR, deterministic tree
├── integration/                # API, storage, hybrid payload, protocol bridges (TRISA/TRP/gRPC)
└── compliance/                 # Regulatory scenarios: sanctions match, real OFAC addresses, revocation, thresholds
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add a new compliance scenario | `tests/compliance/` (new file or extend existing) | Highest value — mirrors FATF / BSA / MiCA rules |
| Change tier thresholds or jurisdiction logic | `tests/unit/test_circuits.py` + `tests/compliance/test_threshold_tiers.py` | Tier logic lives in `src/prover/tier_mapping.py` |
| Test a new API endpoint | `tests/integration/test_api_endpoints.py` | Must set `PII_MASTER_KEY`, `AUTH_MODE`, `API_KEY` before importing app |
| Add fixture used across layers | `tests/conftest.py` | Prefer autouse or explicit over duplication |
| Mock Poseidon for sanctions tree tests | `tests/compliance/test_sanctions_match.py` or `test_real_sanctions.py` | Two different deterministic mocks exist — pick the polynomial one for injectivity |
| Test bridge serialization | `tests/integration/test_trisa_bridge.py`, `test_trp_bridge.py`, `test_grpc_trisa_bridge.py` | Bridges have their own integration tests |

## TESTING MODEL

**Unit** — fast, no external services, pure functions and data models.
**Integration** — spin up real components (FastAPI via ASGI, asyncpg test DB, storage) but mock ZK and external chains.
**Compliance** — regulatory intent tests. These are the canary for "does this still satisfy the law?" even if the cryptographic implementation changes.

`compliance/` is deliberately thin on crypto and thick on policy: sanctions list inclusion, real OFAC addresses (Tornado Cash, etc.), revocation, tier boundaries per jurisdiction.

## FIXTURES (conftest.py)

- `sample_master_key`, `sample_derived_key` — encryption
- `sample_credential`, `sample_zkkyc_credential`, `revoked_credential`, `expired_credential`
- `sample_compliance_proof` — deterministic public_signals array (16 elements)
- `sample_hybrid_payload` — encrypted PII envelope
- `mock_prover` — returns fixed proof + signals, patches subprocess
- `credential_registry` — fresh in-memory instance
- `_set_test_env` (autouse) — forces `ZK_ARTIFACTS_DIR` and `VASP_DID` via tmp_path

**Rule:** If a value is used in more than two test files, it belongs in conftest.py.

## MOCKING RULES (CRITICAL)

1. **ZK is almost always mocked.** Real `snarkjs` + circuit artifacts are only exercised in `tests/unit/test_circuits.py` (and even there mostly tier logic) and the dedicated circuit round-trip helper.
2. **Poseidon hash for sanctions tree** must be mocked because it shells out to Node.js. Two factories exist:
   - Polynomial (injective) mock in `test_sanctions_match.py` — preferred for collision resistance
   - Simple sum mock in `test_real_sanctions.py` — acceptable for OFAC list inclusion tests
3. **Never import the FastAPI app** until required env vars are set (`PII_MASTER_KEY=64hex`, `AUTH_MODE`, `API_KEY`).
4. **Do not** let tests accidentally hit real RPCs or the live sanctions API — all chain and sanctions-oracle calls are mocked in integration tests.

## ADDING A NEW COMPLIANCE SCENARIO

1. Create or extend a file in `tests/compliance/`.
2. Use the deterministic Poseidon mock (copy the polynomial factory).
3. Assert both positive (clean address produces valid non-membership) and negative (sanctioned address cannot).
4. If the scenario involves a jurisdiction threshold, also add a parametrized case in `test_threshold_tiers.py`.
5. Update `conftest.py` only if you need a new reusable fixture (e.g., a new sanctioned address list).

## ANTI-PATTERNS

- **NEVER** write a compliance test that requires real circuit compilation. Use the mock prover.
- **NEVER** duplicate the 16-element `public_signals` array across tests — pull from `sample_compliance_proof`.
- **NEVER** import `src.api.main` at module level in integration tests without the env-var guard.
- **NEVER** use the simple sum Poseidon mock when testing for hash collisions or adversarial inputs (use the polynomial version).
- **NEVER** put real PII (even test data) in test files outside the encrypted envelope pattern.
- **NEVER** skip the revocation or expiry credential fixtures when testing those paths — they exist for a reason.

## COMMANDS

```bash
# All tests (Python)
make test

# Layers
make test-unit
make test-integration
make test-compliance

# Specific file (example)
uv run python -m pytest tests/compliance/test_sanctions_match.py -v

# With coverage (if configured)
uv run python -m pytest --cov=src tests/
```

## NOTES

- Total test surface is deliberately larger in integration than unit because the hard parts (bridges, storage, API contracts, sanctions tree) live at the seams.
- The `compliance/` layer is the one auditors and regulators care about most. Keep it readable as policy, not as crypto.
- When a new jurisdiction is added to `src/prover/tier_mapping.py`, add the boundary cases to both the unit tier tests and the compliance tier wrapper.
- The mock prover's public signals are deliberately chosen so that `is_compliant=1`, `sar_review_flag=0` for the happy path — change them consciously when testing negative cases.
