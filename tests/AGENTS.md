# TESTS/ AGENTS.md

**Scope:** The complete test suite — unit, integration, and regulatory compliance layers.

## OVERVIEW
Three-layer pytest suite for the development pilot and legacy compliance path. Most tests run without artifacts; dedicated real-proof, PostgreSQL and local-EVM acceptance paths run in CI. Policy scenarios and synthetic evidence are implementation checks, not legal-compliance assurance.

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
| Poseidon parity and tree hashing | `tests/unit/test_poseidon.py`, `src/registry/poseidon.py` | Native Python BN254 Poseidon; dedicated parity checks compare circomlibjs |
| Test bridge serialization | `tests/integration/test_trisa_bridge.py`, `test_trp_bridge.py`, `test_grpc_trisa_bridge.py` | Bridges have their own integration tests |

## TESTING MODEL

**Unit** — fast, no external services, pure functions and data models.
**Integration** — exercise FastAPI, psycopg 3/PostgreSQL storage, encrypted evidence and protocol boundaries. Ordinary tests isolate external chains; explicit acceptance runs use real development proofs and an owned local EVM.
**Compliance** — synthetic policy intent tests: sanctions inclusion, credential status and configured threshold boundaries. Passing them does not establish legal compliance.

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

1. **Real proofs require explicit bundles.** CI uses `scripts/test_development_circuits.py` to generate unapproved development artifacts, then supplies `CLEARPROOF_PILOT_TEST_ARTIFACTS` and `CLEARPROOF_LEGACY_TEST_ARTIFACTS` to real-proof acceptance suites. Ordinary tests use synthetic/mocked proof records; inspect each suite’s artifact guard.
2. **Poseidon is native Python** (`src/registry/poseidon.py`); it does not shell out to Node. Existing isolated legacy policy scenarios may use deterministic test hashes for speed. Those mocks do not demonstrate cryptographic behavior:
   - Polynomial mock in `test_sanctions_match.py` — preserves distinctions in bounded synthetic examples; not a collision-resistant cryptographic hash
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
- **NEVER** confuse the legacy 16-signal profile with the current pilot eight-signal profile. Use profile-specific fixtures; `sample_compliance_proof` is legacy.
- **NEVER** import `src.api.main` at module level in integration tests without the env-var guard.
- **NEVER** use a synthetic hash mock to claim cryptographic collision resistance or circuit parity; use real Poseidon for those properties.
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
