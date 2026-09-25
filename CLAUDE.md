# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository

Privacy-focused evidence for regulated crypto transfers (Travel Rule context). A polyglot monorepo combining Circom circuits, Solidity contracts, a TypeScript SDK and a Python FastAPI gateway with PostgreSQL. Together they produce transfer-bound Groth16 proofs (credential, authorized issuer, sanctions non-membership), policy decisions, recipient-encrypted transfer information and retained evidence that can be verified offline, without revealing PII. Status: the local adoption pilot is merged; nothing is audited; proving keys are development-only. See `README.md` for the current capability boundary.

There is a hierarchy of `AGENTS.md` files that document each layer in depth. **Read the relevant one before making non-trivial changes** in that directory:

- `AGENTS.md` (root) — cross-cutting structure, conventions, anti-patterns
- `src/AGENTS.md` — Python SDK / FastAPI / storage / chain / SAR
- `circuits/AGENTS.md` — Circom circuits, signal contract, audit fixes
- `packages/contracts/AGENTS.md` — Solidity, Hardhat, multi-chain deployment
- `packages/proof/AGENTS.md` — TypeScript snarkjs wrapper SDK
- `tests/AGENTS.md` — pytest layers + mocking rules
- `scripts/AGENTS.md` — sanctions tree + circuit compile + Poseidon shim

## Sibling Repos

This repo lives at `~/code/clearproof/`. Related material lives outside it:

- **`~/obsidian/`** — Obsidian vault (multi-domain; follow its `SCHEMA.md` and `Vault-Naming-Conventions.md`). Clearproof internal context lives in:
  - `Research Reports/Clearproof/` — product, adoption, and regulatory research (e.g. use cases/monetization, SEC/Treasury ZK-KYC policy signals)
  - `Software Development/Repo Reviews/Clearproof Review 2026-03-31.md`
  - `Memory/clearproof.md` — running project memory

  Useful for the *why* behind protocol and positioning decisions when commit history is silent. New Clearproof notes go in `Research Reports/Clearproof/` and get an entry in `Vault Master Index.md`. Not a code repo.
- **`~/code/clearproof-web/`** — Separate Next.js 16 / React 19 / Tailwind 4 app. Has its own AGENTS.md warning: this is a newer Next.js than your training data — check `node_modules/next/dist/docs/` before writing code there. Don't conflate it with `apps/docs/` inside this repo (the developer docs site).

## Common Commands

```bash
# Setup (must run both)
uv sync --all-extras
npm install

# Python tests
make test                 # all
make test-unit
make test-integration
make test-compliance
uv run python -m pytest tests/unit/test_circuits.py -v     # single file
uv run python -m pytest tests/path/to/file.py::test_name   # single test

# TypeScript / contracts
npm test                                                   # turbo (ts + hardhat)
cd packages/contracts && npx hardhat test                  # Hardhat suite (~24 tests inc. E2E)
cd packages/proof && npx tsc --noEmit                      # type-check
cd packages/cli && npx tsc --noEmit

# Lint / format (ruff: E,F,I,W only, line-length 120)
make lint
make format

# Circuit compile (~5 min first run, needs circom + ptau)
bash scripts/compile_circuits.sh

# Sanctions tree → on-chain oracle (two-step, human-confirmed)
make build-sanctions-tree
make update-sanctions-oracle NETWORK=sepolia
make relay-sanctions                                       # sync root across all deployed chains

# Dev API (PII_MASTER_KEY required or startup fails)
make dev                                                   # uvicorn src.api.main:app --reload
```

## Architecture: The Critical Invariants

The system's correctness depends on a few cross-layer invariants. If you change one side without the other, you ship unverifiable proofs.

### 1. Two proof profiles; never pick one by signal count

The **current** profile is `pilot-transfer-v3` (`specs/pilot-transfer-v3.md`, ADRs 0009 and 0011): **eight** public signals in a fixed order and tree depths of 32 (issuance), 20 (authorized issuers) and 20 (sanctions). There is no public amount tier or SAR flag.

`projection_commitment, authorized_issuer_root, sanctions_root, authorization_nullifier, evaluated_at, proof_expires_at, domain_chain_id, domain_registry`

These places must agree on that order:

- `circuits/pilot_compliance.circom` — `main { public [...] }`
- `src/prover/pilot_compliance.py` — `PUBLIC_SIGNALS` / `PROFILE`
- `packages/contracts/contracts/PilotGroth16Verifier.sol` and `PilotCurrentRegistry.sol` — `uint256[8]` signals, with indices checked against statements and pins
- `packages/proof/src/authorization.ts` — hardcoded indices (`[3]` nullifier, `[5]` expiry)
- `specs/pilot-transfer-v3.md` — authoritative reference

Tree depths are defined once in `src/registry/pilot_tree.py` (`ISSUANCE_TREE_DEPTH`, `ISSUER_TREE_DEPTH`, `SANCTIONS_TREE_DEPTH`) and must match the `main` instantiation `PilotCompliance(32, 20, 20)`. Changing a depth changes the keys and requires a new profile name.

V1 and v2 have the same signal count but different keys (v1 also gives signal 0 a different meaning; v2 used depth-8 trees). Manifests name their profile explicitly; current checks reject v1 and v2.

The **legacy** `circuits/compliance.circom` profile has 16 signals (14 inputs + `is_compliant`/`sar_review_flag` outputs). It remains a separate demo/parity path and is documented in `docs/internal/CIRCUIT_SIGNALS.md`. Never reinterpret legacy proofs as current pilot authorization.

Reordering or renaming a signal in either profile is a breaking change across all of that profile's files.

### 2. Domain binding lives in the contract, not the circuit

The domain signals (pilot: `domain_chain_id`, `domain_registry`; legacy: `domain_chain_id`, `domain_contract_hash`) have **no in-circuit constraint**. Their security comes from the registry checking them against `block.chainid` and `address(this)` (`PilotCurrentRegistry`, legacy `ComplianceRegistry`). Removing those checks silently enables cross-chain replay.

### 2a. PostgreSQL is the authorization authority

In the pilot, PostgreSQL owns authorization consumption and replay. `PilotCurrentRegistry` only mirrors receipts that have already been consumed, under publisher-attested checkpoints. It cannot create an authorization or detect a lying publisher. Read-only inspection and observation must never consume an authorization (spend a nullifier). See `docs/internal/PILOT_CURRENT_REGISTRY.md`.

### 3. Sanctions tree rebuild **must** be followed by oracle relay

`scripts/build_sanctions_tree.py` regenerates the Merkle tree from live OFAC/EU feeds. Until `make relay-sanctions` (or `make update-sanctions-oracle NETWORK=<x>`) propagates the new root on-chain, proofs are inconsistent across chains. The oracle enforces a 1h cooldown and a 50% leaf-count floor; skipping the relay is one of the project's loudest anti-patterns.

### 4. Audit fixes in `circuits/` must not regress

Range checks (252-bit on sanctions keys, 64-bit on amounts, 16-bit on jurisdiction, 2-bit on kyc_tier), threshold ordering, `sanctions_clear` as a constrained private input, and adjacency-derived-from-path-bits in gap proofs are all post-audit additions. See `circuits/AGENTS.md` for the full list. Do not remove or weaken them.

## Layout Quirks Worth Knowing

- **The Python package installs as `clearproof` but source lives at `src/`**, and internal imports use `from src.api...`, `from src.protocol...` etc. This is unusual and trips up newcomers. Keep using the `src.` prefix.
- **Generated protobuf files** (`*_pb2.py`, `*_pb2_grpc.py`) in `src/protocol/bridges/` must never be edited by hand; ruff is configured to skip them.
- **TypeScript packages are an npm workspace** under `packages/*` (plus `apps/*`); turbo orchestrates `build`/`test`/`lint`. `npm test` from root runs the TS+Hardhat suite; `make test` runs Python.
- **The SDK has no baked-in circuit artifacts** — `wasmPath`, `zkeyPath`, `vkeyPath` are caller-supplied. Locally-built artifacts are dev-only. Production artifacts need an approved setup path: an MPC ceremony, or a universal setup if ADR 0004 (fflonk) is adopted. Production configuration rejects unapproved keys.

## Hard Rules (project-wide)

- **Never log, store, or transmit raw PII** outside the encrypted envelopes: HPKE v2 recipient envelopes by default; the legacy `HybridPayload` AES-256-GCM v1 path only when an operator selects it. Logs and reports carry minimized references and reason codes only.
- **Never resolve ENS names for sanctions** — raw hex addresses only. `normalize_address` in `scripts/build_sanctions_tree.py` enforces this.
- **Never start the API without a valid `PII_MASTER_KEY`** (64 hex chars or ≥32 UTF-8 bytes); the app refuses to boot otherwise.
- **Never import `src.api.main`** in tests without first setting `PII_MASTER_KEY`, `AUTH_MODE`, and `API_KEY` env vars — module import triggers the key check.
- **Never let tests require real circuit compilation.** The `mock_prover` fixture and deterministic public signals in `tests/conftest.py` are the single source of truth for happy-path proofs.
- **Compliance tests** (`tests/compliance/`) are policy-readable regulatory scenarios — keep them thin on crypto and thick on intent.

## CI

`.github/workflows/ci.yml` runs on push/PR to `main`. The job list is authoritative in that file. Main groups:
- Pilot gates: `pilot-root-checkpoint`, `pilot-credential-witness`, `discovery`, `proof-storage`
- `python-tests`, `python-aggregate-coverage`
- `typescript-build`, `operational-tests`, `operational-javascript`, `docs-browser`
- `hardhat-tests` — contract suite
- `circuits` — circom compile with audited Hermez ptau (SHA256-pinned); `circuit-lint` runs Circomspect
- Hygiene: `protobuf-freshness`, `license-compliance` (REUSE)

`sanctions-update.yml` rebuilds the sanctions Merkle tree daily from live feeds. `release.yml` publishes packages.

## Environment

| Variable | Required | Purpose |
|----------|----------|---------|
| `PII_MASTER_KEY` | API | 32+ byte key (64-hex preferred). API refuses to start without it. |
| `AUTH_MODE`, `API_KEY` | Tests/API | Required before importing the FastAPI app. |
| `VASP_DID` | No | This VASP's DID. Default `did:web:vasp.example.com`. |
| `CIRCUIT_ARTIFACTS_DIR` | No | Default `./artifacts`. |
| `CORS_ALLOWED_ORIGINS` | No | Default `http://localhost:3000`. |
| `DEPLOYER_PRIVATE_KEY`, `SEPOLIA_RPC_URL` | Deploy only | For Hardhat deployment scripts. |
