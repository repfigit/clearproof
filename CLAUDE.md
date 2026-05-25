# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository

ZK infrastructure for FATF Travel Rule compliance. A polyglot monorepo combining Circom circuits, Solidity contracts, a TypeScript SDK, and a Python FastAPI gateway that together generate and verify Groth16 proofs attesting sanctions / credential / amount-tier checks without revealing PII.

There is a hierarchy of `AGENTS.md` files that document each layer in depth. **Read the relevant one before making non-trivial changes** in that directory:

- `AGENTS.md` (root) — cross-cutting structure, conventions, anti-patterns
- `src/AGENTS.md` — Python SDK / FastAPI / storage / chain / SAR
- `circuits/AGENTS.md` — Circom circuits, signal contract, audit fixes
- `packages/contracts/AGENTS.md` — Solidity, Hardhat, multi-chain deployment
- `packages/proof/AGENTS.md` — TypeScript snarkjs wrapper SDK
- `tests/AGENTS.md` — pytest layers + mocking rules
- `scripts/AGENTS.md` — sanctions tree + circuit compile + Poseidon shim

## Sibling Repos

This repo lives at `/Users/keith/code/clearproof/protocol/`. Two sibling directories live alongside it:

- **`../notes/`** — Obsidian vault with internal-only context: `decisions.md`, `roadmap-internal.md`, `business-strategy.md`, `community-strategy.md`, `legal-contacts.md`, `sanctions-oracle-trust.md`, `analysis-layerzero.md`, `tca.md`, and adversarial LLM `debates/`. Useful for the *why* behind protocol decisions when commit history is silent. Not a code repo.
- **`../web/`** — Separate Next.js 16 / React 19 / Tailwind 4 app (`clearproof-web`). Has its own AGENTS.md warning: this is a newer Next.js than your training data — check `node_modules/next/dist/docs/` before writing code there. Don't conflate it with `apps/docs/` inside this repo (the developer docs site).

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

### 1. Python witness ↔ Circom circuit ↔ Solidity verifier ABI

The compliance circuit declares 14 public inputs + 2 public outputs in a fixed order (see `circuits/AGENTS.md` for the full list). Three places must agree on this order:

- `circuits/compliance.circom` — `main { public [...] }`
- `src/protocol/compliance_proof.py` — `ComplianceProof.public_signals` (the 16-element array)
- `packages/proof/src/prover.ts` — the camelCase→snake_case mapping in `generateProof` (this is the SDK's only knowledge of the circuit ABI)
- `packages/proof/src/verifier.ts` — hardcoded indices `publicSignals[0]=is_compliant`, `[1]=sar_review_flag`
- `docs/internal/CIRCUIT_SIGNALS.md` — authoritative reference

Reordering or renaming any signal is a breaking change across all of these.

### 2. Domain binding lives in the contract, not the circuit

`domain_chain_id` and `domain_contract_hash` are public inputs to the circuit but have **no in-circuit constraint**. Their security comes from `ComplianceRegistry` checking them against `block.chainid` and `address(this)`. Removing those checks on either side silently enables cross-chain replay.

### 3. Sanctions tree rebuild **must** be followed by oracle relay

`scripts/build_sanctions_tree.py` regenerates the Merkle tree from live OFAC/EU feeds. Until `make relay-sanctions` (or `make update-sanctions-oracle NETWORK=<x>`) propagates the new root on-chain, proofs are inconsistent across chains. The oracle enforces a 1h cooldown and a 50% leaf-count floor; skipping the relay is one of the project's loudest anti-patterns.

### 4. Audit fixes in `circuits/` must not regress

Range checks (252-bit on sanctions keys, 64-bit on amounts, 16-bit on jurisdiction, 2-bit on kyc_tier), threshold ordering, `sanctions_clear` as a constrained private input, and adjacency-derived-from-path-bits in gap proofs are all post-audit additions. See `circuits/AGENTS.md` for the full list. Do not remove or weaken them.

## Layout Quirks Worth Knowing

- **The Python package installs as `clearproof` but source lives at `src/`**, and internal imports use `from src.api...`, `from src.protocol...` etc. This is unusual and trips up newcomers. Keep using the `src.` prefix.
- **Generated protobuf files** (`*_pb2.py`, `*_pb2_grpc.py`) in `src/protocol/bridges/` must never be edited by hand; ruff is configured to skip them.
- **TypeScript packages are an npm workspace** under `packages/*` (plus `apps/*`); turbo orchestrates `build`/`test`/`lint`. `npm test` from root runs the TS+Hardhat suite; `make test` runs Python.
- **The SDK has no baked-in circuit artifacts** — `wasmPath`, `zkeyPath`, `vkeyPath` are caller-supplied. Locally-built artifacts are dev-only; production artifacts must come from an audited MPC ceremony.

## Hard Rules (project-wide)

- **Never log, store, or transmit raw PII** outside the `HybridPayload` AES-256-GCM envelope.
- **Never resolve ENS names for sanctions** — raw hex addresses only. `normalize_address` in `scripts/build_sanctions_tree.py` enforces this.
- **Never start the API without a valid `PII_MASTER_KEY`** (64 hex chars or ≥32 UTF-8 bytes); the app refuses to boot otherwise.
- **Never import `src.api.main`** in tests without first setting `PII_MASTER_KEY`, `AUTH_MODE`, and `API_KEY` env vars — module import triggers the key check.
- **Never let tests require real circuit compilation.** The `mock_prover` fixture and deterministic public signals in `tests/conftest.py` are the single source of truth for happy-path proofs.
- **Compliance tests** (`tests/compliance/`) are policy-readable regulatory scenarios — keep them thin on crypto and thick on intent.

## CI

Four jobs on push/PR to `main` (`.github/workflows/ci.yml`):
- `python-tests` — full pytest suite
- `typescript-build` — type-check `@clearproof/proof` and `@clearproof/cli` (builds `content` and `proof` first as deps)
- `hardhat-tests` — contract suite incl. E2E prove→submit→verify
- `circuits` — circom compile with audited Hermez ptau18 (SHA256-pinned), generates `Groth16Verifier.sol`

A daily `sanctions-update` cron rebuilds the sanctions Merkle tree from live feeds.

## Environment

| Variable | Required | Purpose |
|----------|----------|---------|
| `PII_MASTER_KEY` | API | 32+ byte key (64-hex preferred). API refuses to start without it. |
| `AUTH_MODE`, `API_KEY` | Tests/API | Required before importing the FastAPI app. |
| `VASP_DID` | No | This VASP's DID. Default `did:web:vasp.example.com`. |
| `CIRCUIT_ARTIFACTS_DIR` | No | Default `./artifacts`. |
| `CORS_ALLOWED_ORIGINS` | No | Default `http://localhost:3000`. |
| `DEPLOYER_PRIVATE_KEY`, `SEPOLIA_RPC_URL` | Deploy only | For Hardhat deployment scripts. |
