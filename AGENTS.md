# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-21
**Commit:** 0f725e4
**Branch:** main

## OVERVIEW
ZK infrastructure for FATF Travel Rule compliance. Generates Groth16 proofs (Circom) attesting sanctions/credential/amount checks; hybrid payload bundles proof + AES-256-GCM encrypted PII for regulatory transmission without raw data exposure.

## STRUCTURE
```
clearproof/
├── src/                    # Python SDK (FastAPI, protocol, storage, chain, sar, registry)
├── packages/contracts/     # Solidity (Hardhat) — Groth16Verifier, ComplianceRegistry, VASPRegistry, SanctionsOracle
├── packages/proof/         # TypeScript SDK (snarkjs) — generateProof/verifyProof
├── packages/cli/           # CLI (demo, proof generation)
├── packages/content/       # Marketing/content package
├── circuits/               # Circom sources (compliance.circom + test vectors)
├── tests/                  # pytest: unit/, integration/, compliance/
├── scripts/                # sanctions tree, circuit compile, benchmark, deploy
├── apps/docs/              # Next.js documentation site
├── protos/                 # gRPC .proto for TRISA bridge
└── artifacts/              # Compiled circuit artifacts (wasm, zkey, vkey, ptau cache)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add compliance check | `src/protocol/compliance_proof.py` + `circuits/` | Keep Python model + circuit in sync |
| New protocol bridge | `src/protocol/bridges/` | Follow TRISA (gRPC), TRP (REST), TAIP-10 (VP) patterns |
| On-chain change | `packages/contracts/contracts/` | Hardhat test + multi-chain deploy |
| Sanctions update | `scripts/build_sanctions_tree.py` | Merkle root → oracle relay |
| Proof generation | `packages/proof/src/` or `src/prover/` | TS (snarkjs) vs Python paths |
| API route | `src/api/routes/` | JWT + SIWE auth required |
| Storage layer | `src/storage/` | asyncpg + psycopg, sanctions Merkle |
| Chain interaction | `src/chain/` | web3.py reader/writer + audit mirror |

## CODE MAP
| Symbol | Type | Location | Role |
|--------|------|----------|------|
| ComplianceProof | class | src/protocol/compliance_proof.py | Core proof builder (inputs → witness) |
| HybridPayload | class | src/protocol/hybrid_payload.py | ZK proof + encrypted PII envelope |
| Database | class | src/storage/database.py | Connection pool, migrations |
| SanctionsOracle | contract | packages/contracts/contracts/ | On-chain Merkle root storage |
| generateProof | fn | packages/proof/src/prover.ts | snarkjs fullProve wrapper |
| SIWEAuth | middleware | src/api/middleware/ | Sign-In with Ethereum + JWT |

## CONVENTIONS
- Python: ruff (E,F,I,W only), line-length 120, target 3.11+
- TypeScript: strict, vitest, noEmit for typecheck in CI
- Solidity: 0.8.24, optimizer runs=200
- Commits: conventional (feat/fix/docs/chore)
- Multi-chain: `make deploy NETWORK=<name>` then `make relay-sanctions`
- Circuit artifacts: committed only from audited trusted setup; dev builds are local-only
- PII_MASTER_KEY: required at API startup (64 hex chars or ≥32 UTF-8 bytes)

## ANTI-PATTERNS (THIS PROJECT)
- NEVER log or store raw PII outside encrypted envelope
- ENS names are NEVER resolved for sanctions — raw hex addresses only
- Do not edit generated pb2/pb2_grpc files in `src/protocol/bridges/`
- Never skip sanctions oracle relay after root update — all chains must be consistent
- Production proving keys must come from documented multi-party ceremony

## COMMANDS
```bash
# Setup
npm install && uv sync --all-extras

# Build all workspaces
npm run build

# Compile circuits (requires circom + ptau)
bash scripts/compile_circuits.sh

# Test layers
npm test                    # turbo (ts + hardhat)
make test                   # all Python
make test-unit
make test-integration
make test-compliance

# Sanctions
make build-sanctions-tree
make update-sanctions-oracle NETWORK=ethereum
make relay-sanctions        # all deployed chains

# Dev API
make dev                    # uvicorn src.api.main:app --reload

# Deploy
make deploy NETWORK=arbitrum-sepolia
```

## NOTES
- API refuses to start without valid PII_MASTER_KEY
- Circuit compilation (~5 min first run); CI caches ptau18
- TRISA bridge depends on generated protobufs — regenerate via protoc if protos/ changes
- Multi-chain deployment uses Hardhat scripts in `packages/contracts/scripts/`

## LAYOUT NOTES
- Python package installs as `clearproof` (pyproject.toml) but source lives at `src/` with internal imports `from src.api...`, `from src.protocol...`.
- This is deliberate (monorepo + editable install) but unusual. New contributors often trip on the `src.` prefix.
- All AGENTS.md files document the actual import paths used in this repo.
