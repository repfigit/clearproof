# SRC/ AGENTS.md

**Scope:** Python SDK core — FastAPI gateway, protocol models, storage, chain, SAR, registry.

## OVERVIEW
Monorepo Python package (`clearproof`) implementing the ZK Travel Rule compliance engine. FastAPI + asyncpg + web3.py + cryptography.

## STRUCTURE
```
src/
├── api/              # FastAPI routes + middleware (auth, proof, credential, health)
├── protocol/         # Core models: ComplianceProof, HybridPayload, IVMS101, bridges/
├── storage/          # asyncpg + psycopg: database, sanctions Merkle, credentials, audit, keyring
├── chain/            # web3.py readers/writers + audit mirror
├── sar/              # AES-256-GCM encryption, SAR flags, review workflow
├── registry/         # Credential/sanctions/issuer registries (in-memory + DB)
├── prover/           # Python proving path (thin wrapper)
├── auth/             # SIWE + JWT middleware
└── circuits/         # Circuit input builders (keep in sync with circuits/)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add new API route | `src/api/routes/` + `src/api/main.py` | Include router, add auth dependency |
| Compliance logic | `src/protocol/compliance_proof.py` | Model + witness builder |
| Hybrid payload | `src/protocol/hybrid_payload.py` | Encryption envelope |
| New bridge | `src/protocol/bridges/` | TRISA (gRPC), TRP (REST), TAIP-10 |
| Storage schema | `src/storage/models.py` + migrations | asyncpg + psycopg |
| Chain write | `src/chain/writer.py` | web3.py + audit mirror |
| Encryption | `src/sar/encryption.py` | AES-256-GCM + keyring |

## CONVENTIONS
- **Python 3.11+**, ruff (E,F,I,W only), line-length 120
- **Async-first**: All DB/chain I/O via asyncpg/web3 async patterns
- **No raw PII**: All PII flows through `HybridPayload` encryption
- **Bridge protobufs**: Generated files (`*_pb2.py`, `*_pb2_grpc.py`) — NEVER edit manually
- **Registry pattern**: In-memory cache + DB fallback for sanctions/credentials/issuers

## ANTI-PATTERNS
- NEVER bypass `PII_MASTER_KEY` check in `src/api/main.py`
- NEVER resolve ENS names for sanctions — raw hex addresses only
- NEVER store decrypted PII outside encrypted envelope
- NEVER edit generated protobuf files in `bridges/`
- NEVER skip sanctions Merkle root relay after tree rebuild

## COMMANDS
```bash
# Run dev API
make dev

# All Python tests
make test
make test-unit
make test-integration
make test-compliance

# Lint/format
make lint
make format
```

## NOTES
- API startup fails fast if `PII_MASTER_KEY` invalid (64 hex or ≥32 UTF-8 bytes)
- Sanctions tree rebuild (`scripts/build_sanctions_tree.py`) must be followed by oracle relay
- Circuit artifacts path configurable via `CIRCUIT_ARTIFACTS_DIR` env
- TRISA bridge requires `protos/` regeneration via protoc if `.proto` changes
