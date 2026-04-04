# clearproof

**ZK infrastructure for compliant value transfer.**

Generate zero-knowledge proofs that FATF Travel Rule compliance was performed correctly — without transmitting raw PII between counterparties. Encrypted PII travels alongside the proof in a hybrid payload, satisfying regulatory "transmit" requirements while minimizing data exposure.

## What It Does

```
Originator VASP                          Beneficiary VASP
      │                                        │
      ├─ Generate ZK proof ◄── Circom/Groth16  │
      ├─ Encrypt PII ◄──────── AES-256-GCM     │
      ├─ Build hybrid payload                   │
      │       │                                 │
      │       ▼                                 │
      │  ┌─────────────────────┐                │
      │  │ Hybrid Payload      │                │
      │  │ ┌─ ZK Proof ──────┐ │  ──────────►  ├─ Verify proof (<50ms)
      │  │ │ sanctions clear  │ │               ├─ Decrypt PII if needed
      │  │ │ credential valid │ │               ├─ Log to audit trail
      │  │ │ tier correct     │ │               │
      │  │ └─────────────────┘ │                │
      │  │ ┌─ Encrypted PII ─┐ │                │
      │  │ │ AES-256-GCM     │ │                │
      │  │ └─────────────────┘ │                │
      │  └─────────────────────┘                │
```

**The ZK proof attests.** Encrypted PII satisfies the law. Neither requires the other — but together they give VASPs cryptographic compliance evidence with minimal data sprawl.

## Quick Start

```bash
# Clone and build (circuit compilation required)
git clone https://github.com/repfigit/clearproof.git
cd clearproof
npm install && uv sync --all-extras
bash scripts/compile_circuits.sh    # ~5 min, requires circom
npx @clearproof/cli demo
```

You can also install the circuits package standalone:

```bash
npm install @clearproof/circuits
```

> **Note:** The CLI currently requires locally compiled circuit artifacts. The `@clearproof/circuits` npm package will bundle pre-compiled artifacts in a future release.

For the Python SDK, install locally (PyPI publishing is planned):

```bash
pip install -e ".[all]"
```

## What's Inside

| Package | Description |
|---------|-------------|
| `circuits/` | Circom circuits — sanctions non-membership, credential validity, amount tier, proof expiration |
| `packages/contracts/` | Solidity contracts — Groth16 verifier, ComplianceRegistry, VASPRegistry, SanctionsOracle |
| `packages/proof/` | TypeScript SDK for generating and verifying ZK compliance proofs |
| `packages/cli/` | CLI tool with demo command for proof generation |
| `src/api/` | FastAPI gateway with JWT/SIWE auth |
| `src/protocol/` | ComplianceProof, HybridPayload, IVMS101 data models |
| `src/protocol/bridges/` | TRISA (gRPC), TRP/OpenVASP (REST), TAIP-10 (W3C VP) |
| `src/sar/` | AES-256-GCM encryption, SAR review flags (advisory), audit log |
| `src/registry/` | Credential, sanctions Merkle tree, trusted issuer registries |
| `tests/` | ~190 tests (144 Python + 46 Hardhat) across unit, integration, compliance, and E2E |

## Circuits

Six Circom circuits proving compliance without revealing private data:

- **`compliance.circom`** — Main composed circuit wiring all subcircuits (16 public signals)
- **`sanctions_nonmembership.circom`** — Sorted Merkle tree gap proof (wallet NOT sanctioned)
- **`credential_validity.circom`** — Poseidon commitment check, expiry, issuer membership
- **`amount_tier.circom`** — Jurisdiction-specific threshold encoding with SAR flag
- **`lib/merkle_tree.circom`** — Poseidon-based membership and non-membership proofs
- **`lib/poseidon_hasher.circom`** — Domain-separated Poseidon hash wrapper

### Public Signals (16)

| Index | Signal | Purpose |
|-------|--------|---------|
| 0 | `is_compliant` | 1 if all checks pass (output) |
| 1 | `sar_review_flag` | 1 if tier >= 3 (output) |
| 2 | `sanctions_tree_root` | Current OFAC/UN/EU Merkle root |
| 3 | `issuer_tree_root` | Trusted credential issuer root |
| 4 | `amount_tier` | 1-4 (not the exact amount) |
| 5 | `transfer_timestamp` | Unix timestamp |
| 6 | `jurisdiction_code` | ISO 3166-1 alpha-2 encoded |
| 7 | `credential_commitment` | Poseidon hash of credential preimage |
| 8-10 | `tier2/3/4_threshold` | Jurisdiction-specific boundaries |
| 11 | `domain_chain_id` | Binds proof to specific chain |
| 12 | `domain_contract_hash` | Binds proof to specific ComplianceRegistry |
| 13 | `transfer_id_hash` | Binds proof to specific transfer |
| 14 | `credential_nullifier` | One-time use (prevents proof replay) |
| 15 | `proof_expires_at` | Proof TTL enforced on-chain |

All circuits are audited for soundness: range checks on all comparator inputs, adjacency derived from Merkle path bits, thresholds as public inputs, domain binding for cross-chain replay prevention.

## On-Chain Contracts

Deployed to **Sepolia testnet**:

| Contract | Address | Purpose |
|----------|---------|---------|
| Groth16Verifier | `0xa8DF5a9F02cB6113463327C54F6e03C682D00a7a` | Proof verification (snarkjs-generated) |
| VASPRegistry | `0x89535b85EB5a4F9Fb30a09d4c0Ad9f1614C8f0E7` | VASP registration + issuer root |
| SanctionsOracle | `0x05446C7A45c7Bd84F4702022B68232242c05Ffd1` | Sanctions Merkle root with staleness checks |
| ComplianceRegistry | `0x3e4601759064654f28C5368f2B444A749AB26D8f` | Domain-bound proof verification + recording |
| SanctionsRootRelay | `0x1e808E9739f24b80bEb379B1a88e4152eB41635A` | Multi-chain sanctions root relay |

### Security Properties

- **Domain binding** — proofs are bound to a specific chain ID + contract address (cross-chain replay prevention)
- **Nullifier** — each credential+transfer pair produces a unique nullifier (proof reuse prevention)
- **Transfer binding** — proof is bound to a specific `transferId` hash
- **Proof expiration** — `proof_expires_at` enforced on-chain via `block.timestamp`
- **State binding** — proof must match current sanctions root and issuer root
- **VASP binding** — only the registered VASP wallet can submit proofs
- **Credential revocation** — revoked credentials are rejected on-chain
- **Dependency health** — sanctions oracle staleness and VASP registry pause checks

## Sanctions List Management

The sanctions Merkle tree is rebuilt from live feeds (OFAC SDN XML, OFAC Consolidated CSV, EU Consolidated Sanctions) and updated on-chain through a two-step operator workflow:

```bash
# Automated: daily cron rebuilds the tree (GitHub Actions, 06:00 UTC)
# See .github/workflows/sanctions-update.yml

# Manual: operator reviews diff and submits on-chain root update
make update-sanctions-oracle NETWORK=sepolia

# Or step by step:
python scripts/build_sanctions_tree.py                          # rebuild tree
cd packages/contracts
npm run update-sanctions -- --network sepolia                   # submit to oracle
```

The oracle enforces safety invariants:
- **Cooldown** — minimum 1 hour between updates
- **Leaf count floor** — new tree must have >= 50% of current leaf count (prevents accidental clearing)
- **Staleness detection** — `isStale()` returns true after configurable grace period (default 24h)
- **Root history** — ring buffer of last 1000 roots for auditability

Delisting propagation is automatic: when an address is removed from upstream OFAC/EU lists, the next tree rebuild excludes it, and the oracle update propagates the change on-chain. Human confirmation is required before submitting.

## Development

```bash
# Install dependencies
uv sync --all-extras    # Python
npm install             # Node (circom, snarkjs, hardhat)

# Run all tests
uv run pytest tests/ -v                           # 119 Python tests
cd packages/contracts && npx hardhat test          # 24 Hardhat tests

# Compile circuits (requires circom + snarkjs)
bash scripts/compile_circuits.sh

# Type-check TypeScript packages
cd packages/proof && npx tsc --noEmit
cd packages/cli && npx tsc --noEmit

# Start API server (requires PII_MASTER_KEY env var)
PII_MASTER_KEY=your-32-byte-key uv run uvicorn src.api.main:app --reload --port 8000
```

Start the API server and visit `http://localhost:8000/docs` for interactive Swagger documentation.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PII_MASTER_KEY` | Yes | Stable key for PII encryption (server will not start without it) |
| `VASP_DID` | No | This VASP's DID (default: `did:web:vasp.example.com`) |
| `CIRCUIT_ARTIFACTS_DIR` | No | Path to circuit artifacts (default: `./artifacts`) |
| `CORS_ALLOWED_ORIGINS` | No | Comma-separated origins (default: `http://localhost:3000`) |
| `DEPLOYER_PRIVATE_KEY` | For deploy | Wallet private key for contract deployment |
| `SEPOLIA_RPC_URL` | For deploy | Sepolia RPC endpoint |

## Documentation Roadmap

Detailed documentation is planned for the `docs/` directory, including `docs/architecture.md`, `docs/threat-model.md`, and `docs/integration-guide.md`. Contributions welcome.

## Architecture Decisions

Key decisions made via multi-LLM adversarial debate (Codex + Gemini + Sonnet + Qwen):

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Proof system | Circom/Groth16 | Smallest proofs (192B), cheapest verification, mature auditor ecosystem |
| Proving | VASP-local | No external network dependency; deterministic latency |
| PII handling | Hybrid (encrypted PII + ZK) | Satisfies regulatory "transmit" requirement |
| SAR logic | Advisory flags | FinCEN SAR is activity-based, not amount-based |
| On-chain verification | Domain-bound | Prevents cross-chain and cross-contract replay |
| Sanctions updates | Operator-confirmed | Human review before on-chain propagation |
| License | Apache-2.0 | Patent grant for enterprise compliance adoption |

## CI

Four jobs run on every push to `main`:

| Job | What it checks |
|-----|---------------|
| `python-tests` | 119 pytest tests (unit + integration + compliance) |
| `typescript-build` | Type-check `@clearproof/proof` and `@clearproof/cli` |
| `hardhat-tests` | 24 Hardhat tests (contracts + E2E prove-submit-verify) |
| `circuits` | Circom compilation (syntax + constraint check) |

A daily `sanctions-update` cron job rebuilds the sanctions Merkle tree from live OFAC/EU feeds.

## NPM Packages

| Package | Version | Description |
|---------|---------|-------------|
| [`@clearproof/circuits`](https://www.npmjs.com/package/@clearproof/circuits) | 0.2.0 | Compiled circuit artifacts (WASM + zkey) |
| [`@clearproof/proof`](https://www.npmjs.com/package/@clearproof/proof) | 0.2.0 | TypeScript SDK for proof generation/verification |
| [`@clearproof/cli`](https://www.npmjs.com/package/@clearproof/cli) | 0.2.0 | CLI tool with demo command |
| [`@clearproof/contracts`](https://www.npmjs.com/package/@clearproof/contracts) | 0.2.0 | Solidity contracts + ABIs |

## License

[Apache-2.0](LICENSE)
