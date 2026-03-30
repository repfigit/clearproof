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
# Install circuit package
npm install @clearproof/circuits

# Generate a compliance proof (60 seconds)
npx @clearproof/cli demo

# Or use the Python SDK
pip install clearproof
```

## What's Inside

| Package | Description |
|---------|-------------|
| `circuits/` | Circom circuits — sanctions non-membership, credential validity, amount tier |
| `src/prover/` | SnarkJS Groth16 prover (VASP-local, no external network) |
| `src/protocol/` | ComplianceProof, HybridPayload, IVMS101 data models |
| `src/protocol/bridges/` | TRISA (gRPC), TRP/OpenVASP (REST), TAIP-10 (W3C VP) |
| `src/sar/` | AES-256-GCM encryption, SAR review flags (advisory), audit log |
| `src/api/` | FastAPI gateway with JWT/API-key auth |
| `src/registry/` | Credential, sanctions Merkle tree, trusted issuer registries |
| `tests/` | 100 tests (unit + integration + compliance) |

## Circuits

Six Circom circuits proving compliance without revealing private data:

- **`compliance.circom`** — Main composed circuit wiring all subcircuits
- **`sanctions_nonmembership.circom`** — Sorted Merkle tree gap proof (wallet NOT sanctioned)
- **`credential_validity.circom`** — Poseidon commitment check, expiry, issuer membership
- **`amount_tier.circom`** — Jurisdiction-specific threshold encoding with SAR flag
- **`lib/merkle_tree.circom`** — Poseidon-based membership and non-membership proofs
- **`lib/poseidon_hasher.circom`** — Domain-separated Poseidon hash wrapper

All circuits are audited for soundness: range checks on all comparator inputs, adjacency derived from Merkle path bits, thresholds as public inputs.

## Regulatory Positioning

This is **compliance infrastructure** — not privacy technology.

- ZK proofs demonstrate that compliance was performed correctly
- Encrypted PII satisfies the regulatory obligation to transmit originator/beneficiary information
- Both artifacts travel together in every message
- Target jurisdictions: Singapore (MAS), UAE (VARA), then EU (MiCA)
- Hybrid approach satisfies FATF Rec 16 "transmit" requirement

## Development

```bash
# Install dependencies
uv sync --all-extras    # Python
npm install             # Node (circom, snarkjs)

# Run tests
uv run pytest tests/ -v

# Compile circuits (requires circom + snarkjs)
bash scripts/compile_circuits.sh

# Start API server
uv run uvicorn src.api.main:app --reload --port 8000
```

## Architecture Decisions

Key decisions made via [multi-LLM adversarial debate](specs/community-strategy.md) (Codex + Gemini + Sonnet + Qwen):

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Proof system | Circom/Groth16 | Smallest proofs (192B), cheapest verification, mature auditor ecosystem |
| Proving | VASP-local | No external network dependency; deterministic latency |
| PII handling | Hybrid (encrypted PII + ZK) | Satisfies regulatory "transmit" requirement |
| SAR logic | Advisory flags | FinCEN SAR is activity-based, not amount-based |
| License | Apache-2.0 | Patent grant for enterprise compliance adoption |

## Roadmap

- **v0.1** — Circuit package on npm + 60-second demo CLI
- **v0.2** — TypeScript proof SDK + Hardhat on-chain verifier
- **v0.3** — Python SDK on PyPI + Docker bridge
- **v0.4** — Multi-party trusted setup + circuit audit
- **v1.0** — First VASP production deployment
- **v2.0** — Bittensor subnet + Halo2 migration

## License

[Apache-2.0](LICENSE)
