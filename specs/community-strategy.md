# ZK Travel Rule — Developer Community Growth Strategy

## NLSpec: Open Source Packaging & Community Launch

**Version:** 1.0
**Date:** 2026-03-30
**Status:** Draft — pending review
**Derived from:** Multi-LLM strategy debate (Codex, Sonnet, Qwen) + Semaphore/PSE/circomlib packaging research

---

## 1. Strategic Positioning

### Identity
**Name:** `zk-travel-rule`
**Tagline:** "ZK infrastructure for compliant value transfer"
**Positioning:** This is ZK infrastructure — not compliance software, not privacy tech. Developers build on infrastructure; compliance teams buy software. We want builders first, buyers second.

### Framing Rules
- DO say: "ZK infrastructure for compliant DeFi"
- DO say: "Privacy-preserving compliance proofs"
- DO NOT say: "Compliance tooling" (boring, repels OSS contributors)
- DO NOT say: "Privacy tech" (regulatory red flag, per debate consensus)
- DO NOT say: "Replaces PII" (regulators reject this framing)

### Comparable Projects

| Project | What worked | What to copy |
|---------|------------|-------------|
| **Semaphore** | Clean circuit primitive, npm packages, strong docs | Monorepo structure, `@scope/circuits` package, template CLI |
| **WorldID** | Simple integration path, developer docs | "Prove X without revealing Y" narrative |
| **circomlib** | Foundational library, everyone depends on it | File-path imports, minimal surface area |
| **PSE/zk-kit** | Individual circuit packages with `.circom` suffix | Scoped npm packages, composable circuits |
| **Tornado Cash** | Compelling demo, clear repos (CLI/relayer/UI) | 60-second proof demo (not the legal strategy) |

---

## 2. Monorepo Structure

Follow the **Semaphore pattern** exactly: `packages/` for publishable libraries, `apps/` for reference implementations, `examples/` for onboarding.

```
zk-travel-rule/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                    # Lint + test all packages
│   │   ├── circuits-test.yml         # Compile circuits + run circuit tests
│   │   └── release.yml               # Changesets-based npm publish
│   └── CODEOWNERS                    # 2-3 founding maintainers
│
├── packages/
│   ├── circuits/                     # npm: @zk-travel-rule/circuits
│   │   ├── src/
│   │   │   ├── compliance.circom
│   │   │   ├── sanctions-nonmembership.circom
│   │   │   ├── credential-validity.circom
│   │   │   ├── amount-tier.circom
│   │   │   └── lib/
│   │   │       ├── merkle-tree.circom
│   │   │       └── poseidon-hasher.circom
│   │   ├── artifacts/                # Pre-compiled: wasm, zkey, vk.json
│   │   │   ├── compliance.wasm
│   │   │   ├── compliance_final.zkey
│   │   │   └── verification_key.json
│   │   ├── test-vectors/             # Known-good inputs/outputs for every circuit
│   │   │   ├── sanctions-nonmembership.json
│   │   │   ├── credential-validity.json
│   │   │   └── amount-tier.json
│   │   ├── scripts/
│   │   │   ├── compile.sh            # circom compile + trusted setup
│   │   │   └── export-verifier.sh    # snarkjs zkey export solidityverifier
│   │   ├── package.json
│   │   └── README.md                 # Circuit docs, input/output schemas, usage
│   │
│   ├── proof/                        # npm: @zk-travel-rule/proof
│   │   ├── src/
│   │   │   ├── prover.ts             # TypeScript SnarkJS wrapper
│   │   │   ├── verifier.ts           # Groth16 verification
│   │   │   └── types.ts              # ComplianceProof, HybridPayload types
│   │   ├── package.json
│   │   └── README.md
│   │
│   ├── contracts/                    # npm: @zk-travel-rule/contracts
│   │   ├── src/
│   │   │   ├── Groth16Verifier.sol   # Auto-generated from snarkjs
│   │   │   └── ComplianceRegistry.sol # On-chain proof registry (optional)
│   │   ├── test/
│   │   │   └── Verifier.test.ts      # Hardhat test: prove + verify on-chain
│   │   ├── hardhat.config.ts
│   │   ├── package.json
│   │   └── README.md
│   │
│   ├── sdk-python/                   # PyPI: zk-travel-rule
│   │   ├── src/
│   │   │   ├── prover/               # SnarkJS subprocess wrapper
│   │   │   ├── protocol/             # ComplianceProof, HybridPayload, IVMS101
│   │   │   ├── registry/             # Credential, sanctions, issuer registries
│   │   │   ├── sar/                  # Encryption, SAR review, audit log
│   │   │   └── api/                  # FastAPI routes
│   │   ├── pyproject.toml
│   │   └── README.md
│   │
│   └── cli/                          # npm: @zk-travel-rule/cli
│       ├── src/
│       │   ├── commands/
│       │   │   ├── prove.ts          # Generate compliance proof
│       │   │   ├── verify.ts         # Verify compliance proof
│       │   │   ├── demo.ts           # 60-second end-to-end demo
│       │   │   └── init.ts           # Scaffold new integration
│       │   └── index.ts
│       ├── package.json
│       └── README.md
│
├── apps/
│   └── bridge/                       # Docker: reference FastAPI bridge
│       ├── Dockerfile
│       ├── docker-compose.yml
│       └── README.md                 # "Run the full bridge in 3 commands"
│
├── examples/
│   ├── quickstart/                   # 60-second proof generation
│   │   ├── generate-proof.ts         # 20 lines: prove compliance
│   │   ├── verify-proof.ts           # 10 lines: verify proof
│   │   ├── input.json                # Sample circuit input
│   │   └── README.md                 # Copy-paste walkthrough
│   │
│   ├── hardhat-verify/               # On-chain Groth16 verification
│   │   ├── deploy.ts                 # Deploy Groth16Verifier.sol
│   │   ├── verify-on-chain.ts        # Submit proof to contract
│   │   └── README.md
│   │
│   ├── trisa-bridge/                 # TRISA integration example
│   │   ├── send-hybrid-payload.py
│   │   └── README.md
│   │
│   └── jupyter-walkthrough/          # Interactive notebook
│       ├── travel-rule-proof.ipynb   # Full PII encryption + proof pipeline
│       └── README.md
│
├── docs/
│   ├── architecture.md               # System design overview
│   ├── circuits.md                    # Circuit specifications + constraint counts
│   ├── integration-guide.md           # VASP integration walkthrough
│   ├── threat-model.md                # Security assumptions + attack vectors
│   └── regulatory-positioning.md      # FATF/GENIUS Act compliance framing
│
├── turbo.json                         # Turborepo task orchestration
├── package.json                       # Workspace root
├── LICENSE                            # Apache-2.0
├── CONTRIBUTING.md
├── SECURITY.md                        # Vulnerability disclosure
├── ROADMAP.md                         # v0.1 → v0.2 → v1.0 feature roadmap
└── README.md                          # Hero: "Prove compliance. Protect privacy."
```

---

## 3. Package Specifications

### 3.1 `@zk-travel-rule/circuits` (npm)

**The community magnet.** This is the Semaphore `@semaphore-protocol/circuits` equivalent.

**What ships:**
- 6 Circom source files under `src/`
- Pre-compiled artifacts (wasm + zkey + verification_key.json) under `artifacts/`
- Test vectors for every circuit (known-good input → expected output)
- `README.md` with circuit schemas, constraint counts, public/private input specs

**How developers use it:**
```bash
npm install @zk-travel-rule/circuits
```

```circom
// In their own circuit:
include "@zk-travel-rule/circuits/src/sanctions-nonmembership.circom";
include "@zk-travel-rule/circuits/src/credential-validity.circom";
```

```bash
# Compile with import resolution:
circom my-circuit.circom \
  -l node_modules/@zk-travel-rule/circuits/src \
  -l node_modules/circomlib/circuits \
  --r1cs --wasm --sym
```

**Or use pre-compiled artifacts directly:**
```typescript
import { artifacts } from '@zk-travel-rule/circuits';
// artifacts.wasmPath, artifacts.zkeyPath, artifacts.vkeyPath
```

**Versioning:** Follow PSE convention — semver, with major bumps on circuit changes (new trusted setup required).

**Size budget:** < 50MB including pre-compiled artifacts (Semaphore's circuit package is ~30MB).

### 3.2 `@zk-travel-rule/proof` (npm)

**TypeScript SDK for proof generation and verification.**

```typescript
import { generateProof, verifyProof } from '@zk-travel-rule/proof';

const { proof, publicSignals } = await generateProof({
  sanctionsTreeRoot: '0x...',
  issuerTreeRoot: '0x...',
  amountTier: 2,
  transferTimestamp: Date.now() / 1000,
  jurisdictionCode: 8583,  // "US"
  credentialCommitment: '0x...',
  // ... private inputs
});

const valid = await verifyProof(proof, publicSignals);
```

**Dependencies:** `snarkjs`, `@zk-travel-rule/circuits` (for artifacts)

### 3.3 `@zk-travel-rule/contracts` (npm)

**Solidity verifier + optional on-chain registry.**

```bash
# Generate from circuit artifacts:
snarkjs zkey export solidityverifier \
  node_modules/@zk-travel-rule/circuits/artifacts/compliance_final.zkey \
  contracts/Groth16Verifier.sol
```

**Ships with:**
- Auto-generated `Groth16Verifier.sol`
- Optional `ComplianceRegistry.sol` (stores proof hashes on-chain)
- Hardhat test proving end-to-end on-chain verification
- Gas benchmarks in README

### 3.4 `zk-travel-rule` (PyPI)

**Python SDK for VASP backend integration.**

The current `src/` code, repackaged as a proper Python distribution:
- `prover/` — SnarkJS subprocess wrapper
- `protocol/` — ComplianceProof, HybridPayload, IVMS101 models
- `registry/` — Credential, sanctions, issuer registries
- `sar/` — AES-256-GCM encryption, SAR review flags, audit log
- `api/` — FastAPI routes (optional install)

```bash
pip install zk-travel-rule
# or with API server:
pip install zk-travel-rule[api]
```

### 3.5 `@zk-travel-rule/cli` (npm)

**Developer CLI for quickstart and testing.**

```bash
npx @zk-travel-rule/cli demo
# → Generates a test credential
# → Builds circuit inputs
# → Generates Groth16 proof via SnarkJS
# → Verifies proof locally
# → Prints hybrid payload (proof + encrypted PII)
# → Total time: < 60 seconds
```

```bash
npx @zk-travel-rule/cli prove --input input.json
npx @zk-travel-rule/cli verify --proof proof.json --public public.json
npx @zk-travel-rule/cli init --template trisa  # scaffold integration
```

---

## 4. Release Strategy

### Phase 1: Circuit Package (Week 1-2)

**Goal:** Ship `@zk-travel-rule/circuits@0.1.0` to npm.

**Deliverables:**
- [ ] Restructure repo to monorepo (Turborepo)
- [ ] Fix 13 circuit soundness issues from audit
- [ ] Compile circuits, generate artifacts
- [ ] Write test vectors for every circuit
- [ ] Write circuit documentation (constraint counts, input schemas)
- [ ] Publish `@zk-travel-rule/circuits@0.1.0` to npm
- [ ] Create GitHub release with changelog

**Success metric:** A developer can `npm install @zk-travel-rule/circuits`, include a circuit in their own project, and compile successfully.

### Phase 2: Proof SDK + Demo CLI (Week 3-4)

**Goal:** Ship the "60-second proof" experience.

**Deliverables:**
- [ ] Build `@zk-travel-rule/proof` TypeScript SDK
- [ ] Build `@zk-travel-rule/cli` with `demo` command
- [ ] Write quickstart example (20-line proof generation)
- [ ] Record terminal demo GIF for README
- [ ] Publish both packages to npm
- [ ] Write "Getting Started" guide in docs/

**Success metric:** `npx @zk-travel-rule/cli demo` generates and verifies a proof in < 60 seconds on a fresh machine.

### Phase 3: Contracts + Python SDK (Week 5-6)

**Goal:** Enable on-chain verification and VASP backend integration.

**Deliverables:**
- [ ] Generate and test Solidity verifier
- [ ] Build Hardhat example (deploy + verify on Sepolia)
- [ ] Repackage Python SDK for PyPI
- [ ] Write VASP integration guide
- [ ] Ship Docker image for the bridge
- [ ] Publish `@zk-travel-rule/contracts`, `zk-travel-rule` (PyPI)

**Success metric:** An EVM developer can verify a compliance proof on-chain. A Python developer can `pip install zk-travel-rule` and generate proofs.

### Phase 4: Community Launch (Week 7-8)

**Goal:** Public launch with maximum developer visibility.

**Deliverables:**
- [ ] Write announcement blog post
- [ ] Submit to Ethereum Research forum
- [ ] Post to r/ethdev, r/zeroknowledge, r/cryptocurrency
- [ ] Submit to PSE (Privacy & Scaling Explorations) project list
- [ ] Create "Good First Issues" (10+ tagged issues)
- [ ] Open GitHub Discussions
- [ ] Submit to Bittensor community forum (as future subnet proposal)
- [ ] Engage TRISA developer community

**Success metric:** 50+ GitHub stars, 5+ external contributors, 1+ integration PRs within 30 days.

---

## 5. Developer Personas & Funnels

### Persona 1: ZK Circuit Developer (Primary contributor)

**Profile:** Knows Circom/Noir, contributes to OSS, cares about circuit correctness
**Entry point:** `@zk-travel-rule/circuits` on npm
**Hook:** Novel circuits (sanctions non-membership gap proof, jurisdiction-aware tier encoding)
**Contribution path:** Audit circuits → file issues → submit PRs → become maintainer
**Comparable:** circomlib contributors, PSE/zk-kit contributors

### Persona 2: DeFi Protocol Developer (Key amplifier)

**Profile:** Builds on Ethereum/L2s, integrates compliance into protocols
**Entry point:** `@zk-travel-rule/contracts` + Hardhat example
**Hook:** On-chain compliance verification without oracle dependencies
**Contribution path:** Use contracts → request features → build integrations
**Comparable:** Uniswap integrators, Chainlink node operators

### Persona 3: VASP/Exchange Compliance Engineer (Primary customer)

**Profile:** Works at Coinbase/Binance/Kraken compliance team, Python/Go stack
**Entry point:** `zk-travel-rule` PyPI package + Docker bridge
**Hook:** Solves FATF Travel Rule with less PII exposure
**Contribution path:** Deploy bridge → file bugs → request jurisdictions → sponsor features
**Comparable:** TRISA adopters, Chainalysis SDK users

### Persona 4: Bittensor Subnet Developer (v2 target)

**Profile:** Runs Bittensor neurons, understands incentive economics
**Entry point:** ROADMAP.md → future subnet for proof generation market
**Hook:** TAO incentives for compliance proof computation
**Contribution path:** Read roadmap → express interest → build when subnet launches
**Comparable:** Existing Bittensor subnet operators (SN4/Targon, SN1/Prompting)

**Engagement funnel:**
```
npm install (circuits) → run demo → ⭐ star repo → read docs →
file issue → submit PR → become contributor → advocate
```

---

## 6. Governance & Legal

### License
**Apache 2.0** — provides patent grant required for enterprise compliance adoption. MIT is insufficient (no patent clause). GPL is incompatible with proprietary VASP backends.

### Governance Model
- **Maintainers:** 2-3 founding maintainers listed in `CODEOWNERS`
- **Contributions:** Standard GitHub Flow (fork → PR → review → merge)
- **Decisions:** Lazy consensus with 72-hour comment period for breaking changes
- **No DAO, no token, no foundation** — these structures repel the compliance-engineer persona and add legal complexity

### Security
- `SECURITY.md` with responsible disclosure policy
- Circuit changes require 2+ maintainer approval
- Trusted setup ceremony documented in `docs/trusted-setup.md`
- Pre-compiled artifacts signed with maintainer GPG keys

### Code of Conduct
Contributor Covenant v2.1 (industry standard).

---

## 7. Marketing & Distribution Channels

### Tier 1: Developer watering holes
- **Ethereum Research forum** — post explaining ZK compliance innovation
- **r/ethdev** — "Show HN"-style post with demo GIF
- **PSE project list** — submit for inclusion
- **ZK Podcast** — pitch episode on privacy-preserving compliance

### Tier 2: Compliance industry
- **TRISA developer community** — present hybrid payload approach
- **Chainalysis/Elliptic partner programs** — sanctions list integration
- **FATF FinTech Forum** — submit as innovation case study
- **GENIUS Act implementation working groups** — engage FinCEN

### Tier 3: Crypto ecosystem
- **ETHGlobal hackathons** — sponsor "Compliance Track" bounty
- **Bittensor community** — subnet proposal for v2
- **DeFi protocols** — direct outreach for on-chain verification integration

### Content calendar (first 90 days)
| Week | Content | Channel |
|------|---------|---------|
| 1 | "Introducing ZK Travel Rule" blog | Medium, Mirror |
| 2 | Demo video (60-second proof) | YouTube, Twitter |
| 4 | "Building ZK Compliance Circuits" tutorial | Ethereum Research |
| 6 | Hardhat verification walkthrough | r/ethdev |
| 8 | PSE presentation | PSE community call |
| 10 | TRISA integration case study | TRISA blog |
| 12 | "State of ZK Compliance" report | Blog, Twitter |

---

## 8. Metrics & Success Criteria

### 30-day targets (post-launch)
- [ ] 50+ GitHub stars
- [ ] 100+ npm weekly downloads (`@zk-travel-rule/circuits`)
- [ ] 5+ external contributors (PRs merged)
- [ ] 1+ VASP pilot integration started
- [ ] 10+ "Good First Issue" completions

### 90-day targets
- [ ] 200+ GitHub stars
- [ ] 500+ npm weekly downloads
- [ ] 20+ external contributors
- [ ] 3+ VASP integrations in progress
- [ ] 1+ DeFi protocol integration
- [ ] 1+ conference talk delivered
- [ ] Featured in PSE project list

### 180-day targets
- [ ] 500+ GitHub stars
- [ ] 2,000+ npm weekly downloads
- [ ] 50+ contributors
- [ ] Production deployment at 1+ VASP
- [ ] Bittensor subnet proposal submitted
- [ ] Halo2 migration evaluation complete

---

## 9. Roadmap (Public-Facing)

### v0.1.0 — "Proof of Concept" (Week 2)
- Circom circuits (sanctions, credential, tier)
- Pre-compiled Groth16 artifacts
- Test vectors + circuit documentation
- `@zk-travel-rule/circuits` on npm

### v0.2.0 — "Developer Experience" (Week 4)
- TypeScript proof SDK
- CLI with 60-second demo
- Quickstart examples
- Hardhat on-chain verifier

### v0.3.0 — "VASP Integration" (Week 6)
- Python SDK on PyPI
- FastAPI bridge (Docker)
- TRISA/TRP hybrid payload bridges
- Integration guide

### v0.4.0 — "Production Hardening" (Week 10)
- Multi-party trusted setup ceremony
- Circuit formal audit (external firm)
- HSM key management integration
- Load testing + benchmarks

### v1.0.0 — "Production" (Week 16)
- First VASP production deployment
- Regulatory sandbox approval (MAS or VARA)
- Complete compliance test suite
- SLA documentation

### v2.0.0 — "Scale" (Week 24+)
- Bittensor subnet for proof generation market
- Halo2 circuit migration (if needed)
- Multi-jurisdiction routing
- On-chain proof anchoring
- Targon CVM integration for attested SAR

---

## 10. Implementation: Monorepo Migration Steps

### Step 1: Initialize Turborepo workspace
```bash
# From current project root
npm install turbo --save-dev
# Create turbo.json with pipeline config
```

### Step 2: Move circuits to packages/circuits/
```bash
mkdir -p packages/circuits/src packages/circuits/artifacts
mv circuits/*.circom packages/circuits/src/
mv circuits/lib/ packages/circuits/src/lib/
# Create packages/circuits/package.json
```

### Step 3: Move Python code to packages/sdk-python/
```bash
mkdir -p packages/sdk-python
mv src/ packages/sdk-python/src/
mv pyproject.toml packages/sdk-python/
mv tests/ packages/sdk-python/tests/
```

### Step 4: Create TypeScript packages
```bash
mkdir -p packages/proof/src packages/contracts/src packages/cli/src
# Build TS packages
```

### Step 5: Create examples/
```bash
mkdir -p examples/quickstart examples/hardhat-verify examples/jupyter-walkthrough
# Write minimal examples
```

### Step 6: Set up CI/CD
```bash
mkdir -p .github/workflows
# Create ci.yml, circuits-test.yml, release.yml
```

---

## Appendix A: First npm Publish Checklist

- [ ] `packages/circuits/package.json` has correct `name`, `version`, `files`, `main`
- [ ] `packages/circuits/artifacts/` contains compiled wasm + zkey + vk.json
- [ ] `packages/circuits/test-vectors/` has at least 1 vector per circuit
- [ ] `packages/circuits/README.md` has usage examples
- [ ] LICENSE file is Apache-2.0
- [ ] `.npmignore` excludes test files, scripts, CI configs
- [ ] `npm pack` produces a package < 50MB
- [ ] `npm publish --dry-run` succeeds
- [ ] GitHub release tag matches npm version

## Appendix B: Semaphore Pattern Reference

Semaphore's `packages/` directory structure (current as of 2026):
```
packages/
├── circuits/        → @semaphore-protocol/circuits
├── contracts/       → @semaphore-protocol/contracts
├── core/            → @semaphore-protocol/core
├── data/            → @semaphore-protocol/data
├── group/           → @semaphore-protocol/group
├── hardhat/         → @semaphore-protocol/hardhat
├── identity/        → @semaphore-protocol/identity
├── proof/           → @semaphore-protocol/proof
├── utils/           → @semaphore-protocol/utils
└── cli/             → @semaphore-protocol/cli
```

Our mapping:
```
packages/
├── circuits/        → @zk-travel-rule/circuits    (Semaphore equiv)
├── proof/           → @zk-travel-rule/proof       (Semaphore equiv)
├── contracts/       → @zk-travel-rule/contracts   (Semaphore equiv)
├── sdk-python/      → zk-travel-rule (PyPI)       (no Semaphore equiv)
└── cli/             → @zk-travel-rule/cli         (Semaphore equiv)
```
