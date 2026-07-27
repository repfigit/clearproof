# Roadmap

clearproof is moving from a research-oriented ZK Travel Rule repo to a production compliance platform for regulated VASPs.

The strategic wedge is narrow by design: **privacy-preserving Travel Rule infrastructure that interoperates with rails VASPs already use**, especially TRP/OpenVASP and TRISA. clearproof should not be positioned as a generic ZK compliance toolkit or as a replacement for Travel Rule networks. It should prove compliance, minimize PII exposure, and exchange required Travel Rule data through existing protocols.

## Production Definition

clearproof is production quality when a regulated VASP can run real or shadow-mode transfers with:

- Durable tenant-scoped state for credentials, proofs, revocations, sanctions roots, nullifiers, and audit events
- Counterparty-decryptable encrypted PII with clear key exchange, key IDs, rotation, and decrypt audit
- Off-chain verification equivalent to on-chain verification
- TRP, TRISA, and IVMS101 interoperability
- Signed sanctions/root provenance with stale-data fail-closed behavior
- Audited circuits, contracts, trusted setup, and operational runbooks
- Clear liability boundaries, SLAs, retention policies, and compliance exports

## Regulatory And Ecosystem Anchors

- FATF Travel Rule implementation continues expanding globally, but interoperability and enforcement remain uneven: https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-update-virtual-assets-vasps-2025.html
- **FATF R.16 2025 revisions** expanded scope from "virtual asset transfers" to "payments or value transfers and related messages," broadening coverage to include messaging around transfers and emphasizing supervision/enforcement (93% of jurisdictions now have Travel Rule laws): https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-update-virtual-assets-vasps-2025.html
- **FATF Best Practices on Travel Rule Supervision (2025)** provides guidance on what supervisors expect in examinations: evidence of originator/beneficiary information transmission, sanctions screening, record retrieval, and revocation handling
- EU Travel Rule guidance for funds and crypto-asset transfers applies from 30 December 2024: https://www.eba.europa.eu/publications-and-media/press-releases/eba-issues-travel-rule-guidance-tackle-money-laundering-and-terrorist-financing-transfers-funds-and
- U.S. funds travel rule and recordkeeping concepts remain anchored in FinCEN guidance: https://www.fincen.gov/index.php/resources/statutes-regulations/guidance/funds-travel-regulations-questions-answers
- TRP is a mature open Travel Rule protocol with VASP implementations: https://www.openvasp.org/trp
- TRISA provides VASP identity, PKI, GDS, and protocol infrastructure: https://www.trisa.io/

## Current Progress Snapshot

**As of 2026-05-05**

| Track | Current status | Progress | Next proof point |
| --- | --- | --- | --- |
| Research/pilot foundation | Mostly implemented | Groth16 circuit, FastAPI gateway, SDK, CLI, contracts, sanctions tree, hybrid payloads, bridge models, docs, and tests are present | Clean hosted sandbox and pilot limitations document |
| Developer adoption | Implemented for package-first demo path | CLI now uses bundled circuit artifacts, docs include auth headers, SDK README matches exports, on-chain scripts exist | A five-minute hosted quickstart that needs no repo clone |
| Test coverage | Strengthened | Python, Hardhat, package Vitest, docs build, and CLI demo checks pass locally | CI should run the same full suite on every PR |
| Vulnerability cleanup | Partially complete | Non-breaking dependency cleanup done where possible; remaining production audit items require breaking dependency changes | Decide whether to migrate off vulnerable transitive chains or accept short-term risk |
| Production core | Not production-ready | Some auth modes and verification pieces exist, but durable state, tenant isolation, key delivery, and audit durability are not complete. Verifier parity now has a committed test vector enforced in CI (off-chain + on-chain); full registry-check parity remains open | Postgres/Redis-backed tenant-scoped pilot flow |
| Travel Rule interoperability | Prototype level | TRP/TRISA data models and tests exist; full client/server transport, GDS, cert lifecycle, signing, and counterparty workflows remain | Bilateral TRP or TRISA simulator run |
| Security assurance | Pre-audit | Threat areas are known; dev trusted setup and software keys remain blockers | External audit plan plus production trusted setup path |
| Managed platform | Not started | No tenant admin console, SLAs, billing, status page, or managed root service yet | Design-partner pilot environment |
| Business readiness | Strategy defined, not operationalized | ICP, buyer, positioning, pricing direction, and liability concerns are identified | Design partner criteria and pilot success metrics |
| Chain/oracle support | Strong pilot foundation | EVM deploy, relay, deterministic tree, and discovery primitives are implemented | Registry-backed discovery verification and multi-operator root attestation |

Current validation baseline:

- [x] `npm run build`
- [x] `npm run test:ts`
- [x] `npm test -- --quiet`
- [x] `cd packages/contracts && npx hardhat test`
- [x] `cd packages/cli && node dist/index.js demo`

## Phase 0: Current Foundation

**Status: Mostly implemented for pilot use**

This repo already has the technical spine for a pilot:

- [x] FastAPI proof gateway
- [x] Groth16 compliance circuit with 16 public signals
- [x] TypeScript proof SDK and CLI demo
- [x] EVM `ComplianceRegistry`, `VASPRegistry`, `SanctionsOracle`, and `SanctionsRootRelay`
- [x] Deterministic sanctions tree builder with persisted witnesses
- [x] Hybrid payload model with encrypted PII
- [x] TRP/TRISA bridge models and integration tests
- [x] Package-first demo path using bundled circuit artifacts
- [x] Auth-aware recipes and on-chain walkthrough scripts
- [x] Focused tests for circuit metadata, CLI artifact resolution, SDK discovery, and docs recipes
- [x] Full local validation baseline passing

Known limitation: this is still a pilot/research foundation. Production readiness depends on durable state, key management, protocol interop, audit durability, governance, and security assurance.

## Phase 1: Production Core

**Target: 0-90 days**

Goal: make the current system credible for a controlled VASP pilot.

- [ ] Replace in-memory credential, proof, revocation, session, nonce, and rate-limit state with durable stores
- [ ] Use Postgres for tenant-scoped credentials, proofs, revocations, sanctions roots, nullifiers, and audit records
- [ ] Use Redis for SIWE nonces, sessions, rate limits, idempotency, and short-lived transfer workflow state
- [ ] Unify credential issuance and proof generation registries so issued credentials survive restart and can be proven reliably
- [ ] Implement tenant model: VASP organization, environments, API keys, users, roles, issuer roots, and allowed counterparties
- [ ] Harden auth: OIDC/JWT, API-key rotation, mTLS option, RBAC, tenant scoping, and admin audit events
- [ ] Mirror on-chain verification rules in `/proof/verify`: roots, expiry, domain binding, transfer binding, active VASP identity, revocation, nullifier, amount tier, jurisdiction, and stale root checks
- [ ] Implement envelope encryption: per-transfer DEK, beneficiary key wrapping, key IDs, rotation, decrypt audit, and explicit failure states
- [ ] Publish a pilot limitations and threat model document

Current progress:

- [x] API-key, JWT, and SIWE auth modes exist
- [x] Startup/runtime docs now show API-key mode correctly
- [ ] Durable tenant state remains the first production engineering milestone
- [ ] Off-chain verifier parity remains incomplete
- [ ] Counterparty key delivery for encrypted PII remains incomplete

Exit gate:

- [ ] A VASP can run issue -> prove -> verify -> send payload -> audit export in a clean environment without repo-specific manual steps

## Phase 2: Travel Rule Interoperability

**Target: 3-6 months**

Goal: make clearproof usable inside real Travel Rule workflows.

- [ ] Implement full TRP client/server flows, including request submission, response handling, error mapping, retries, and advanced workflow decisions
- [ ] Implement TRISA/GDS certificate lifecycle, mTLS, counterparty identity checks, secure envelope signing, and production config
- [ ] Validate IVMS101 payloads, required fields, schema versions, and jurisdiction-specific rule profiles
- [ ] Define public key profiles for discovery and protocols: age/X25519, RSA, mTLS certificates, rotation, and compatibility rules
- [ ] Add VASP discovery trust model: well-known metadata plus optional VASPRegistry verification
- [ ] Add compliance operator UI for transfers, proof status, counterparty reachability, PII encryption/decryption status, root versions, and SAR-review flag
- [ ] Add webhook and event stream integrations for VASP back offices
- [ ] Add regulator/compliance exports: CSV, JSON, signed audit bundles, and evidence packages
- [ ] Provide a hosted sandbox with seeded VASPs, deterministic proofs, and simulated counterparties

Current progress:

- [x] TRP/TRISA bridge models exist
- [x] Integration tests cover current bridge structures
- [ ] Full TRP request/response transport remains incomplete
- [ ] TRISA GDS, mTLS certificate lifecycle, and production signing remain incomplete

Exit gate:

- [ ] Complete one bilateral pilot or simulator run over TRP or TRISA-compatible messaging

## Phase 3: Security And Assurance

**Target: 6-9 months**

Goal: make the platform defensible to security, legal, and compliance teams.

- [ ] External audit of circuits, contracts, API auth, encryption, key handling, and protocol bridges
- [ ] Production trusted setup or documented MPC ceremony for circuit artifacts
- [ ] Signed build pipeline for circuits, verification keys, contracts, sanctions trees, and root updates
- [ ] WORM-style append-only audit log with tamper evidence, retention controls, export, and external anchoring
- [ ] HSM/KMS support for platform keys, tenant keys, signing keys, and oracle operator keys
- [ ] Sanctions feed provenance: source manifests, signatures, freshness SLAs, stale-data fail-closed behavior, dual-control root publishing
- [ ] Incident response runbooks: sanctions-feed failure, root rollback, key compromise, false positive/negative, counterparty outage, and PII decrypt failure
- [ ] SAR anti-tipping-off safeguards in logs, UI, exports, and webhooks

Current progress:

- [x] Circuit signal specification and trusted setup notes exist
- [x] Security docs identify production key and HKDF requirements
- [ ] External audit has not started
- [ ] Production trusted setup has not started
- [ ] WORM audit log and HSM/KMS support have not started

Exit gate:

- [ ] Audit complete, major findings closed, residual risks documented and accepted

## Phase 4: Managed Platform GA

**Target: 9-12 months**

Goal: sell clearproof as managed compliance infrastructure.

- [ ] Tenant admin console: orgs, users, roles, environments, API keys, webhooks, usage, and audit trails
- [ ] Managed root/oracle service with uptime SLA, root freshness SLA, and status page
- [ ] Production monitoring: proof latency, verification failures, stale roots, decrypt failures, counterparty failures, queue depth, and error budgets
- [ ] Billing and packaging: sandbox, pilot, enterprise managed, self-hosted enterprise
- [ ] Legal/compliance package: DPA, retention policy, subprocessor list, SOC 2 roadmap, security whitepaper, and jurisdictional compliance matrix
- [ ] Customer onboarding playbooks for exchanges, custodians, stablecoin issuers, and crypto payment processors
- [ ] Partner motion with TRP/TRISA vendors, blockchain analytics providers, custody vendors, and compliance consultancies

Current progress:

- [ ] Managed platform work has not started
- [ ] Customer onboarding, billing, and SLA materials have not started
- [ ] Platform operations model has not started

Exit gate:

- [ ] Two paid pilots or production customers handling live or shadow-mode transaction flows

## Phase 5: Platform Expansion

**Target: 12-18 months**

Goal: move from product to ecosystem layer.

- [ ] Multi-jurisdiction policy engine with rule versioning and explainable decisions
- [ ] Sanctions and blockchain analytics provider integrations
- [ ] Counterparty reachability, reputation, and protocol compatibility scoring
- [ ] Self-hosted enterprise distribution with managed control plane
- [ ] Multi-chain proof recording beyond initial EVM deployments
- [ ] Governance model for issuers, roots, revocations, protocol extensions, and emergency halts

Current progress:

- [ ] Expansion work is intentionally deferred until production core and interop are validated with pilots

## Chain And Oracle Track

The previous roadmap focused on chain support and sanctions root propagation. Those items remain useful, but they are not the primary blocker to production platform quality.

### Implemented

- [x] Network config for 10 EVM chains: 5 testnets and 5 mainnets
- [x] `SanctionsRootRelay` adapter contract separating transport from oracle
- [x] Multi-chain deploy script
- [x] Multi-chain relayer script
- [x] GitHub Actions workflow for automated relay
- [x] Deterministic sanctions tree construction
- [x] Canonical address normalization
- [x] Poseidon domain tag 1 for leaf hashing
- [x] Source manifest with SHA-256 hashes of source files
- [x] Versioned build script with published hash
- [x] Test vectors for independent verification
- [x] `--verify` mode to validate existing tree against test vectors
- [x] `VASPRegistry` discovery endpoint field
- [x] `/.well-known/clearproof.json` specification
- [x] SDK well-known discovery resolver with caching
- [x] On-chain proof submission and transfer check scripts for walkthroughs

### Planned

- [ ] Registry-backed verification for discovery metadata
- [ ] `verifyAndRecordBatch()` with soft failures
- [ ] Per-proof batch events for success/failure tracking
- [ ] Batch size cap to stay within block gas limits
- [ ] Evaluate LayerZero v2 and Chainlink CCIP for root propagation
- [ ] Deploy bridge contracts on canonical chain
- [ ] Automated root fan-out to destination chains
- [ ] Multi-operator root attestation with N-of-M threshold
- [ ] Disagreement alerting and halt mechanism
- [ ] Non-EVM support for Solana and Stellar when customer demand justifies it

Protocol fee decision:

- [x] No protocol-level verification fee in `ComplianceRegistry`
- [ ] Cover operating costs through managed platform subscriptions, enterprise support, onboarding, and SLA-backed services

Supported EVM networks:

| Testnet | Mainnet |
| --- | --- |
| Sepolia | Ethereum |
| Base Sepolia | Base |
| Arbitrum Sepolia | Arbitrum |
| Polygon Amoy | Polygon |
| Optimism Sepolia | Optimism |

## Business Readiness Track

- [ ] Define ICP: mid-market exchanges, custodians, stablecoin issuers, and crypto payment processors with existing compliance teams
- [ ] Define buyer: Chief Compliance Officer, Head of Financial Crime, Head of Product Compliance, or regulated crypto infrastructure lead
- [ ] Package value proposition: "prove compliance and exchange Travel Rule data with less PII exposure while interoperating with existing VASP rails"
- [ ] Define pricing: managed platform subscription, volume tiers, enterprise self-hosted license, onboarding, SLA, and compliance support
- [ ] Define liability boundaries for sanctions freshness, false negatives, PII decrypt failures, counterparty non-delivery, and audit evidence retention
- [ ] Create design partner criteria and pilot success metrics

## Production Blockers

These must be closed before clearproof is marketed as production compliance software:

- [ ] Durable credential/proof/audit state
- [ ] Counterparty key delivery and decryptability for encrypted PII
- [ ] Off-chain verifier parity with on-chain registry checks
- [ ] Persistent append-only audit log
- [ ] Production auth, RBAC, tenant isolation, and key rotation
- [ ] Signed sanctions provenance and stale-root fail-closed behavior
- [ ] Real TRP/TRISA transport, identity, signing, and certificate lifecycle
- [ ] Circuit audit and production trusted setup
- [ ] Operational runbooks and compliance export evidence
- [ ] Clear governance for issuers, oracle operators, roots, revocations, and emergency halts

## Adding A New EVM Chain

To add a new EVM chain:

1. Add the network to `packages/contracts/scripts/networks.ts`
2. Add the network to `packages/contracts/hardhat.config.ts`
3. Add RPC URL env var to `.env.example`
4. Deploy: `make deploy NETWORK=<name>`
5. Add the chain to `RELAY_NETWORKS` in GitHub Actions variables
6. Verify contracts on the block explorer
