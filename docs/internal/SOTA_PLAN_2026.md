# State-of-the-Art Alignment Plan

**Date:** 2026-07-23
**Basis:** Codebase audit at v0.4.0 (`e12ca9a`) + live ecosystem research (Firecrawl, July 2026)
**Sources:** Base engineering ZK benchmarks, thirdweb 2026 ZK gas guide, EIP-2537/Pectra mainnet status, EU TFR (Reg. 2023/1113) guidance, FATF 7th Targeted Update (2025), RFC 9180 + draft-ietf-hpke-pq, TRISA↔TRP interop announcement, FATF R.16 2025 revisions

---

## Verdict Summary

The core architecture (Groth16 on BN254, sorted-Merkle gap proofs, domain-bound on-chain verification, hybrid proof+encrypted-PII payloads, TRP+TRISA+TAIP bridge strategy) is validated as current best practice by 2026 sources. No direct production competitor surfaced. The gaps are: PII key management, curve security headroom, circuit tooling, EU self-hosted wallet flows, and missing post-quantum planning.

## Priorities at a Glance

| # | Item | Type | Effort | Impact |
|---|------|------|--------|--------|
| 1 | HPKE key-exchange redesign (replace single PII_MASTER_KEY) | Security | L | Critical |
| 2 | BLS12-381 migration ADR (EIP-2537 live since 2025-05-07) | Security | S | High |
| ~~3~~ | ~~Circomspect in CI~~ **DONE 2026-07-23** (`scripts/circuit_lint.sh` + `circuit-lint` CI job; also removed deprecated vulnerable `MerkleNonMembership` template) | Tooling | S | High |
| 4 | Noir port pilot (ceremony-vs-gas tradeoff data) | Strategy | M | High |
| 5 | EU self-hosted wallet ownership verification | Compliance | M | High |
| 6 | Post-quantum exposure document | Compliance | S | Medium |
| 7 | FATF 2025 supervision best-practices alignment review | Compliance | S | Medium |
| 8 | GDPR/ZKP positioning in docs + content package | GTM | S | Medium |
| ~~9~~ | ~~Native Poseidon for Python~~ **DONE 2026-07-23** (`src/registry/poseidon.py` + clean-room constants generator; no GPL vendoring, no Node runtime dep) | Ops | S | Low |
| 10 | Custom errors in Solidity | Hygiene | XS | Low |

---

## Phase 1 — Security Hardening (0–30 days)

### 1. HPKE key-exchange redesign — CRITICAL — **IN PROGRESS (core primitive done 2026-07-23)**
**Problem:** Single `PII_MASTER_KEY` decrypts every envelope ever sent. One compromise = total PII exposure. This is the weakest link in the system.
**Research basis:** RFC 9180 (HPKE) is the industry standard; `draft-ietf-hpke-pq` adds ML-KEM suites incl. X-Wing (X25519+ML-KEM-768) hybrid; Go stdlib adding `crypto/hpke`.
**Actions:**
- [x] HPKE envelope primitive (`src/sar/hpke_envelope.py`): base mode `DHKEM(X25519, HKDF-SHA256)` + AES-256-GCM; versioned v2 format with suite IDs; `kid` fingerprints; AAD envelope binding; 13 unit tests incl. key isolation + tamper cases. (Authenticated mode deferred until VASP signing keys are standardized.)
- [ ] Beneficiary VASP publishes HPKE public key(s) via VASPRegistry or DID document; key IDs on envelopes
- [ ] Key rotation schedule + decrypt audit trail (already in ROADMAP production definition)
- [x] API routes emit v2 envelopes when a beneficiary key is available (request field `beneficiary_hpke_public_key` or `BENEFICIARY_HPKE_PUBLIC_KEY` env); v1 fallback retained with deprecation warning during migration (done 2026-07-23; also fixed masked non-JSON-safe ciphertext bug)
- [ ] Evaluate X-Wing (PQ-hybrid) suite for archival-grade envelopes; document decision
- [ ] Migration path: encrypt v2 only after cutoff; retire v1 keyring for new envelopes
**Done when:** Two clearproof instances exchange envelopes with no shared secret; envelope format versioned; rotation drill documented.

### 2. BLS12-381 migration ADR — **DRAFTED 2026-07-23** (`docs/adr/0002-bls12381-migration.md`)
**Problem:** BN254 offers ~100-bit security. Regulated buyers will ask. EIP-2537 precompiles are live on mainnet since Pectra (2025-05-07) — the migration path exists today, not "someday."
**Research basis:** Pectra activated epoch 364032; a pairing-precompile consensus bug (infinity-point handling) was found in the Pectra audit competition — pin client versions. L2 precompile availability is uneven.
**Actions:**
- [x] Write ADR 0002 — recommends Option B (BLS12-381 on L1 at the single production ceremony, BN254 retained for L2 pilots)
- [x] Gas benchmark (done 2026-07-23, Prague EVM): **BLS12-381 363,588 vs BN128 341,504 gas = +6.5%** — well inside tolerance. Bonus finding: circomlib Poseidon constants are curve-bound (opt algorithm, BN254-derived constants); production BLS migration must regenerate curve-correct Poseidon parameters.
- [x] Chain matrix (done 2026-07-24): `scripts/check_eip2537.mjs` — **all 10 target networks have EIP-2537** (incl. base, arbitrum, optimism, polygon). Single-curve deployment viable everywhere; recommendation upgraded from "L1-only" to "all chains". Remaining: operator-gated Sepolia confirmation deploy (needs `DEPLOYER_PRIVATE_KEY`)
- [ ] Survey target-chain precompile availability matrix (L1, Arbitrum, Base, OP, Polygon) (ADR Open Task 2)
- [ ] If migrating: fold into the production MPC ceremony (one ceremony, new curve) — do NOT run two ceremonies
**Done when:** ADR merged with gas data and chain matrix; decision recorded before ceremony planning starts.

### 3. Circuit static analysis in CI
**Problem:** Circuit has had manual adversarial review (audit fixes #1–#8 inline) but no automated analysis. Under-constrained-circuit bugs are the #1 ZK vulnerability class.
**Research basis:** Circomspect (Trail of Bits) is the standard linter; Ecne/Picus for verification. zkSecurity's pitfalls series covers the exact bug classes already fixed manually.
**Actions:**
- [ ] Add Circomspect to CI, fail on new warnings (baseline existing ones with justification comments)
- [ ] Evaluate Ecne or Picus for the constraint-coverage check on `compliance.circom`
- [ ] Add circuit lint results to the assurance section of README
**Done when:** CI gate green; every inline "audit fix" comment cross-referenced to a tool rule or a documented manual check.

---

## Phase 2 — Strategic Evaluation (30–60 days)

### 4. Noir port pilot — get real data
**Problem:** Per-circuit MPC ceremony is the #1 stated production blocker. Noir/UltraHonk eliminates it (universal setup) but Base's benchmarks show 6–7x on-chain gas (~2.4M vs ~348k) and its 5–50x proving speed advantage came from non-native-field blackboxes irrelevant to our Poseidon-native circuit.
**Key insight:** Our ADR already states verification happens off-chain in the hot path — so on-chain gas may not be the binding constraint. This is a genuine judgment call; settle it with data, not vibes.
**Actions:**
- [ ] Port `compliance.circom` to Noir (small circuit; est. 2–4 days)
- [ ] Measure: proving time (client-class hardware), proof size, on-chain verify gas, off-chain verify time
- [ ] Compare against current Groth16 numbers from `scripts/` benchmark
- [ ] Decision matrix: ceremony burden vs gas vs tooling maturity vs auditor availability
- [ ] If Noir wins: migration becomes Phase 3 work; if not, ADR records why Groth16 stays
**Done when:** Benchmark report in `docs/internal/`; go/no-go ADR.

### 5. EU self-hosted wallet ownership verification
**Problem:** EU TFR requires CASPs to verify ownership/control of self-hosted wallets for transfers ≥ €1,000 (in force since 2024-12-30). clearproof has no flow for this — a hard gap for the EU market, an anchor jurisdiction in the ROADMAP.
**Research basis:** Reg. 2023/1113 + EBA Travel Rule Guidelines; ownership proof is signature/challenge-based, not ZK — but the proof can be attested inside the compliance envelope.
**Actions:**
- [ ] Add wallet-ownership proof flow: EIP-191/EIP-712 signature challenge over `(wallet, vasp_did, timestamp, nonce)`
- [ ] Store attestation in credential model; add `wallet_ownership_verified` flag to credential preimage (circuit change — coordinate with #2/#4 timing to avoid double ceremony)
- [ ] Map EBA risk-based assessment requirements into SAR review flags (advisory)
**Done when:** EU pilot flow demonstrable end-to-end; circuit change batched with any curve/proof-system migration.

### 6. Post-quantum exposure document
**Problem:** Compliance archives have 10+ year horizons. BN254 proofs, X25519 HPKE, and (store-now-decrypt-later) AES-256-GCM envelopes each have different PQ exposure. Nothing in the repo addresses this.
**Research basis:** 2026 decision frameworks (thirdweb guide) now treat PQ horizon as step one of proof-system selection; Plonky3 ecosystem is PQ-safe.
**Actions:**
- [ ] One-page threat model: what breaks, when, and at what attacker cost (proof forgery vs envelope decryption)
- [ ] Record migration triggers (curve precompile availability, HPKE-PQ finalization, NIST timelines)
- [ ] Note: proofs attest to *past* compliance — forgery risk is forward-looking; PII envelopes are the store-now-decrypt-later exposure
**Done when:** `docs/internal/PQ_EXPOSURE.md` merged; referenced from SECURITY.md.

---

## Phase 3 — Compliance & Positioning (60–90 days)

### 7. FATF 2025 alignment review
**Research basis:** 7th Targeted Update — 93% of surveyed jurisdictions have Travel Rule laws; gap is now supervision/enforcement. FATF published Best Practices on Travel Rule Supervision. R.16 2025 revisions extend the rule to all "payments or value transfers and related messages."
**Actions:**
- [ ] Read FATF Travel Rule Supervision best-practices doc; gap-check clearproof's evidence outputs (what a supervisor would ask for) against what `src/storage/audit.py` + on-chain records produce
- [ ] Assess R.16 2025 revision impact on bridge message formats (TRP/TRISA/TAIP payload fields)
- [ ] Update ROADMAP regulatory anchors with 2025 revision citation
**Done when:** Supervisor-evidence checklist exists; any audit-trail gaps ticketed.

### 8. GDPR/ZKP positioning
**Research basis:** EU TFR mandates GDPR-compliant data transmission; active policy conversation (INATBA 2025 ZKP-GDPR paper, a16z privacy-preserving regulatory frameworks paper) describes exactly clearproof's architecture. No production competitor surfaced in research.
**Actions:**
- [ ] Add "GDPR data-minimization by design" section to docs site + `packages/content/`
- [ ] Position hybrid payload as the concrete answer to the TFR↔GDPR tension (proof attests, minimal encrypted data travels, counterparty decrypts only when legally required)
- [ ] Reference INATBA/a16z framings in compliance-facing material
**Done when:** Docs page live; content package updated.

---

## Phase 4 — Hygiene (opportunistic)

- [ ] **Native Poseidon for Python** — remove the runtime Node dependency (`src/registry/sanctions_list.py` shells out to circomlibjs; caused a test failure on a fresh machine). Use a Python Poseidon binding or vendor a pure-Python implementation with test vectors against circomlibjs.
- [ ] **Custom errors in Solidity** — replace `require(..., "string")` with custom errors; gas savings + current idiom.
- [ ] **Hardhat 3 migration** — already tracked in `docs/internal/hardhat3-migration.md`; schedule it.
- [ ] **Document or drop `ezkl`** — optional zkML dep pulls torch into every `--all-extras` install with no documented use.

## Sequencing Constraints

1. **Batch circuit changes.** Items #2 (curve), #4 (proof system), and #5 (credential preimage change) all invalidate the trusted setup. Decide all three BEFORE the production MPC ceremony — one ceremony, not three.
2. **HPKE (#1) is independent** of circuit work and is the highest-severity item — start immediately.
3. **Interop runs** (ROADMAP Phase 1) should wait for HPKE v2 envelopes to avoid baking legacy encryption into bilateral pilot agreements.

## What We Are NOT Doing (and why)

- **Not migrating to STARKs/Plonky3** — on-chain verification cost (2.5M+ gas) is prohibitive for per-transfer proofs; revisit only if aggregation becomes the primary on-chain path.
- **Not building proof aggregation yet** — pilot volume doesn't justify recursion engineering; add when on-chain verification exceeds ~1k proofs/day.
- **Not replacing Circom preemptively** — the Noir pilot (#4) decides this with measurements.
