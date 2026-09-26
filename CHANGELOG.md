# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Packages under `packages/` version together with the repository until 1.0.0;
after 1.0.0 each published package (`@clearproof/*`, `clearproof` on PyPI)
maintains its own version line in this file.

## [Unreleased]

## [0.6.0] - 2026-09-26

All five packages are published at 0.6.0 through npm trusted publishing with signed provenance, including `@clearproof/circuits` for the first time since 0.3.0. Pre-production: nothing is independently audited, and keys remain development-only.

### Changed

- **`@clearproof/circuits` is now a source-only package (0.6.0).** It publishes the canonical `circuits/` sources for both the current `pilot-transfer-v3` profile and the legacy demo circuit. They are copied at publish time with `circomlib` includes rewritten to `circomlib/...` (compile with `-l node_modules`), plus a `MANIFEST.json` of repository and package SHA-256 hashes. `circomlib` (GPL-3.0) is a peer dependency. **Breaking:** no compiled WASM, proving keys or verification keys, and the API changes to `dir`, `pilot`, `legacy` and `includePath`. The previous package held a stale legacy-only copy of the sources and development artifacts.

### Fixed

- **`clearproof demo` no longer resolves the artifacts in `@clearproof/circuits` 0.3.0.** Those were compiled before the sanctions-leaf hashing fix and fail witness generation with the current demo input (`MerkleTreeVerifier` assertion), so `demo` from the published 0.5.0 CLI fails. The CLI no longer depends on `@clearproof/circuits`: generate matching development artifacts with `scripts/test_development_circuits.py` and pass `--artifacts <output>/legacy`. The existing error message explains this.

### Added

- **Issue reporting for people and AI agents.** `clearproof report` prints a pre-filled GitHub issue link with the CLI version, Node version and platform (`--json` for scripts and agents, `--doctor <file>` adds a whitelisted summary of a saved `clearproof doctor` result); nothing is sent. New docs page "Report an issue", a footer link, a README section, and an `AGENTS.md` section on what agents should include and never include. Issue forms gain a "Reported by" field.
- **Private vulnerability reporting** is enabled on GitHub and is now the preferred channel in `SECURITY.md`; email remains an alternative. GitHub Discussions is enabled, so the issue chooser's discussions link works.

## [0.5.0] - 2026-09-26

First npm release since 0.3.0. It publishes `@clearproof/proof`, `@clearproof/content`, `@clearproof/cli` and `@clearproof/contracts` at 0.5.0; `@clearproof/circuits` stays at 0.3.0. Version 0.4.0 was tagged on GitHub in July but never published to npm. All proving keys remain development-only, and nothing in this release has been independently audited.

### Release

- **npm packages now match the source pilot.** 0.5.0 includes the adoption pilot (merged in PR #27) and the `pilot-transfer-v3` proof profile, which 0.3.0 predates.
- **`@clearproof/content` is published** for the first time, so `@clearproof/cli` installs from npm. The CLI now depends on `@clearproof/proof` and `@clearproof/content` `^0.5.0` instead of `*`; the `circuits` dependency (legacy demo artifacts) resolves to the published 0.3.0.
- **Release workflow:** publishes through npm trusted publishing (OIDC) instead of a stored token, following npm's deprecation of 2FA-bypass publish tokens; provenance attestations are generated automatically. It uses Node 24 with npm 11.9.0 and a locked install, builds only the published packages, compiles the contracts, publishes content → proof → CLI → contracts, and skips versions already on npm so a partial release can be re-run. The PyPI job is disabled until a PyPI trusted publisher is configured (`PUBLISH_PYPI=true`).

### Changed

- **Proof profile `pilot-transfer-v3`: production tree depths** ([ADR 0011](docs/adr/0011-production-tree-depths.md)). The composed pilot circuit changes from `PilotCompliance(8, 8, 8)` to `PilotCompliance(32, 20, 20)`:
  - Capacity is now 2^32 credentials per issuance root, 2^20 authorized-issuer leaves and 2^20 − 2 sanctioned EVM addresses. Previously each tree held 256 leaves (254 addresses).
  - Public signals are unchanged. Keys change, so `pilot-transfer-v2` becomes a historical profile: current artifact/context checks reject it, and pinned read-only pairing can still inspect it.
  - Depths are defined once in `src/registry/pilot_tree.py`. Signed root snapshots must carry the exact depth for their kind. The registrar takes separate `issuance_depth`/`issuer_depth`, and `PilotTree` no longer caps entries at 256.
  - Circuit size grows from 51,728 to 95,408 constraints, so development setup uses `2^17` powers of tau. CI now uses the SHA-256-pinned PSE `ppot_0080_17.ptau` via `--prepared-ptau` instead of generating a single-party phase 1. Keys remain development-only.
  - **Regenerate development artifacts after upgrading.**

### Documentation

- Add a public adoption roadmap and publication boundaries; retain evaluation and usage semantics in operational docs while removing internal commercial preparation from the current public tree.

### Added

- **Native Python Poseidon** (`src/registry/poseidon.py`): pure-Python Poseidon over BN254 implementing the standard reference permutation. Round constants and MDS matrices (`src/registry/poseidon_constants.json`) are generated **clean-room** by `scripts/generate_poseidon_constants.py` (Apache-2.0) from the public Grain-LFSR parameter algorithm in the Poseidon paper (eprint 2019/458) — nothing is vendored from circomlibjs, preserving the repo's no-GPL posture (ADR 0001). Replaces the Node.js subprocess bridge (`scripts/poseidon_hash.js`) in `sanctions_list.py`, `issuer_registry.py`, `credential_registry.py`, and `scripts/build_sanctions_tree.py` — the API and tree builder no longer require a Node.js runtime at deploy time. Parity with circomlibjs (and therefore the in-circuit `Poseidon(n)` template) is enforced by `tests/unit/test_poseidon.py` (hardcoded vectors, optional live parity check, and a constants-regeneration consistency test).
- **Circuit static analysis in CI**: new `circuit-lint` job runs Circomspect (Trail of Bits) over all circuits via `scripts/circuit_lint.sh`. Five known-intentional findings (contract-constrained domain signals, constant compliance outputs, cosmetic `valid` signals) are allowlisted with inline justification; any new finding fails the build.
- **HPKE v2 envelopes** (`src/sar/hpke_envelope.py`): RFC 9180 hybrid public-key encryption for counterparty PII payloads — DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/AES-256-GCM, base mode. First increment of the SOTA plan's critical item #1: per-recipient key isolation replaces the shared-master-key model (one VASP's key compromise no longer exposes every envelope). Envelope format is versioned (`v=2`) with explicit suite identifiers so PQ-hybrid suites (draft-ietf-hpke-pq, e.g. X-Wing) can land as v3 without a format break. Key fingerprinting (`kid`) supports rotation and decrypt-audit trails. API-route migration to v2 and beneficiary public-key discovery via the registry are follow-ups. New dependency: `pyhpke` (MIT).
- **HPKE v2 wired into the proof gateway**: `POST /proof/generate` accepts `beneficiary_hpke_public_key` (base64url X25519 key) or the `BENEFICIARY_HPKE_PUBLIC_KEY` env var; when present, PII is sealed as an HPKE v2 envelope (returned in `pii_envelope`, algorithm field `HPKE-X25519-HKDF-SHA256-AES-256-GCM`). Without a key, the route falls back to v1 shared-key AES-256-GCM with a deprecation warning in the logs. `HybridPayload` gains an optional `pii_envelope` field, surfaced in the TRP/TRISA serializations. Integration test proves the v1 path is bypassed and the envelope round-trips to the beneficiary's private key.
- **HPKE key discovery** (spec 0.3.0): `GET /.well-known/clearproof.json` (`src/api/routes/discovery.py`) publishes this VASP's HPKE public key (`VASP_HPKE_PRIVATE_KEY`/`VASP_HPKE_PUBLIC_KEY` env); `src/protocol/discovery.py` resolves counterparty keys from their well-known documents with a 1-hour cache. `/proof/generate` key precedence: request field → `BENEFICIARY_HPKE_PUBLIC_KEY` env → well-known discovery from `destination_vasp_did` (fail-open to v1 with warning during migration; `HPKE_DISCOVERY_ENABLED=0` disables). `scripts/hpke_keygen.py` generates operator keypairs. `specs/well-known-clearproof.md` bumped to 0.3.0 with `hpkePublicKey`/`hpkeKeyId`/`hpkeSuites` fields and a rotation policy.
- **BLS12-381 gas benchmark** (ADR 0002 Open Task 1, done): `scripts/generate_verifier_bls.mjs` renders an EIP-2537 Groth16 verifier (`packages/contracts/contracts/bench/Groth16VerifierBLS.sol`); measured on Prague EVM with real proofs — **BLS12-381 363,588 gas vs BN128 341,504 (+6.5%)**. Benchmark test `test/Groth16VerifierBLS.bench.ts` (valid proof verifies, tampered rejected, BN128 baseline). Dev artifacts in `tests/vectors/compliance-bls/` (single-party setup; regenerate inputs with `scripts/make_bls_input.py`). Finding: circomlib Poseidon constants are curve-bound — production BLS migration must regenerate curve-correct Poseidon parameters. Hardhat local network now targets the Prague hardfork.
- **BLS verifier Sepolia deploy script**: `packages/contracts/scripts/deploy-verifier-bls.ts` — deploys `Groth16VerifierBLS`, verifies the committed BLS12-381 vector on-chain (valid accepted, tampered rejected), reports gas, and records the deployment. Validated end-to-end on a local Prague EVM (363,588 verify gas, matching the benchmark). Operator runs `npx hardhat run scripts/deploy-verifier-bls.ts --network sepolia` to complete the last ADR 0002 gate.
- **EIP-2537 chain matrix** (ADR 0002 Open Task 2, done): `scripts/check_eip2537.mjs` probes the PAIRING precompile on all ten target networks — **every chain (ethereum, sepolia, base, arbitrum, optimism, polygon + testnets) has BLS12-381 precompiles live**, resolving the "uneven L2 availability" caveat and enabling single-curve deployment. Exits non-zero on regression for release gating.
- `docs/adr/0002-bls12381-migration.md` — decision record for migrating Groth16 from BN254 to BLS12-381 (EIP-2537 live since Pectra, 2025-05-07), with measured gas data (+6.5%), the full chain matrix, and the curve-bound-Poseidon caveat. Only the operator-gated Sepolia confirmation deploy remains before DECIDED.
- `docs/internal/SOTA_PLAN_2026.md` — state-of-the-art alignment plan from the July 2026 ecosystem review.

### Fixed

- **Non-JSON-safe ciphertext in `/proof/generate` response**: `encrypted_pii` was returned as raw bytes, which 500s on real (non-UTF-8) ciphertext — previously masked by test mocks returning valid-UTF-8 fake ciphertext. Now base64-encoded.

### Removed

- **`MerkleNonMembership` template** (`circuits/lib/merkle_tree.circom`, `packages/circuits/src/lib/merkle_tree.circom`): dead code deprecated since v0.3.0 containing the pre-audit-fix vulnerabilities (free-input adjacency indices, unconstrained `LessThan` inputs). Superseded by `SanctionsNonMembership`; flagged by the new Circomspect gate. No compiled-circuit change (the template was never instantiated).

## [0.4.0] - 2026-07-20

### Added

- **Apache-2.0 Groth16 verifier (ADR 0001 Option B, resolved)**: `scripts/generate_verifier.mjs` renders `Groth16Verifier.sol` from any snarkjs verification key — an independent implementation on the MIT-licensed Pairing library (`packages/contracts/contracts/Pairing.sol`, Copyright 2017 Christian Reitwiessner, attribution in `NOTICE`). Replaces the GPL-3.0 snarkjs-generated verifier; **no GPL code remains in the repository**. Security checks implemented independently: ABI-level fixed-size public-signal array (count mismatches inexpressible) and canonical scalar-field range checks (revert on `>= r`). New Hardhat tests cover out-of-field revert and in-field tamper rejection.
- **Verifier parity (off-chain ≡ on-chain)**: committed test vector at `tests/vectors/compliance/` (input, proof, public signals, verification key, manifest). Verified off-chain via new `packages/proof/test/parity.test.ts` (snarkjs + tamper cases) and on-chain via `packages/contracts/test/Verifier.test.ts`, which now reads the committed vector instead of an ephemeral `/tmp` fixture — the on-chain proof test previously always skipped.
- `demo --export <dir>` CLI option writes the parity vector.
- `docs/internal/CEREMONY_RUNBOOK.md` — production MPC trusted-setup runbook: roles, contribution protocol, signed attestation template, finality beacon, abort conditions.
- `docs/adr/0001-groth16-verifier-licensing.md` — decision record for the GPL-3.0 snarkjs verifier (interim acceptance + pre-mainnet options).
- `specs/README.md` — specification lifecycle (draft/candidate/stable, SemVer, change process); spec front matter added to `well-known-clearproof.md`.
- CI: off-chain parity tests run in the TypeScript job; the circuits job now smoke-tests proof generation from a fresh build.
- `CHANGELOG.md` (this file) — Keep a Changelog format, SemVer policy.
- GitHub issue templates (bug report, feature request) and a pull request template.
- Developer Certificate of Origin (DCO) sign-off requirement documented in `CONTRIBUTING.md`.
- REUSE 3.3 licensing compliance: `REUSE.toml` bulk SPDX metadata, license texts in `LICENSES/`, and a `reuse lint` CI job.
- Protobuf supply-chain check: `scripts/regen_protobufs.sh` regenerates the gRPC stubs from `protos/` with a pinned `grpcio-tools` and documented post-processing; `make check-protobufs` and a CI job fail on drift. Generated stubs should no longer be hand-edited.
- "Assurance Status" section in `README.md` stating the current audit / trusted-setup posture.

### Fixed

- **Stale CLI demo input**: `DEMO_INPUT` predated the sanctions-leaf domain-hash fix (`28c9403`) and produced invalid witnesses (`MerkleTreeVerifier` assert failure) — the demo was broken against current circuits. Recomputed all Poseidon-derived values (domain-separated sanctions/issuer leaves, zero-subtree paths) against the current circuit.

### Changed

- ADR 0001 updated: Option D (upstream licensing clarification) completed without filing — iden3 affirmed the GPL-3 verifier template in snarkjs#138/#139 and declined relicensing in #199/#261; Option B amended with the recoverable MIT-licensed template ancestor (≤ snarkjs `577b3f3580`), then **resolved** via an independent Apache-2.0 implementation.
- `compile_circuits.sh` and CI now generate the Solidity verifier with `scripts/generate_verifier.mjs` instead of `snarkjs zkey export solidityverifier`.
- `compile_circuits.sh` now downloads the audited Hermez powers-of-tau (sha256-pinned, same as CI) instead of a local single-party ceremony by default; `CLEARPROOF_GENERATE_PTAU=1` restores local generation. Documents that snarkjs mixes OS randomness into contributions, so dev key sets are never byte-reproducible and `Groth16Verifier.sol` + `tests/vectors/` must be committed together.
- Release workflow: npm packages publish with `--provenance` (Sigstore attestations); added PyPI publish job using a trusted publisher (OIDC).

## [0.3.0] - 2026-05

### Added

- Durable storage layer (`src/storage/`): asyncpg/psycopg connection pools, migrations, hash-chained audit log (`StoredAuditEntry.compute_hash`).
- Multi-chain contract deployment and sanctions-root relay scripts (Hardhat).
- Production platform roadmap (`ROADMAP.md`) defining the production-readiness bar.
- Hierarchical `AGENTS.md` project knowledge base.

### Changed

- Storage tests skip cleanly when `DATABASE_URL` is unset.

[Unreleased]: https://github.com/repfigit/clearproof/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/repfigit/clearproof/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/repfigit/clearproof/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/repfigit/clearproof/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/repfigit/clearproof/releases/tag/v0.3.0
