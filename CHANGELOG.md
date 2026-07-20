# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Packages under `packages/` version together with the repository until 1.0.0;
after 1.0.0 each published package (`@clearproof/*`, `clearproof` on PyPI)
maintains its own version line in this file.

## [Unreleased]

### Added

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

- ADR 0001 updated: Option D (upstream licensing clarification) completed without filing — iden3 affirmed the GPL-3 verifier template in snarkjs#138/#139 and declined relicensing in #199/#261; Option B amended with the recoverable MIT-licensed template ancestor (≤ snarkjs `577b3f3580`).
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

[Unreleased]: https://github.com/repfigit/clearproof/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/repfigit/clearproof/releases/tag/v0.3.0
