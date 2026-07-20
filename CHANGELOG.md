# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Packages under `packages/` version together with the repository until 1.0.0;
after 1.0.0 each published package (`@clearproof/*`, `clearproof` on PyPI)
maintains its own version line in this file.

## [Unreleased]

### Added

- `CHANGELOG.md` (this file) — Keep a Changelog format, SemVer policy.
- GitHub issue templates (bug report, feature request) and a pull request template.
- Developer Certificate of Origin (DCO) sign-off requirement documented in `CONTRIBUTING.md`.
- REUSE 3.3 licensing compliance: `REUSE.toml` bulk SPDX metadata, license texts in `LICENSES/`, and a `reuse lint` CI job.
- Protobuf supply-chain check: `scripts/regen_protobufs.sh` regenerates the gRPC stubs from `protos/` with a pinned `grpcio-tools` and documented post-processing; `make check-protobufs` and a CI job fail on drift. Generated stubs should no longer be hand-edited.
- "Assurance Status" section in `README.md` stating the current audit / trusted-setup posture.

### Changed

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
