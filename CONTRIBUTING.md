# Contributing to clearproof

Thank you for your interest in contributing to the clearproof compliance bridge. This guide will help you get started.

## Development Environment Setup

### Prerequisites

- **Python 3.11+** with [uv](https://docs.astral.sh/uv/) for package management
- **Node.js 20+** with npm
- **circom 2.2.2+** for circuit compilation

### Install Dependencies

```bash
# Python dependencies
uv sync --all-extras

# Node.js dependencies (workspaces: packages/proof, packages/cli, packages/contracts)
npm install

# Install circom (macOS)
brew install circom

# Install circom (Linux)
curl -L https://github.com/iden3/circom/releases/download/v2.2.2/circom-linux-amd64 -o /usr/local/bin/circom
chmod +x /usr/local/bin/circom
```

## Running Tests

### Python Tests

```bash
# All tests
uv run pytest tests/ -v

# Unit tests only
uv run pytest tests/unit/ -v

# Integration tests
uv run pytest tests/integration/ -v

# Compliance tests
uv run pytest tests/compliance/ -v

# Circuit-specific tests
uv run pytest tests/unit/test_circuits.py -v
```

### TypeScript / Hardhat Tests

```bash
# Type-check the proof SDK and CLI
cd packages/proof && npx tsc --noEmit
cd packages/cli && npx tsc --noEmit

# Run Hardhat contract tests (24 tests including E2E)
cd packages/contracts && npx hardhat test
```

### Circuit Compilation

```bash
# Full compile + trusted setup + verification key export
bash scripts/compile_circuits.sh

# Syntax check only (no trusted setup)
mkdir -p /tmp/circuit-build
circom circuits/compliance.circom --r1cs --sym -l node_modules -o /tmp/circuit-build
```

## Regenerating gRPC / Protobuf Stubs

The files `src/protocol/bridges/*_pb2.py` and `*_pb2_grpc.py` are generated from `protos/` and **must never be hand-edited**. Regenerate them with:

```bash
make regen-protobufs    # regenerate in place (pinned grpcio-tools)
make check-protobufs    # verify committed stubs match protos/ (runs in CI)
```

`scripts/regen_protobufs.sh` pins the generator version and applies the documented post-processing (package-relative imports, warn-only grpcio version guard). If `protos/*.proto` changes, commit the regenerated stubs in the same PR — CI fails on drift.

## Developer Certificate of Origin (DCO)

All contributions must be signed off with the [Developer Certificate of Origin](https://developercertificate.org/). This certifies that you wrote or have the right to submit the contribution under the project's Apache-2.0 license. Because this repository contains cryptographic compliance code, contribution provenance matters to downstream regulated users.

Sign off every commit:

```bash
git commit -s -m "feat: your change"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer. Use your real name and a reachable email. PRs without sign-offs on all commits will be asked to amend (`git rebase --signoff` + force-push).

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Branch naming**: Use descriptive names like `feat/add-range-check`, `fix/verifier-gas`, or `docs/update-readme`.
3. **Make your changes** with clear, atomic commits.
4. **Run all tests** before submitting (Python, TypeScript, Hardhat, circuit compilation).
5. **Open a Pull Request** against `main` with a clear description of what changed and why.
6. **Address review feedback** -- maintainers may request changes before merging.

### Agent-assisted development (repfigit-loop)

This repository uses the [repfigit-loop](https://github.com/repfigit/repfigit-loop) process for agent-assisted work:

- Work items live as Linear issues (AI Factory team) with explicit acceptance criteria (`AC-N`) and non-goals (`NG-N`). If it is not in the issue, it does not exist.
- Human applies the `agent-ready` label in Linear to release an issue to the builder.
- Builder opens PRs (one issue per PR). Automated review posts a verdict label: `loop-approved`, `loop-changes-requested`, or `needs-human-review`.
- **Only humans merge.** `loop-approved` is evidence for a human, not authorization. Agents never merge or enable auto-merge.

### PR Checklist

- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] TypeScript compiles without errors
- [ ] Circuit changes include constraint count analysis (current: ~31K constraints, 16 public signals)
- [ ] No secrets or private keys committed
- [ ] `CHANGELOG.md` updated under `[Unreleased]` for user-visible changes
- [ ] All commits signed off (`git commit -s`) per the DCO section above
- [ ] `make check-protobufs` passes if `protos/` or `src/protocol/bridges/` changed
- [ ] AGENTS.md files updated if you added/modified behavior in `src/`, `packages/contracts/`, `circuits/`, `packages/proof/`, `tests/`, or `scripts/` (see root AGENTS.md for hierarchy)

## Code Style

### Python

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
uv run ruff check .
uv run ruff format .
```

### TypeScript

TypeScript strict mode is enforced. Run the type checker:

```bash
npx tsc --noEmit
```

## Circuit Contribution Guidelines

Circuits are the most security-sensitive part of this project. Extra care is required:

### Requirements

- **Range checks**: All arithmetic operations must include range checks to prevent overflow/underflow in the finite field.
- **Soundness**: Every circuit must be sound -- it should be impossible to generate a valid proof for a false statement. Document your soundness argument.
- **Constraint efficiency**: Minimize the number of constraints. Include constraint counts in your PR description.
- **Signal naming**: Use descriptive signal names. Inputs should be clearly documented.

### Testing Circuits

- Write Python tests in `tests/unit/` that exercise the circuit with both valid and invalid inputs.
- Verify that invalid inputs are properly rejected (the prover should fail).
- Test edge cases: zero values, maximum values, boundary conditions.

### Audit Reference

Before modifying circuits, review the circuit audit document in `specs/` for context on design decisions and known considerations.

## Good First Issues

Look for issues labeled [`good first issue`](../../labels/good%20first%20issue) for tasks that are well-scoped and beginner-friendly. Common entry points:

- **Documentation improvements**: Clarify setup instructions, add examples.
- **Test coverage**: Add edge-case tests for existing functionality.
- **TypeScript SDK ergonomics**: Improve error messages, add helper functions.
- **Gas optimization**: Profile and reduce gas usage in the on-chain verifier.

If you're unsure where to start, open a discussion or comment on an issue and a maintainer will help orient you.

## Questions?

Open a [GitHub Discussion](../../discussions) or reach out in the issue tracker.
