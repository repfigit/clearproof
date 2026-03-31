# Contributing to ZK Travel Rule

Thank you for your interest in contributing to the ZK Travel Rule compliance bridge. This guide will help you get started.

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

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Branch naming**: Use descriptive names like `feat/add-range-check`, `fix/verifier-gas`, or `docs/update-readme`.
3. **Make your changes** with clear, atomic commits.
4. **Run all tests** before submitting (Python, TypeScript, Hardhat, circuit compilation).
5. **Open a Pull Request** against `main` with a clear description of what changed and why.
6. **Address review feedback** -- maintainers may request changes before merging.

### PR Checklist

- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] TypeScript compiles without errors
- [ ] Circuit changes include constraint count analysis (current: ~31K constraints, 16 public signals)
- [ ] No secrets or private keys committed

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
