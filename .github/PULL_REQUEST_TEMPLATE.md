## Summary

<!-- What does this PR change and why? Link issues (Fixes #123). -->

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Circuit change (requires the circuit checklist below)
- [ ] Contract change (requires the contract checklist below)
- [ ] Docs / chore / CI

## Compliance guardrails (must all be true)

- [ ] No raw PII is logged or stored outside the encrypted envelope
- [ ] No ENS-name resolution added to sanctions paths (raw hex addresses only)
- [ ] Generated protobuf stubs (`*_pb2*.py`) were not hand-edited — changes go through `scripts/regen_protobufs.sh`
- [ ] Sanctions oracle relay implications considered if sanctions roots/tree changed

## Testing

- [ ] `uv run pytest tests/` passes (or affected subset)
- [ ] `npm run test:ts` / `npx hardhat test` passes for TS/contract changes
- [ ] New behavior is covered by tests (valid **and** invalid inputs for circuits)

## Circuit changes only

- [ ] Range checks on all arithmetic; soundness argument included in PR description
- [ ] Constraint counts before/after included
- [ ] Python model (`src/protocol/compliance_proof.py`) kept in sync

## Contract changes only

- [ ] Hardhat tests added; gas impact noted
- [ ] Deploy/relay script impact assessed (`packages/contracts/scripts/`)

## Changelog & DCO

- [ ] `CHANGELOG.md` updated under `[Unreleased]` for user-visible changes
- [ ] All commits signed off (`git commit -s`) per the DCO in `CONTRIBUTING.md`
