# Builder context

## AIF-67 (PR #11) — 2026-07-28 — Fixed missing wallet_ownership_verified circuit input

- Architecture: Circuit inputs flow from TypeScript SDK (packages/proof/src/types.ts + prover.ts) → test vectors (tests/vectors/compliance/input.json) → demo CLI (packages/cli/src/commands/demo.ts). All three must stay in sync with circuits/*.circom signal declarations.
- Patterns: When adding a new circuit input, must update: (1) ComplianceInput type, (2) prover mapping, (3) test vector JSON, (4) demo CLI DEMO_INPUT. Credential commitment is Poseidon hash of 6 fields (issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at, wallet_ownership_verified). Nullifier = Poseidon(commitment, transfer_id_hash).
- Gotchas: Test vector credentialCommitment and credentialNullifier must be recomputed when any credential field changes. Use `echo '[inputs]' | node scripts/poseidon_hash.js` to compute. CLI test failure about missing artifacts is pre-existing (gitignored files) — not related to circuit input changes.

## AIF-79 — 2026-07-30 — Bound amount-tier thresholds to jurisdiction in all three verifiers

- Architecture: three verifier implementations must agree on any check over public signals — `ComplianceRegistry.verifyAndRecord` (Solidity), `verifyProof` (packages/proof/src/verifier.ts), `/proof/verify` (src/api/routes/proof.py). New canonical config lives at `config/jurisdiction_thresholds.json`; deploy.ts seeds the chain from it, and both test suites assert their copy matches in both directions.
- Patterns: `jurisdiction_code` is big-endian ASCII of the alpha-2 code ("US" = 0x5553), so it always fits uint16 and 0 is a safe default-sentinel key. Several public inputs are unconstrained in-circuit (thresholds, domain_*) — security lives in the verifier, now documented in the CIRCUIT_SIGNALS.md constraint-provenance table.
- Gotchas: Groth16Verifier reverts `PublicSignalExceedsScalarField` on any signal >= BN254 r, so Hardhat fixtures must reduce keccak roots mod r; Pairing.sol reverts with a *string* ("Pairing: ecpairing failed") not a custom error, so a positive control should assert `.to.not.be.revertedWithCustomError(...)` rather than expecting ProofVerificationFailed. The committed parity vector claims US but carries 100x thresholds — it is cryptographically valid and policy-invalid (AIF-89).
- Preflight: `.repfigit-loop/` is untracked and not gitignored, so `git status --porcelain` is never empty — preflight's clean-tree rule trips on every pass until that is fixed.

## AIF-79 repair (PR #17) — 2026-07-30 — Fixed CI smoke test by using getThresholds() in demo

- Architecture: CLI demo (packages/cli/src/commands/demo.ts) is the smoke test entry point. It must use the same threshold accessor as the verifiers, or the proof will fail verification when thresholds don't match jurisdiction.
- Patterns: When jurisdiction thresholds change, the demo must call `getThresholds(jurisdiction)` instead of hardcoding values. The actualAmount must be in the same scale as the thresholds (USD, not cents).
- Gotchas: The demo test failure about missing artifacts is pre-existing (artifacts not compiled locally) — not related to threshold changes. CI compiles artifacts before running the smoke test.

## Retry log

- AIF-67 — 2026-07-28 — status: escalated — stuck after 3 repair cycles; NG-1 backward-compat conflict + ADR 0002 staging question require product decision
- AIF-86 — 2026-07-31 — fflonk benchmark: 32% cheaper verification, no ceremony, 20x slower proving
- AIF-122 — 2026-08-05 — status: failed — Linear API unreachable, cannot claim issue
- AIF-122 — 2026-08-05 — status: failed — wrong-repo (string-utils doesn't exist in clearproof); gate script error; missing AGENT_IDENTITY