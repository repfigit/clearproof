# CIRCUITS/ AGENTS.md

**Scope:** Circom circuits (Groth16/BN254). They are the cryptographic correctness root of Clearproof's transfer evidence.

## OVERVIEW

Two proof profiles live here. **Never select a profile by signal count.**

| Profile | Main circuit | Public signals | Status |
|---------|--------------|----------------|--------|
| `pilot-transfer-v3` | `pilot_compliance.circom` | 8 | **Current.** Spec: `specs/pilot-transfer-v3.md` (authoritative), ADRs 0009 and 0011 |
| `pilot-transfer-v2` / `v1` | same circuit, earlier depths/binding | 8 | Historical. Current checks reject them |
| Legacy | `compliance.circom` | 16 (14 in + 2 out) | Separate demo and parity path. Never current pilot authorization |

The current profile proves all of the following without revealing any of them publicly:
- The exact private transfer projection. Only a commitment is public.
- A valid, holder-bound credential issued under an authorized issuer.
- Sanctions non-membership for **both** the originator and beneficiary wallets.
- Exact valuation and a private tier.
- A single-use authorization nullifier and a bounded expiry.

Amount, tier, wallets, jurisdiction and participants stay private. There is no public amount-tier or SAR signal.

## STRUCTURE
```
circuits/
├── pilot_compliance.circom           # CURRENT main: PilotCompliance(32, 20, 20), 8 public signals
├── pilot_transfer.circom             # PilotTransferProjection: 48 private fields → commitment + authorization scope
├── pilot_credential.circom           # PilotCredentialValidity: credential, holder, issuance + authorized-issuer membership
├── pilot_sanctions.circom            # PilotSanctionsGap: raw-address gap non-membership
├── pilot_valuation.circom            # PilotValuation (exact 128-bit arithmetic), PilotAmountTier (private tier)
├── wallet_ownership_credential.circom # Staged extension only; no verifier accepts it (docs/internal/WALLET_OWNERSHIP.md)
├── compliance.circom                 # LEGACY main orchestrator (16 signals)
├── sanctions_nonmembership.circom    # Legacy gap proof (hashed keys)
├── credential_validity.circom        # Legacy credential + issuer + expiry checks
├── amount_tier.circom                # Legacy tier assignment + SAR flag
├── lib/
│   ├── merkle_tree.circom            # Poseidon MerkleProof / MerkleTreeVerifier (binary path indices)
│   └── poseidon_hasher.circom        # DomainPoseidon (legacy tags 0x01/0x02)
└── (compiled artifacts live outside the repo; see scripts/test_development_circuits.py)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Change the current public ABI | `pilot_compliance.circom` main + `src/prover/pilot_compliance.py` (`PUBLIC_SIGNALS`, `PROFILE`) + `PilotGroth16Verifier.sol` / `PilotCurrentRegistry.sol` + `packages/proof/src/authorization.ts` + `specs/pilot-transfer-v3.md` | Breaking change. It needs a new profile name, new keys and fixtures; never reuse v3 |
| Change a tree depth | `pilot_compliance.circom` main + `src/registry/pilot_tree.py` constants | Changes the keys, so it needs a new profile name (ADR 0011); check the constraint count against the ptau size (2^17) |
| Change projection fields | `pilot_transfer.circom` + `src/prover/pilot_projection.py` + `packages/proof` canonical code | ADR 0005; field table in `docs/internal/CIRCUIT_SIGNALS.md` |
| Change credential layout | `pilot_credential.circom` + `src/protocol/credential.py` + `src/prover/pilot_compliance.py` witness | ADR 0003/0009; commitment domain 102 |
| Change pilot sanctions logic | `pilot_sanctions.circom` + `src/prover/pilot_roots.py` / tree builder | Raw-address tree, leaf domain 301 (ADR 0006) |
| Change valuation/tier | `pilot_valuation.circom` + `src/prover/pilot_valuation.py` | ADR 0004 (valuation arithmetic) |
| Legacy changes | `compliance.circom` + `src/protocol/compliance_proof.py` | See LEGACY PROFILE below |

## CURRENT PROFILE: pilot-transfer-v3

`PilotCompliance(32, 20, 20)`: issuance depth 32, authorized-issuer depth 20, sanctions depth 20 (2^20 − 2 addresses), 95,408 constraints. See ADR 0011.

Public signals, in exact order (on-chain ABI):
1. `projection_commitment` — `Poseidon(204, transfer_projection_commitment, credential_commitment, issuance_root)`
2. `authorized_issuer_root`
3. `sanctions_root`
4. `authorization_nullifier` — `Poseidon(203, holder_secret, authorization_scope)`
5. `evaluated_at` — equals projection field 23
6. `proof_expires_at` — `evaluated_at < exp <= min(transfer expiry, credential expiry, evaluated_at + 300)`
7. `domain_chain_id` — equals projection field 26; **no link to a real chain in-circuit**
8. `domain_registry` — equals projection field 27; **no link to a real address in-circuit**

`PilotCurrentRegistry` checks signals 7 and 8 against `block.chainid` and `uint160(address(this))`. PostgreSQL, not the circuit or contract, consumes the nullifier. Per-signal enforcement is tabulated in `docs/internal/CIRCUIT_SIGNALS.md`.

Poseidon domain tags in use by the pilot circuits: 101 holder, 102 credential commitment, 103 issuer leaf, 202 authorization scope, 203 nullifier, 204 outer projection binding, 301 sanctions leaf, 111 wallet-ownership extension.

## SOUNDNESS PROPERTIES THAT MUST NOT REGRESS (pilot)

- **PilotSanctionsGap:**
  - The wallet is a raw 160-bit address (`Num2Bits(160)`). Keys are checked to 161 bits before `LessThan(161)`, and the right key must be `<= 2^160` (sentinel).
  - Adjacency is derived from path bits: `right_index === left_index + 1`.
  - It runs for **both** parties (projection fields 10 and 11).
- **PilotCredentialValidity:**
  - Range checks: 128-bit limbs, 160-bit wallet, 53-bit times, 2-bit tier, ASCII A–Z jurisdiction bytes.
  - Nonzero checks: wallet, nonce (jointly), tier, holder secret, holder commitment.
  - The issuer screening assertion (`fields[12]`) is constrained to 1.
  - `issued_at <= evaluated_at < expires_at`.
  - The commitment is a member of `issuance_root`. The issuer leaf binds `issuance_root` and is a member of `authorized_issuer_root`.
  - Expected tenant, subject and jurisdiction come from private projection fields, never from free inputs.
- **PilotValuation / PilotAmountTier:**
  - Exact limb multiplication with range-checked carries.
  - `remainder < denominator`.
  - Amount, numerator, denominator and USD cents are positive.
  - Thresholds are positive and strictly ordered. The tier is derived.
  - No SAR output.
- **PilotTransferProjection:**
  - All 48 fields are width-checked.
  - Time ordering: observation ≤ creation ≤ evaluation < transfer expiry ≤ quote expiry.
  - Age ≤ max age ≤ 86,400 s, and decimals ≤ 18.
  - Wallets, asset chain and contract, and deployment address are nonzero.
  - Asset chain == deployment chain.
  - Non-VASP parties carry no DID limbs.
- **The outer binding (signal 0) must include the exact credential commitment and issuance root.** This is the v1 → v2 credential-substitution fix (ADR 0009).

## LEGACY PROFILE: compliance.circom

Everything below documents the legacy 16-signal profile. It remains a demo/parity path. Its audit fixes still must not regress, but none of it describes the current pilot ABI.

### PUBLIC SIGNAL CONTRACT (legacy main circuit)

**Instantiation:** `ComplianceProof(20, 10)` — 20-level sanctions tree, 10-level issuer tree.

**Public Inputs (14, in exact order — this order is part of the on-chain ABI):**
1. `sanctions_tree_root` — current OFAC/UN/EU combined Merkle root
2. `issuer_tree_root` — trusted VASP issuer Merkle root
3. `amount_tier` — claimed tier (1–4)
4. `transfer_timestamp` — Unix timestamp of the transfer
5. `jurisdiction_code` — ISO 3166-1 alpha-2 as integer
6. `credential_commitment` — Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
7. `tier2_threshold` — jurisdiction-specific (USD cents)
8. `tier3_threshold`
9. `tier4_threshold`
10. `domain_chain_id` — EVM chain ID (enforced by verifier contract, not circuit)
11. `domain_contract_hash` — truncated keccak of ComplianceRegistry address
12. `transfer_id_hash` — keccak(transferId) — binds proof to one transfer
13. `credential_nullifier` — Poseidon(credential_commitment, transfer_id_hash) — one-time-use
14. `proof_expires_at` — Unix timestamp (must be > transfer_timestamp in-circuit)

**Public Outputs (2):**
- `is_compliant` — always 1 if circuit succeeds
- `sar_review_flag` — 1 if tier >= 3 (triggers human review)

**CRITICAL:** The Python `ComplianceProof.public_signals` list must emit these 16 values in this exact order. Changing the order without coordinated updates on both sides produces unverifiable proofs.

### SUB-CIRCUIT RESPONSIBILITIES (legacy)

**CredentialValidity(issuer_depth=10)**
- Verifies `Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at) == credential_commitment`
- `expires_at > transfer_timestamp` (in-circuit)
- Issuer is member of trusted tree
- Jurisdiction matches expected
- `sanctions_clear === 1` (explicit private input, not a constant — audit fix #5)
- `kyc_tier` and `jurisdiction_code` are range-checked before comparison (audit fixes #11, #13)

**SanctionsNonMembership(sanctions_depth=20)**
- "Gap proof": prover supplies two adjacent leaves such that `left_key < query_key < right_key`
- Adjacency is **derived** from Merkle path direction bits via `PathToIndex` (audit fix #1) — not a free input
- All keys range-checked to 252 bits before `LessThan` (audit fix #2) — prevents field wrapping attacks
- Leaf hash uses domain tag `0x01`

**AmountTier()**
- Thresholds (`tier2/3/4_threshold`) are **public inputs** supplied by verifier per jurisdiction (audit fix #3)
- Threshold ordering enforced: `tier2 < tier3 < tier4` (audit fix #9)
- All amounts and tier range-checked before comparators (audit fixes #10, #12)
- Outputs `sar_review_flag = (tier >= 3)`

### LIBS

**merkle_tree.circom**
- `MerkleProof(depth)` — generic Poseidon membership proof (used by both credential and sanctions)
- Non-membership lives in `sanctions_nonmembership.circom` (`SanctionsNonMembership`); the legacy `MerkleNonMembership` template was removed in v0.4.x (deprecated since v0.3.0 — free-input adjacency, no range checks)
- Path indices are constrained to binary; ordering uses `MultiMux1`

**poseidon_hasher.circom**
- `PoseidonHasher(n)` — raw Poseidon
- `DomainPoseidon(n)` — prepends domain tag
- Domain tags in use: `0x01` (sanctions leaf), `0x02` (issuer leaf), `0x03` reserved for future credential commitment variant

### CONVENTIONS (legacy)

- **"Python model == circuit witness"** is the #1 correctness invariant. The Python `ComplianceProof` class (and its witness builder) must produce exactly the private + public inputs the circuit expects.
- Signal ordering in the `main {public [...]}` component is part of the external interface. Treat changes like a breaking API change.
- Thresholds are always verifier-supplied (public). Never bake jurisdiction logic into the circuit.
- All range checks required for comparator soundness are already present (post-audit). Do not remove them.
- Nullifier + domain binding + expiration are the replay / cross-chain protections. The circuit enforces part of it; the contract enforces the rest.

### ANTI-PATTERNS (legacy)

- **NEVER** change Python witness generation without updating the circuit (or vice versa). You will ship unverifiable proofs.
- **NEVER** reorder public signals without updating `docs/internal/CIRCUIT_SIGNALS.md`, the Python model, all test vectors, and the verifier contract call site.
- **NEVER** treat `sanctions_clear` as a constant inside the circuit. It must be a private input constrained to 1 (so a malicious issuer that sets it to 0 produces an invalid proof — which is correct).
- **NEVER** let the prover supply thresholds. They are public for a reason.
- **NEVER** remove the 252-bit range checks on sanctions keys or the 64-bit checks on amounts — the comparators become unsound.
- **NEVER** assume adjacency in a gap proof is "just two numbers the prover gives you." It is derived from path bits.
- **NEVER** forget that `domain_chain_id` and `domain_contract_hash` have **no in-circuit constraint** — their security comes from the verifier contract checking them against `block.chainid` and `address(this)`.

### TEST VECTORS & REGENERATION (legacy)

- Authoritative signal reference: `docs/internal/CIRCUIT_SIGNALS.md`
- Test vectors live alongside the Python test suite (see `tests/unit/test_circuits.py` and the `test-vectors/` patterns referenced in the proof package).
- To regenerate vectors after a circuit change:
  1. Update circuit
  2. Update Python witness builder to match
  3. Recompile (`bash scripts/compile_circuits.sh`)
  4. Regenerate vectors via the Python test helpers
  5. Update `CIRCUIT_SIGNALS.md` if public interface changed

### AUDIT FIXES (PRESERVED, legacy)

Post-audit the following soundness issues were fixed and must not regress:
- #1 Adjacency derived from path bits, not free input
- #2 252-bit range check on all sanctions keys before LessThan
- #3 Thresholds are public inputs (verifier-supplied)
- #5 `sanctions_clear` is explicit private input constrained to 1
- #9 Threshold ordering enforced in-circuit
- #10/#12 Range checks on amounts, tiers, and thresholds before comparators
- #11/#13 Range checks on jurisdiction (16-bit) and kyc_tier (2-bit)

## COMMANDS

```bash
# Pilot circuit tests (compile pilot_compliance.circom when circom + node are available; otherwise skip)
uv run python -m pytest tests/unit/test_pilot_compliance.py tests/unit/test_pilot_credential.py \
  tests/unit/test_pilot_valuation.py tests/unit/test_pilot_projection.py -v

# Compile and prove BOTH profiles with isolated, unapproved development keys (new output dir)
.venv/bin/python scripts/test_development_circuits.py /absolute/new-development-artifacts

# Legacy compile (compliance.circom only)
bash scripts/compile_circuits.sh

# Legacy circuit tests
uv run python -m pytest tests/unit/test_circuits.py -v

# Static analysis (Circomspect; allowlisted findings only)
bash scripts/circuit_lint.sh
```

## NOTES (legacy)

- Default tree sizes (20 + 10) are sufficient for current sanctions lists (~1M entries) and ~1K trusted issuers. Changing depths is a breaking change for all proofs.
- The circuit aborts on any unsatisfied constraint. Reaching the final `is_compliant <== 1` line means every sub-circuit passed.
- Proof expiration has **dual enforcement**: circuit ensures `proof_expires_at > transfer_timestamp`; the verifier contract additionally checks `proof_expires_at >= block.timestamp`.
