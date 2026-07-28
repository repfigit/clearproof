# CIRCUITS/ AGENTS.md

**Scope:** Circom circuits (Groth16) — the cryptographic correctness root of the entire ZK Travel Rule system.

## OVERVIEW
Four Circom circuits + two lib helpers that together prove: (1) credential valid + not expired, (2) wallet not sanctioned (gap proof), (3) amount tier correctly assigned, (4) domain-bound + single-use + expiring. All without revealing PII or exact amounts.

## STRUCTURE
```
circuits/
├── compliance.circom                 # Main orchestrator (232 LOC)
├── sanctions_nonmembership.circom    # Gap proof (sorted Merkle non-membership)
├── credential_validity.circom        # Credential + issuer + expiry checks
├── amount_tier.circom                # Tier assignment + SAR flag
├── lib/
│   ├── merkle_tree.circom            # Generic Poseidon MerkleProof + gap helper
│   └── poseidon_hasher.circom        # DomainPoseidon (tags 0x01/0x02)
└── (compiled artifacts live in artifacts/ at repo root)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add new compliance check | `compliance.circom` + matching Python model | MUST update both or proofs are worthless |
| Change signal ordering | `compliance.circom` main component + `src/protocol/compliance_proof.py` + `docs/internal/CIRCUIT_SIGNALS.md` | Breaking change — update test vectors too |
| Modify sanctions gap logic | `sanctions_nonmembership.circom` | Adjacency is derived from path bits (see below) |
| Add credential field | `credential_validity.circom` + Python `_field_ints()` | Keep commitment layout identical |
| Change tier thresholds | `amount_tier.circom` (public inputs only) | Verifier supplies — prover cannot manipulate |
| Debug Poseidon collision | `lib/poseidon_hasher.circom` | Domain tags: 0x01=sanctions, 0x02=issuer |

## PUBLIC SIGNAL CONTRACT (Main Circuit)

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

## SUB-CIRCUIT RESPONSIBILITIES

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

## LIBS

**merkle_tree.circom**
- `MerkleProof(depth)` — generic Poseidon membership proof (used by both credential and sanctions)
- Non-membership lives in `sanctions_nonmembership.circom` (`SanctionsNonMembership`); the legacy `MerkleNonMembership` template was removed in v0.4.x (deprecated since v0.3.0 — free-input adjacency, no range checks)
- Path indices are constrained to binary; ordering uses `MultiMux1`

**poseidon_hasher.circom**
- `PoseidonHasher(n)` — raw Poseidon
- `DomainPoseidon(n)` — prepends domain tag
- Domain tags in use: `0x01` (sanctions leaf), `0x02` (issuer leaf), `0x03` reserved for future credential commitment variant

## CONVENTIONS

- **"Python model == circuit witness"** is the #1 correctness invariant. The Python `ComplianceProof` class (and its witness builder) must produce exactly the private + public inputs the circuit expects.
- Signal ordering in the `main {public [...]}` component is part of the external interface. Treat changes like a breaking API change.
- Thresholds are always verifier-supplied (public). Never bake jurisdiction logic into the circuit.
- All range checks required for comparator soundness are already present (post-audit). Do not remove them.
- Nullifier + domain binding + expiration are the replay / cross-chain protections. The circuit enforces part of it; the contract enforces the rest.

## ANTI-PATTERNS (THIS PROJECT)

- **NEVER** change Python witness generation without updating the circuit (or vice versa). You will ship unverifiable proofs.
- **NEVER** reorder public signals without updating `docs/internal/CIRCUIT_SIGNALS.md`, the Python model, all test vectors, and the verifier contract call site.
- **NEVER** treat `sanctions_clear` as a constant inside the circuit. It must be a private input constrained to 1 (so a malicious issuer that sets it to 0 produces an invalid proof — which is correct).
- **NEVER** let the prover supply thresholds. They are public for a reason.
- **NEVER** remove the 252-bit range checks on sanctions keys or the 64-bit checks on amounts — the comparators become unsound.
- **NEVER** assume adjacency in a gap proof is "just two numbers the prover gives you." It is derived from path bits.
- **NEVER** forget that `domain_chain_id` and `domain_contract_hash` have **no in-circuit constraint** — their security comes from the verifier contract checking them against `block.chainid` and `address(this)`.

## TEST VECTORS & REGENERATION

- Authoritative signal reference: `docs/internal/CIRCUIT_SIGNALS.md`
- Test vectors live alongside the Python test suite (see `tests/unit/test_circuits.py` and the `test-vectors/` patterns referenced in the proof package).
- To regenerate vectors after a circuit change:
  1. Update circuit
  2. Update Python witness builder to match
  3. Recompile (`bash scripts/compile_circuits.sh`)
  4. Regenerate vectors via the Python test helpers
  5. Update `CIRCUIT_SIGNALS.md` if public interface changed

## AUDIT FIXES (PRESERVED)

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
# Compile (requires circom + ptau in artifacts/)
bash scripts/compile_circuits.sh

# Run circuit-specific tests
make test-circuits          # or uv run python -m pytest tests/unit/test_circuits.py -v

# Full test suite (includes circuit round-trips)
make test
```

## NOTES

- Default tree sizes (20 + 10) are sufficient for current sanctions lists (~1M entries) and ~1K trusted issuers. Changing depths is a breaking change for all proofs.
- The circuit aborts on any unsatisfied constraint. Reaching the final `is_compliant <== 1` line means every sub-circuit passed.
- Proof expiration has **dual enforcement**: circuit ensures `proof_expires_at > transfer_timestamp`; the verifier contract additionally checks `proof_expires_at >= block.timestamp`.
