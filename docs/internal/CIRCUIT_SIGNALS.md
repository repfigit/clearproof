# Circuit Signals Reference

This document describes the public and private signals of Clearproof's circuits. There are two proof profiles. **Never select a profile by signal count.**

| Profile | Circuit | Public signals | Status |
| --- | --- | --- | --- |
| `pilot-transfer-v3` | `circuits/pilot_compliance.circom` | 8 | **Current** pilot profile. Authoritative spec: [`specs/pilot-transfer-v3.md`](../../specs/pilot-transfer-v3.md) |
| `pilot-transfer-v2` / `v1` | same circuit, earlier depths/binding | 8 | Historical. Current checks reject them; pinned read-only pairing only |
| Legacy | `circuits/compliance.circom` | 16 (14 inputs + 2 outputs) | Separate demo and parity path. Never valid as current pilot authorization |

## Current profile: pilot-transfer-v3

Instantiation: `PilotCompliance(32, 20, 20)`, meaning tree depths of 32 (issuance, 2^32 credentials), 20 (authorized issuers) and 20 (sanctions, 2^20 − 2 addresses). The depths are defined in `src/registry/pilot_tree.py` (ADR 0011) and the circuit has 95,408 constraints. Signal order is fixed by the `main` component and mirrored by `PUBLIC_SIGNALS` in `src/prover/pilot_compliance.py`. The spec and ADRs 0009/0011 are authoritative. The table below records which constraints come from the circuit and which from outside it.

| # | Signal | In-circuit constraint | Enforced outside the circuit by |
| --- | --- | --- | --- |
| 0 | `projection_commitment` | `== Poseidon(204, transfer_projection_commitment, credential_commitment, issuance_root)` | Verifier reconstructs it from authenticated records; `PilotCurrentRegistry` statement binding |
| 1 | `authorized_issuer_root` | Issuer leaf `Poseidon(103, issuer DID limbs, issuance_root)` is a member | Current-root checks; registry pin 1 (issuers) |
| 2 | `sanctions_root` | Gap non-membership for **both** originator and beneficiary wallets (projection fields 10 and 11) | Current-root checks; registry pin 2 (sanctions) |
| 3 | `authorization_nullifier` | `== Poseidon(203, holder_secret, authorization_scope)`; scope = `Poseidon(202, tenant, transfer ID, nonce, deployment chain, deployment address)` | PostgreSQL consumes it (single use). The registry only mirrors consumed receipts |
| 4 | `evaluated_at` | `== transfer_fields[23]`; credential `issued_at <= evaluated_at < expires_at` | Verifier freshness policy |
| 5 | `proof_expires_at` | 53-bit; `evaluated_at < proof_expires_at <= min(transfer expiry, credential expiry, evaluated_at + 300)` | Registry rejects `> statement.validUntil` |
| 6 | `domain_chain_id` | `== transfer_fields[26]` only; not tied to any real chain | `PilotCurrentRegistry`: `== block.chainid` |
| 7 | `domain_registry` | `== transfer_fields[27]` only | `PilotCurrentRegistry`: `== uint160(address(this))` |

Amount, tier, wallets, jurisdiction, participants and credential fields are all **private**. There is no public amount-tier or SAR signal.

### Soundness properties that must not regress (pilot circuits)

- **Sanctions gap proof (`PilotSanctionsGap`):**
  - The wallet is a raw 160-bit address (`Num2Bits(160)`). Keys are range-checked to 161 bits before `LessThan(161)`.
  - The right key is bounded by the `2^160` sentinel.
  - Adjacency is derived from Merkle path bits (`right_index === left_index + 1`), not taken as free input.
  - Leaves are `Poseidon(301, key)`.
  - The raw-address tree is incompatible with the legacy hashed-key tree (see ADR 0006).
- **Credential (`PilotCredentialValidity`):**
  - Limbs are range-checked (128-bit limbs, 160-bit wallet, 53-bit times, 2-bit KYC tier).
  - Nonzero checks cover the wallet, nonce, tier, holder secret and holder commitment. Jurisdiction bytes must be ASCII A–Z.
  - The issuer screening assertion is constrained to 1.
  - Holder binding is `Poseidon(101, holder_secret)`. The commitment is `Poseidon(102, fields)`, and it must be a member of `issuance_root`.
  - Expected tenant, subject and jurisdiction are bound to private transfer fields.
- **Valuation and tier (`PilotValuation`, `PilotAmountTier`):**
  - Exact 128-bit limb arithmetic with quotient/remainder semantics, and positive operands.
  - Thresholds are positive and strictly ordered. The tier is derived, not supplied.
  - No SAR output.
- **Transfer projection (`PilotTransferProjection`):**
  - Per-field bit widths are checked on all 48 fields.
  - Time ordering: observation ≤ creation ≤ evaluation < transfer expiry ≤ quote expiry.
  - Maximum age is at most 86,400 s, and decimals are at most 18.
  - Both wallets, the asset chain and contract, and the deployment address must be nonzero.
  - Asset chain must equal deployment chain.
  - DID fields may be nonzero only for parties marked as VASPs.

## Legacy profile: compliance.circom (16 signals)

Everything from here through "Legacy signal hashing schemes" describes the legacy profile only.

**File**: `circuits/compliance.circom`
**Instantiation**: `ComplianceProof(20, 10)` (sanctions_depth=20, issuer_depth=10)
**Total Public Inputs**: 14 (+ 2 public outputs = 16 total public signals)
**Total Private Inputs**: 12 + 60 Merkle proof elements (see below)

### Public Inputs (verifier-supplied)

These signals are exposed to the verifier contract and must be provided when calling `verifyProof()`.

| # | Signal Name | Type | Description | Range/Constraints |
|---|------------|------|-------------|-------------------|
| 0 | `sanctions_tree_root` | field | Merkle root of the sorted sanctions tree (OFAC/UN/EU combined) | Valid BN128 field element |
| 1 | `issuer_tree_root` | field | Merkle root of the trusted VASP issuer tree | Valid BN128 field element |
| 2 | `amount_tier` | uint64 | Transfer tier (1=retail, 2=professional, 3=institutional, 4=high-value) | [1, 4] |
| 3 | `transfer_timestamp` | uint64 | Unix timestamp of the transfer | [0, 2^64-1] |
| 4 | `jurisdiction_code` | uint16 | ISO 3166-1 alpha-2 country code as integer (e.g., 840 for USA) | [0, 65535] |
| 5 | `credential_commitment` | field | Poseidon hash of credential preimage: Poseidon(issuer_did, kyc_tier, 1, issued_at, expires_at) | Valid BN128 field element |
| 6 | `tier2_threshold` | uint64 | Maximum amount in USD cents for tier 2 (jurisdiction-specific) | < tier3_threshold |
| 7 | `tier3_threshold` | uint64 | Maximum amount in USD cents for tier 3 (jurisdiction-specific) | < tier4_threshold |
| 8 | `tier4_threshold` | uint64 | Maximum amount in USD cents for tier 4 (jurisdiction-specific) | > tier3_threshold |
| 9 | `domain_chain_id` | uint256 | Ethereum chain ID (e.g., 1=mainnet, 11155111=Sepolia) | Checked by verifier contract |
| 10 | `domain_contract_hash` | field | Truncated keccak256 of ComplianceRegistry address | Checked by verifier contract |
| 11 | `transfer_id_hash` | field | keccak256 of transferId, binds proof to specific transfer | Prevents replay |
| 12 | `credential_nullifier` | field | Poseidon(credential_commitment, transfer_id_hash) | One-time-use, stored on-chain |
| 13 | `proof_expires_at` | uint64 | Unix timestamp after which proof is invalid | > transfer_timestamp |

### Private Inputs

These signals are kept secret by the prover and never revealed to the verifier.

#### Credential Preimage Fields

| Signal Name | Type | Description |
|-------------|------|-------------|
| `issuer_did` | field | Credential issuer's DID as field element |
| `kyc_tier` | uint2 | KYC level (1, 2, or 3) |
| `sanctions_clear` | bit | Must be 1 (issuer attests sanctions check passed) |
| `issued_at` | uint64 | Unix timestamp of credential issuance |
| `expires_at` | uint64 | Unix timestamp of credential expiration |

#### Issuer Merkle Membership Proof (depth=10)

| Signal Name | Array Size | Description |
|-------------|------------|-------------|
| `issuer_path_elements` | 10 | Sibling hashes at each level of the Merkle path |
| `issuer_path_indices` | 10 | Direction bits (0=left child, 1=right child) at each level |

#### Sanctions Non-Membership Proof (depth=20)

| Signal Name | Array Size | Description |
|-------------|------------|-------------|
| `wallet_address_hash` | 1 | Poseidon hash of the wallet address being verified |
| `left_key` | 1 | Largest sanctions list key less than wallet_address_hash |
| `right_key` | 1 | Smallest sanctions list key greater than wallet_address_hash |
| `left_path_elements` | 20 | Sibling hashes for left neighbor Merkle path |
| `left_path_indices` | 20 | Direction bits for left neighbor Merkle path |
| `right_path_elements` | 20 | Sibling hashes for right neighbor Merkle path |
| `right_path_indices` | 20 | Direction bits for right neighbor Merkle path |

#### Amount Verification

| Signal Name | Type | Description |
|-------------|------|-------------|
| `actual_amount` | uint64 | Real transfer amount in USD cents (private, revealed only to off-chain verifier) |

### Public Outputs

| Signal Name | Type | Description |
|-------------|------|-------------|
| `is_compliant` | bit | 1 if all checks pass (always 1 if circuit executes without failure) |
| `sar_review_flag` | bit | 1 if amount_tier >= 3 (triggers human review) |

## Legacy sub-circuit: Sanctions Non-Membership

**File**: `circuits/sanctions_nonmembership.circom`
**Template**: `SanctionsNonMembership(tree_depth=20)`

### Public Inputs

| # | Signal Name | Description |
|---|-------------|-------------|
| 0 | `sanctions_root` | Merkle root of sanctions tree |

### Private Inputs

| Signal Name | Array Size | Description |
|-------------|------------|-------------|
| `query_key` | 1 | Wallet address hash to prove is NOT sanctioned |
| `left_key` | 1 | Largest key in tree < query_key |
| `right_key` | 1 | Smallest key in tree > query_key |
| `left_path_elements` | 20 | Merkle path for left neighbor |
| `left_path_indices` | 20 | Direction bits for left path |
| `right_path_elements` | 20 | Merkle path for right neighbor |
| `right_path_indices` | 20 | Direction bits for right path |

### Outputs

| Signal Name | Description |
|-------------|-------------|
| `valid` | 1 if gap proof is valid |

**Note**: Adjacency of left/right leaves is enforced by deriving leaf indices from path direction bits, preventing false gap claims.

## Legacy sub-circuit: Credential Validity

**File**: `circuits/credential_validity.circom`
**Template**: `CredentialValidity(issuer_tree_depth=10)`

### Public Inputs

| # | Signal Name | Description |
|---|-------------|-------------|
| 0 | `credential_commitment` | Expected Poseidon hash of credential |
| 1 | `issuer_tree_root` | Merkle root of trusted issuers |
| 2 | `current_timestamp` | Time for expiry check |
| 3 | `expected_jurisdiction` | Expected jurisdiction code |

### Private Inputs

| Signal Name | Type | Description |
|-------------|------|-------------|
| `issuer_did` | field | Issuer DID |
| `jurisdiction_code` | uint16 | Actual jurisdiction (must equal expected) |
| `kyc_tier` | uint2 | KYC level (1-3) |
| `sanctions_clear` | bit | Must be 1 |
| `issued_at` | uint64 | Issuance timestamp |
| `expires_at` | uint64 | Expiration timestamp |
| `issuer_path_elements` | 10 | Issuer membership proof |
| `issuer_path_indices` | 10 | Issuer membership proof directions |

## Legacy sub-circuit: Amount Tier

**File**: `circuits/amount_tier.circom`
**Template**: `AmountTier()`

### Public Inputs

| # | Signal Name | Description |
|---|-------------|-------------|
| 0 | `amount_tier` | Claimed tier (1-4) |
| 1 | `tier2_threshold` | Tier 2 boundary (cents) |
| 2 | `tier3_threshold` | Tier 3 boundary (cents) |
| 3 | `tier4_threshold` | Tier 4 boundary (cents) |

### Private Inputs

| Signal Name | Type | Description |
|-------------|------|-------------|
| `actual_amount` | uint64 | Real transfer amount in cents |

### Public Outputs

| Signal Name | Type | Description |
|-------------|------|-------------|
| `sar_review_flag` | bit | 1 if tier >= 3 |

## Legacy signal ordering for proof generation

When generating a proof using snarkjs, inputs must be provided in this exact order:

```
Public Signals (14 values):
[0]  sanctions_tree_root
[1]  issuer_tree_root
[2]  amount_tier
[3]  transfer_timestamp
[4]  jurisdiction_code
[5]  credential_commitment
[6]  tier2_threshold
[7]  tier3_threshold
[8]  tier4_threshold
[9]  domain_chain_id
[10] domain_contract_hash
[11] transfer_id_hash
[12] credential_nullifier
[13] proof_expires_at

Private Signals (in circuit order):
[14] issuer_did
[15] kyc_tier
[16] sanctions_clear
[17] issued_at
[18] expires_at
[19-28] issuer_path_elements[0-9]
[29-38] issuer_path_indices[0-9]
[39] wallet_address_hash
[40] left_key
[41] right_key
[42-61] left_path_elements[0-19]
[62-81] left_path_indices[0-19]
[82-101] right_path_elements[0-19]
[102-121] right_path_indices[0-19]
[122] actual_amount
```

## Legacy on-chain verification

The Solidity verifier (`Groth16Verifier.sol`) expects:

```solidity
function verifyProof(
    uint[2] calldata _pA,      // Groth16 proof element A
    uint[2][2] calldata _pB,    // Groth16 proof element B
    uint[2] calldata _pC,       // Groth16 proof element C
    uint[16] calldata _pubSignals  // 16 public signals (2 outputs + 14 inputs)
) public view returns (bool)
```

snarkjs outputs public signals in this order: **outputs first** (indices 0-1), then **public inputs** in declaration order (indices 2-15).

### Which signals are constrained in-circuit, and which are not

This distinction is load-bearing and easy to get wrong. Some public inputs are
**not constrained by the circuit at all** — the prover chooses their value
freely, and the only thing standing between a chosen value and an accepted
proof is a verifier-side check. If a verifier omits that check, the attestation
built on that signal is worthless even though the proof is cryptographically
valid.

| Slot | Signal | Constrained in-circuit? | Enforced by |
|------|--------|------------------------|-------------|
| 0 | `is_compliant` | Literal constant `1` (see note) | — |
| 1 | `sar_review_flag` | Derived from `amount_tier` | circuit |
| 2 | `sanctions_tree_root` | No | `ComplianceRegistry` vs `SanctionsOracle.currentRoot()` |
| 3 | `issuer_tree_root` | No | `ComplianceRegistry` vs `VASPRegistry.issuerMerkleRoot()` |
| 4 | `amount_tier` | Derived from amount vs thresholds | circuit (but see 8-10) |
| 5 | `transfer_timestamp` | Range only | `ComplianceRegistry` (not in future) |
| 6 | `jurisdiction_code` | Range only (16-bit) | `ComplianceRegistry._checkThresholds` (must be alpha-2) |
| 7 | `credential_commitment` | Yes — Poseidon preimage | circuit + revocation check |
| 8-10 | `tier2/3/4_threshold` | **No** | `ComplianceRegistry._checkThresholds`, `verifyProof` (TS), `/proof/verify` (Python) |
| 11 | `domain_chain_id` | **No** | `ComplianceRegistry` vs `block.chainid` |
| 12 | `domain_contract_hash` | **No** | `ComplianceRegistry` vs keccak256 of its own address |
| 13 | `transfer_id_hash` | No | `ComplianceRegistry` vs keccak256(transferId) mod r |
| 14 | `credential_nullifier` | Yes — Poseidon preimage | circuit + `usedNullifiers` |
| 15 | `proof_expires_at` | `> transfer_timestamp` | `ComplianceRegistry` vs `block.timestamp` |

Notes:

- **`is_compliant` is the literal constant `1`**, not a computed verdict. It is
  sound — the circuit aborts if any constraint fails, so a proof only exists for
  a compliant witness — but an integrator reading `publicSignals[0]` as a
  computed result is misreading it.
- **Slots 8-10 (thresholds) are the subtlest case.** `amount_tier` *is* derived
  in-circuit, but it is derived *from these prover-supplied thresholds*. A
  prover that submits `tier2_threshold = 2**63` gets a valid proof that a $50M
  transfer is tier 1 — defeating the tier attestation and, transitively, the
  SAR review flag. Every verifier must therefore re-derive the thresholds from
  its own table for the jurisdiction in slot 6. The canonical table is
  `config/jurisdiction_thresholds.json`; the on-chain copy is seeded by
  `packages/contracts/scripts/deploy.ts` and is the authority for on-chain
  submission. Cross-language agreement is asserted by
  `tests/unit/test_jurisdiction_thresholds.py` and
  `packages/proof/test/thresholds.test.ts`.
- Unregistered jurisdictions resolve to the FATF default entry
  (`DEFAULT_JURISDICTION_KEY = 0` on-chain). Whether unregistered jurisdictions
  should instead be rejected outright is an open policy question — see AIF-79.

## Legacy signal hashing schemes

### Credential Commitment
```
Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
```
Note: `jurisdiction_code` is NOT included in the commitment. It's verified separately via equality constraint.

### Credential Nullifier
```
Poseidon(credential_commitment, transfer_id_hash)
```
Binds the nullifier to both the specific credential and specific transfer.

### Sanctions Leaf Hash
```
Poseidon(0x01, wallet_address_hash)
```
Domain-separated leaf hash for sanctions list entries.

### Issuer Leaf Hash
```
Poseidon(0x02, issuer_did)
```
Domain-separated leaf hash for trusted issuer entries.

## Pilot credential subcircuit

`circuits/pilot_credential.circom` defines `PilotCredentialValidity(issuance_depth,
issuer_depth)` for `clearproof-credential-v1`. It does not instantiate `main` by
itself; `pilot_compliance.circom` composes it into `pilot-transfer-v3`. Its unit
harness uses two-level trees solely to exercise membership constraints.

`fields[13]` is the credential Poseidon preimage excluding domain tag 102:

| Index | Value | Range |
| --- | --- | --- |
| 0–1 | SHA-256 of canonical issuer DID, high then low limb | 128 bits each |
| 2–3 | SHA-256 of opaque tenant ID, high then low limb | 128 bits each |
| 4–5 | Credential nonce, high then low limb | 128 bits each; jointly nonzero |
| 6 | Subject EVM wallet | 160 bits, nonzero |
| 7 | Poseidon(101, holder secret) | Nonzero BN254 scalar |
| 8 | Uppercase ASCII jurisdiction bytes, big endian | Two bytes A–Z |
| 9 | KYC tier | 1–3 |
| 10–11 | Issued-at and expires-at | 53 bits each |
| 12 | Issuer screening assertion | Must equal 1 |

Other inputs are the holder secret, credential commitment, private issuance root
and path, authorized issuer root and path, expected tenant limbs, expected subject,
expected jurisdiction and evaluation time. Membership paths have boolean indices.
The evaluation time must satisfy `issued_at <= evaluated_at < expires_at`.

In `pilot-transfer-v3`, the expected tenant, subject, jurisdiction and evaluation
time are bound to private transfer fields 4–5, 10, 25 and 23. None is public, and
the legacy SAR advisory signal is absent. (The standalone harness exposes expected
subject/jurisdiction for testing only.) See ADR 0003 for external enrollment and root authority.

## Pilot valuation subcircuits

`pilot_valuation.circom` adds `PilotValuation()` with private inputs
`amount_base_units`, `numerator`, `denominator`, `usd_cents`, and `remainder`.
Each is constrained as an unsigned 128-bit value; all but the remainder must be
positive. Limb arithmetic enforces exact integer quotient/remainder semantics.

`PilotAmountTier()` accepts `usd_cents`, three ordered positive `thresholds` and
`tier`. It exposes no output. `PilotTransferProjection` composes both privately:
amount and tier never become public signals. Policy/valuation provenance is bound
through the projection fields and the registry's policy/valuation pins. See ADR 0004 and `src/prover/pilot_valuation.py` for witness rules.


## Pilot private transfer projection

`PilotTransferProjection` consumes `transfer_fields[48]`, `valuation_remainder`
and the expected `projection_commitment`. Its `authorization_scope` output is
for the parent holder-nullifier construction. The 48 fields are private inputs to
`pilot-transfer-v3`; only their commitment is bound publicly, via signal 0.

| Index | Field |
| --- | --- |
| 0 | `transfer_digest_hi` |
| 1 | `transfer_digest_lo` |
| 2 | `context_digest_hi` |
| 3 | `context_digest_lo` |
| 4 | `tenant_hi` |
| 5 | `tenant_lo` |
| 6 | `transfer_id_hi` |
| 7 | `transfer_id_lo` |
| 8 | `nonce_hi` |
| 9 | `nonce_lo` |
| 10 | `originator_wallet` |
| 11 | `beneficiary_wallet` |
| 12 | `asset_chain` |
| 13 | `asset_contract` |
| 14 | `asset_decimals` |
| 15 | `amount_base_units` |
| 16 | `valuation_numerator` |
| 17 | `valuation_denominator` |
| 18 | `usd_cents` |
| 19 | `valuation_observed_at` |
| 20 | `valuation_expires_at` |
| 21 | `transfer_created_at` |
| 22 | `transfer_expires_at` |
| 23 | `evaluated_at` |
| 24 | `max_transfer_age` |
| 25 | `jurisdiction` |
| 26 | `deployment_chain` |
| 27 | `deployment_address` |
| 28 | `policy_digest_hi` |
| 29 | `policy_digest_lo` |
| 30 | `catalog_digest_hi` |
| 31 | `catalog_digest_lo` |
| 32 | `threshold_2` |
| 33 | `threshold_3` |
| 34 | `threshold_4` |
| 35 | `private_tier` |
| 36 | `originator_did_hi` |
| 37 | `originator_did_lo` |
| 38 | `originator_is_vasp` |
| 39 | `beneficiary_did_hi` |
| 40 | `beneficiary_did_lo` |
| 41 | `beneficiary_is_vasp` |
| 42 | `valuation_source_hi` |
| 43 | `valuation_source_lo` |
| 44 | `valuation_evidence_hi` |
| 45 | `valuation_evidence_lo` |
| 46 | `valuation_digest_hi` |
| 47 | `valuation_digest_lo` |

See ADR 0005 for canonical-record binding and trust boundaries.

## Composed profile

The composed circuit `pilot_compliance.circom` is the current `pilot-transfer-v3`
profile described at the top of this document. See
[ADR 0006](../adr/0006-composed-pilot-transfer.md) for private fields, tree bounds and
trust requirements, and [ADR 0009](../adr/0009-credential-bound-pilot-profile.md) for
the v1 → v2 change (signal 0 now binds the exact credential and issuance root). See
[ADR 0011](../adr/0011-production-tree-depths.md) for the v2 → v3 change (tree depths
from 8/8/8 to 32/20/20; same signals, new keys).
