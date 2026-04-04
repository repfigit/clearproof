# Circuit Signals Reference

This document provides the complete signal specification for all ZK Travel Rule Compliance Bridge circuits, including exact ordering for public inputs and private inputs.

## Main Compliance Circuit

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

## Sub-Circuit: Sanctions Non-Membership

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

## Sub-Circuit: Credential Validity

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

## Sub-Circuit: Amount Tier

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

## Signal Ordering for Proof Generation

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

## On-Chain Verification

The Solidity verifier (`Groth16Verifier.sol`) expects:

```solidity
function verifyProof(
    uint[2] calldata _pA,      // Groth16 proof element A
    uint[2][2] calldata _pB,    // Groth16 proof element B
    uint[2] calldata _pC,       // Groth16 proof element C
    uint[16] calldata _pubSignals  // 16 public signals (2 outputs + 14 inputs)
) public view returns (bool)
```

snarkjs outputs public signals in this order: **outputs first** (indices 0-1), then **public inputs** in declaration order (indices 2-15). All 16 slots are actively validated by ComplianceRegistry:

| Slot | Signal | On-Chain Usage |
|------|--------|----------------|
| 0 | `is_compliant` | Must equal 1 for proof acceptance |
| 1 | `sar_review_flag` | Stored in `userSARFlags` mapping |
| 2 | `sanctions_tree_root` | Checked against `SanctionsOracle.root()` |
| 3 | `issuer_tree_root` | Checked against `IssuerRegistry.root()` |
| 5 | `transfer_timestamp` | Must be ≤ `block.timestamp` |
| 7 | `credential_commitment` | Used for credential binding |
| 11 | `domain_chain_id` | Must equal `block.chainid` |
| 12 | `domain_contract_hash` | Must equal keccak256 of registry address |
| 13 | `transfer_id_hash` | Unique per transfer, prevents replay |
| 14 | `credential_nullifier` | Stored on-chain, prevents credential reuse |
| 15 | `proof_expires_at` | Must be ≥ `block.timestamp` |

## Signal Hashing Schemes

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
