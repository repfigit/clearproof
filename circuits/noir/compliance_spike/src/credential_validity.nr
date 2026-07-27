// Credential validity circuit
// Mirrors circuits/credential_validity.circom
//
// Proves a VASP credential is valid without revealing its contents:
// 1. Poseidon(preimage fields) == credential_commitment
// 2. Credential is not expired (expires_at > current_timestamp)
// 3. Issuer is in the trusted issuer Merkle tree
// 4. Jurisdiction matches expected jurisdiction
// 5. KYC tier is valid (1, 2, or 3)
// 6. sanctions_clear flag is 1

use dep::std;
use crate::merkle::{merkle_proof, issuer_leaf_hash};

/// Credential validity inputs
pub struct CredentialValidityInputs<let ISSUER_DEPTH: u32> {
    pub credential_commitment: Field,
    pub issuer_tree_root: Field,
    pub current_timestamp: Field,
    pub expected_jurisdiction: Field,
    pub issuer_did: Field,
    pub jurisdiction_code: Field,
    pub kyc_tier: Field,
    pub sanctions_clear: Field,
    pub issued_at: Field,
    pub expires_at: Field,
    pub issuer_path_elements: [Field; ISSUER_DEPTH],
    pub issuer_path_indices: [Field; ISSUER_DEPTH],
}

/// Verify credential validity
///
/// Constraints:
/// 1. commitment = Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
/// 2. sanctions_clear == 1
/// 3. expires_at > current_timestamp
/// 4. Issuer is in trusted issuer set (Merkle membership)
/// 5. jurisdiction matches expected
/// 6. kyc_tier in [1, 3]
pub fn verify_credential_validity<let ISSUER_DEPTH: u32>(
    inputs: &CredentialValidityInputs<ISSUER_DEPTH>,
) -> bool {
    // Range checks
    // jurisdiction_code and expected_jurisdiction fit in 16 bits
    assert(inputs.jurisdiction_code < 2^16);
    assert(inputs.expected_jurisdiction < 2^16);

    // kyc_tier fits in 2 bits (values 1-3)
    assert(inputs.kyc_tier < 4);

    // timestamps fit in 64 bits
    assert(inputs.issued_at < 2^64);
    assert(inputs.expires_at < 2^64);
    assert(inputs.current_timestamp < 2^64);

    // Constraint 1: Credential commitment matches preimage hash
    // commitment = Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
    let computed_commitment = std::hash::poseidon2::Poseidon2Hasher::hash_with_4_chunks([
        inputs.issuer_did,
        inputs.kyc_tier,
        inputs.sanctions_clear,
        inputs.issued_at,
    ]);
    // Note: Noir's Poseidon2 takes 4 chunks, so we need to hash the 5th separately
    // For simplicity, we'll use a different approach: hash all 5 fields
    let commitment_hash = std::hash::poseidon2::Poseidon2Hasher::hash(&[
        inputs.issuer_did,
        inputs.kyc_tier,
        inputs.sanctions_clear,
        inputs.issued_at,
        inputs.expires_at,
    ]);
    assert(commitment_hash == inputs.credential_commitment);

    // Constraint 2: sanctions_clear must be 1
    assert(inputs.sanctions_clear == 1);

    // Constraint 3: Credential is not expired
    assert(inputs.expires_at > inputs.current_timestamp);

    // Constraint 4: Issuer is in the trusted issuer set
    let issuer_leaf = issuer_leaf_hash(inputs.issuer_did);
    let issuer_valid = merkle_proof(
        issuer_leaf,
        inputs.issuer_tree_root,
        inputs.issuer_path_elements,
        inputs.issuer_path_indices,
    );
    assert(issuer_valid);

    // Constraint 5: Jurisdiction matches expected
    assert(inputs.expected_jurisdiction == inputs.jurisdiction_code);

    // Constraint 6: KYC tier is valid (1, 2, or 3)
    assert(inputs.kyc_tier >= 1);
    assert(inputs.kyc_tier <= 3);

    true
}
