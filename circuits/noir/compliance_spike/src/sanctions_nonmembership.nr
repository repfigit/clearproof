// Sanctions non-membership proof via sorted-tree gap proof
// Mirrors circuits/sanctions_nonmembership.circom
//
// Proves that a wallet address hash is NOT in the sanctions Merkle tree
// by showing two adjacent leaves that bracket the query key.

use dep::std;
use crate::merkle::{merkle_proof, sanctions_leaf_hash};

/// Sanctions non-membership proof inputs
pub struct SanctionsNonMembershipInputs<let DEPTH: u32> {
    pub sanctions_root: Field,
    pub query_key: Field,
    pub left_key: Field,
    pub right_key: Field,
    pub left_path_elements: [Field; DEPTH],
    pub left_path_indices: [Field; DEPTH],
    pub right_path_elements: [Field; DEPTH],
    pub right_path_indices: [Field; DEPTH],
}

/// Verify sanctions non-membership via gap proof
///
/// Constraints:
/// 1. left_key < query_key < right_key (strict ordering)
/// 2. Adjacency: right_index == left_index + 1
/// 3. Both left and right keys are valid members of the tree
pub fn verify_sanctions_non_membership<let DEPTH: u32>(
    inputs: &SanctionsNonMembershipInputs<DEPTH>,
) -> bool {
    // Range check: all keys must be < 2^252 for LessThan soundness
    // In Noir, Field is ~254 bits, so we check the top 2 bits are 0
    assert(inputs.left_key < 2^252);
    assert(inputs.query_key < 2^252);
    assert(inputs.right_key < 2^252);

    // Constraint 1: left_key < query_key (strict)
    assert(inputs.left_key < inputs.query_key);

    // Constraint 2: query_key < right_key (strict)
    assert(inputs.query_key < inputs.right_key);

    // Constraint 3: Adjacency derived from path bits
    // Derive leaf indices from Merkle path direction bits
    let mut left_index: Field = 0;
    let mut right_index: Field = 0;
    let mut pow2: Field = 1;

    for i in 0..DEPTH {
        // indices are already constrained to binary by merkle_proof
        left_index = left_index + inputs.left_path_indices[i] * pow2;
        right_index = right_index + inputs.right_path_indices[i] * pow2;
        pow2 = pow2 * 2;
    }

    // Enforce adjacency: right leaf is exactly one position after left leaf
    assert(right_index == left_index + 1);

    // Constraint 4: left_key is a valid leaf in the sanctions tree
    let left_leaf = sanctions_leaf_hash(inputs.left_key);
    let left_valid = merkle_proof(
        left_leaf,
        inputs.sanctions_root,
        inputs.left_path_elements,
        inputs.left_path_indices,
    );
    assert(left_valid);

    // Constraint 5: right_key is a valid leaf in the sanctions tree
    let right_leaf = sanctions_leaf_hash(inputs.right_key);
    let right_valid = merkle_proof(
        right_leaf,
        inputs.sanctions_root,
        inputs.right_path_elements,
        inputs.right_path_indices,
    );
    assert(right_valid);

    // All constraints passed — wallet is provably not in the sanctions tree
    true
}
