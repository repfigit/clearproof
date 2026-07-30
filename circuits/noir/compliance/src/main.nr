// Compliance Circuit - Noir Port (Spike for AIF-66)
// 
// This is a benchmark spike comparing Noir/UltraHonk vs Groth16.
// Uses pedersen_hash as a stand-in hash; production would use Poseidon.
// The circuit logic is identical to the Circom version.

use std::hash::pedersen_hash;

// ============================================================
// Merkle Proof Verification (depth-parameterized)
// ============================================================
fn verify_merkle_proof_20(
    leaf: Field,
    root: Field,
    siblings: [Field; 20],
    indices: [Field; 20]
) -> bool {
    let mut current = leaf;
    
    for i in 0..20 {
        let index = indices[i];
        let sibling = siblings[i];
        
        let left = if index == 0 { current } else { sibling };
        let right = if index == 0 { sibling } else { current };
        
        let inputs: [Field; 2] = [left, right];
        current = pedersen_hash(inputs);
    }
    
    current == root
}

fn verify_merkle_proof_10(
    leaf: Field,
    root: Field,
    siblings: [Field; 10],
    indices: [Field; 10]
) -> bool {
    let mut current = leaf;
    
    for i in 0..10 {
        let index = indices[i];
        let sibling = siblings[i];
        
        let left = if index == 0 { current } else { sibling };
        let right = if index == 0 { sibling } else { current };
        
        let inputs: [Field; 2] = [left, right];
        current = pedersen_hash(inputs);
    }
    
    current == root
}

// ============================================================
// Credential Validity Check
// ============================================================
fn check_credential(
    credential_commitment: Field,
    issuer_tree_root: Field,
    transfer_timestamp: Field,
    issuer_did: Field,
    kyc_tier: Field,
    sanctions_clear: Field,
    issued_at: Field,
    expires_at: Field,
    issuer_path_elements: [Field; 10],
    issuer_path_indices: [Field; 10]
) {
    // Constraint 1: Credential commitment matches preimage
    let preimage: [Field; 5] = [issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at];
    let computed_commitment = pedersen_hash(preimage);
    assert(computed_commitment == credential_commitment, "credential commitment mismatch");
    
    // Constraint 2: sanctions_clear must be 1
    assert(sanctions_clear == 1, "sanctions_clear must be 1");
    
    // Constraint 3: Credential not expired (cast to u64 for comparison)
    let expires_u64 = expires_at as u64;
    let timestamp_u64 = transfer_timestamp as u64;
    assert(expires_u64 > timestamp_u64, "credential expired");
    
    // Constraint 4: Issuer in trusted tree (domain tag 0x02)
    let issuer_leaf_inputs: [Field; 2] = [Field::from(2u64), issuer_did];
    let issuer_leaf = pedersen_hash(issuer_leaf_inputs);
    
    let issuer_valid = verify_merkle_proof_10(issuer_leaf, issuer_tree_root, issuer_path_elements, issuer_path_indices);
    assert(issuer_valid, "issuer not in trusted tree");
    
    // Constraint 5: KYC tier in valid range [1, 3] (cast to u64)
    let kyc_u64 = kyc_tier as u64;
    assert(kyc_u64 >= 1, "kyc_tier too low");
    assert(kyc_u64 <= 3, "kyc_tier too high");
}

// ============================================================
// Sanctions Non-Membership (Gap Proof)
// ============================================================
fn check_sanctions_nonmembership(
    sanctions_root: Field,
    query_key: Field,
    left_key: Field,
    right_key: Field,
    left_path_elements: [Field; 20],
    left_path_indices: [Field; 20],
    right_path_elements: [Field; 20],
    right_path_indices: [Field; 20]
) {
    // Constraint 1: left_key < query_key (cast to u64)
    let left_u64 = left_key as u64;
    let query_u64 = query_key as u64;
    let right_u64 = right_key as u64;
    
    assert(left_u64 < query_u64, "left_key >= query_key");
    
    // Constraint 2: query_key < right_key
    assert(query_u64 < right_u64, "query_key >= right_key");
    
    // Constraint 3: Adjacency derived from path bits
    let mut left_index: Field = 0;
    let mut right_index: Field = 0;
    let mut pow2: Field = 1;
    
    for i in 0..20 {
        left_index = left_index + left_path_indices[i] * pow2;
        right_index = right_index + right_path_indices[i] * pow2;
        pow2 = pow2 * 2;
    }
    
    assert(right_index == left_index + 1, "leaves not adjacent");
    
    // Constraint 4: left_key is valid member
    let left_valid = verify_merkle_proof_20(left_key, sanctions_root, left_path_elements, left_path_indices);
    assert(left_valid, "left_key not in sanctions tree");
    
    // Constraint 5: right_key is valid member
    let right_valid = verify_merkle_proof_20(right_key, sanctions_root, right_path_elements, right_path_indices);
    assert(right_valid, "right_key not in sanctions tree");
}

// ============================================================
// Amount Tier Verification
// ============================================================
fn check_amount_tier(
    amount_tier: Field,
    tier2_threshold: Field,
    tier3_threshold: Field,
    tier4_threshold: Field,
    actual_amount: Field
) -> Field {
    // Cast to u64 for comparisons
    let tier_u64 = amount_tier as u64;
    let t2_u64 = tier2_threshold as u64;
    let t3_u64 = tier3_threshold as u64;
    let t4_u64 = tier4_threshold as u64;
    let amount_u64 = actual_amount as u64;
    
    // Constraint 1: Tier ordering
    assert(t2_u64 < t3_u64, "tier2 >= tier3");
    assert(t3_u64 < t4_u64, "tier3 >= tier4");
    
    // Constraint 2: Tier in valid range [1, 4]
    assert(tier_u64 >= 1, "tier too low");
    assert(tier_u64 <= 4, "tier too high");
    
    // Constraint 3: Compute expected tier
    let lt_tier2 = if amount_u64 < t2_u64 { 1 } else { 0 };
    let lt_tier3 = if amount_u64 < t3_u64 { 1 } else { 0 };
    let lt_tier4 = if amount_u64 < t4_u64 { 1 } else { 0 };
    
    let expected_tier = 4 - lt_tier2 - lt_tier3 - lt_tier4;
    assert(tier_u64 == expected_tier as u64, "wrong amount tier");
    
    // SAR review flag: 1 if tier >= 3
    let sar_review_flag = if tier_u64 >= 3 { 1 } else { 0 };
    
    Field::from(sar_review_flag as u64)
}

// ============================================================
// Main Compliance Circuit
// ============================================================
fn main(
    // Public inputs
    sanctions_tree_root: Field,
    issuer_tree_root: Field,
    amount_tier: Field,
    transfer_timestamp: Field,
    credential_commitment: Field,
    tier2_threshold: Field,
    tier3_threshold: Field,
    tier4_threshold: Field,
    
    // Private inputs: Credential
    issuer_did: Field,
    kyc_tier: Field,
    sanctions_clear: Field,
    issued_at: Field,
    expires_at: Field,
    issuer_path_elements: [Field; 10],
    issuer_path_indices: [Field; 10],
    
    // Private inputs: Sanctions
    wallet_address_hash: Field,
    left_key: Field,
    right_key: Field,
    left_path_elements: [Field; 20],
    left_path_indices: [Field; 20],
    right_path_elements: [Field; 20],
    right_path_indices: [Field; 20],
    
    // Private inputs: Amount
    actual_amount: Field
) -> pub Field {
    // Sub-circuit 1: Credential validity
    check_credential(
        credential_commitment,
        issuer_tree_root,
        transfer_timestamp,
        issuer_did,
        kyc_tier,
        sanctions_clear,
        issued_at,
        expires_at,
        issuer_path_elements,
        issuer_path_indices
    );
    
    // Sub-circuit 2: Sanctions non-membership
    check_sanctions_nonmembership(
        sanctions_tree_root,
        wallet_address_hash,
        left_key,
        right_key,
        left_path_elements,
        left_path_indices,
        right_path_elements,
        right_path_indices
    );
    
    // Sub-circuit 3: Amount tier
    let sar_review_flag = check_amount_tier(
        amount_tier,
        tier2_threshold,
        tier3_threshold,
        tier4_threshold,
        actual_amount
    );
    
    sar_review_flag
}

// ============================================================
// Test: Amount tier logic (standalone, no Merkle proofs needed)
// ============================================================

#[test]
fn test_amount_tier_1() {
    // Amount 10000 < tier2_threshold 25000 => tier 1
    let sar = check_amount_tier(
        Field::from(1u64),
        Field::from(25000u64),
        Field::from(300000u64),
        Field::from(1000000u64),
        Field::from(10000u64)
    );
    assert(sar == 0, "tier 1 should not flag SAR");
}

#[test]
fn test_amount_tier_2() {
    // Amount 100000 >= 25000 but < 300000 => tier 2
    let sar = check_amount_tier(
        Field::from(2u64),
        Field::from(25000u64),
        Field::from(300000u64),
        Field::from(1000000u64),
        Field::from(100000u64)
    );
    assert(sar == 0, "tier 2 should not flag SAR");
}

#[test]
fn test_amount_tier_3() {
    // Amount 500000 >= 300000 but < 1000000 => tier 3
    let sar = check_amount_tier(
        Field::from(3u64),
        Field::from(25000u64),
        Field::from(300000u64),
        Field::from(1000000u64),
        Field::from(500000u64)
    );
    assert(sar == 1, "tier 3 should flag SAR");
}

#[test]
fn test_amount_tier_4() {
    // Amount 2000000 >= 1000000 => tier 4
    let sar = check_amount_tier(
        Field::from(4u64),
        Field::from(25000u64),
        Field::from(300000u64),
        Field::from(1000000u64),
        Field::from(2000000u64)
    );
    assert(sar == 1, "tier 4 should flag SAR");
}

#[test(should_fail)]
fn test_wrong_tier_rejected() {
    // Claim tier 3 but amount is 100000 (should be tier 2)
    check_amount_tier(
        Field::from(3u64),
        Field::from(25000u64),
        Field::from(300000u64),
        Field::from(1000000u64),
        Field::from(100000u64)
    );
}

#[test(should_fail)]
fn test_inverted_thresholds_rejected() {
    // tier2 > tier3 should fail
    check_amount_tier(
        Field::from(1u64),
        Field::from(300000u64),
        Field::from(25000u64),
        Field::from(1000000u64),
        Field::from(10000u64)
    );
}

#[test(should_fail)]
fn test_tier_zero_rejected() {
    check_amount_tier(
        Field::from(0u64),
        Field::from(25000u64),
        Field::from(300000u64),
        Field::from(1000000u64),
        Field::from(10000u64)
    );
}

#[test(should_fail)]
fn test_tier_five_rejected() {
    check_amount_tier(
        Field::from(5u64),
        Field::from(25000u64),
        Field::from(300000u64),
        Field::from(1000000u64),
        Field::from(10000u64)
    );
}

// ============================================================
// Test: Credential validity (standalone)
// ============================================================

#[test]
fn test_credential_valid() {
    // Build a valid credential and verify it
    let issuer_did = Field::from(123456789u64);
    let kyc_tier = Field::from(2u64);
    let sanctions_clear = Field::from(1u64);
    let issued_at = Field::from(1700000000u64);
    let expires_at = Field::from(1800000000u64);
    let transfer_timestamp = Field::from(1711670400u64);
    
    let preimage: [Field; 5] = [issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at];
    let commitment = pedersen_hash(preimage);
    
    // Build a trivial issuer tree (depth 10, single issuer at index 0)
    let issuer_leaf_inputs: [Field; 2] = [Field::from(2u64), issuer_did];
    let issuer_leaf = pedersen_hash(issuer_leaf_inputs);
    
    // Build tree: all siblings are zero-hashes
    let mut path_elements: [Field; 10] = [0; 10];
    let path_indices: [Field; 10] = [0; 10];
    
    // Compute the root from the leaf
    let mut current = issuer_leaf;
    for i in 0..10 {
        let inputs: [Field; 2] = [current, Field::from(0u64)];
        current = pedersen_hash(inputs);
        path_elements[i] = Field::from(0u64); // sibling is zero-hash
    }
    let issuer_tree_root = current;
    
    // Recompute path_elements correctly
    let mut path_elements2: [Field; 10] = [0; 10];
    let mut cur = issuer_leaf;
    for i in 0..10 {
        // sibling at each level (right side since index=0)
        path_elements2[i] = Field::from(0u64);
        let inputs: [Field; 2] = [cur, Field::from(0u64)];
        cur = pedersen_hash(inputs);
    }
    
    check_credential(
        commitment,
        issuer_tree_root,
        transfer_timestamp,
        issuer_did,
        kyc_tier,
        sanctions_clear,
        issued_at,
        expires_at,
        path_elements2,
        path_indices
    );
}

#[test(should_fail)]
fn test_credential_expired() {
    let issuer_did = Field::from(123456789u64);
    let kyc_tier = Field::from(2u64);
    let sanctions_clear = Field::from(1u64);
    let issued_at = Field::from(1700000000u64);
    let expires_at = Field::from(1700000000u64); // expires_at == transfer_timestamp
    let transfer_timestamp = Field::from(1700000000u64);
    
    let preimage: [Field; 5] = [issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at];
    let commitment = pedersen_hash(preimage);
    
    check_credential(
        commitment,
        Field::from(0u64), // root doesn't matter, will fail on expiry first
        transfer_timestamp,
        issuer_did,
        kyc_tier,
        sanctions_clear,
        issued_at,
        expires_at,
        [0; 10],
        [0; 10]
    );
}

#[test(should_fail)]
fn test_credential_sanctions_clear_zero() {
    let issuer_did = Field::from(123456789u64);
    let kyc_tier = Field::from(2u64);
    let sanctions_clear = Field::from(0u64); // BAD
    let issued_at = Field::from(1700000000u64);
    let expires_at = Field::from(1800000000u64);
    let transfer_timestamp = Field::from(1711670400u64);
    
    let preimage: [Field; 5] = [issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at];
    let commitment = pedersen_hash(preimage);
    
    check_credential(
        commitment,
        Field::from(0u64),
        transfer_timestamp,
        issuer_did,
        kyc_tier,
        sanctions_clear,
        issued_at,
        expires_at,
        [0; 10],
        [0; 10]
    );
}

// ============================================================
// Test: Sanctions non-membership (standalone)
// ============================================================

#[test]
fn test_sanctions_gap_proof() {
    // Build a simple sorted tree with 2 leaves at indices 0 and 1
    let left_key = Field::from(100u64);
    let right_key = Field::from(200u64);
    let query_key = Field::from(150u64); // between left and right
    
    // Build tree of depth 20 with left at index 0, right at index 1
    let left_leaf = left_key;
    let right_leaf = right_key;
    
    // Level 0: hash(left, right)
    let pair_inputs: [Field; 2] = [left_leaf, right_leaf];
    let parent = pedersen_hash(pair_inputs);
    
    // Levels 1-19: hash(parent, 0) going up
    let mut left_path_elements: [Field; 20] = [0; 20];
    let mut left_path_indices: [Field; 20] = [0; 20];
    let mut right_path_elements: [Field; 20] = [0; 20];
    let mut right_path_indices: [Field; 20] = [0; 20];
    
    // Left is at index 0 (left child at level 0)
    left_path_elements[0] = right_leaf; // sibling is right_key
    left_path_indices[0] = Field::from(0u64); // left is left child
    
    // Right is at index 1 (right child at level 0)
    right_path_elements[0] = left_leaf; // sibling is left_key
    right_path_indices[0] = Field::from(1u64); // right is right child
    
    // For levels 1-19, both paths go left (index=0), sibling is 0
    let mut current = parent;
    for i in 1..20 {
        left_path_elements[i] = Field::from(0u64);
        left_path_indices[i] = Field::from(0u64);
        right_path_elements[i] = Field::from(0u64);
        right_path_indices[i] = Field::from(0u64);
        let inputs: [Field; 2] = [current, Field::from(0u64)];
        current = pedersen_hash(inputs);
    }
    let sanctions_root = current;
    
    check_sanctions_nonmembership(
        sanctions_root,
        query_key,
        left_key,
        right_key,
        left_path_elements,
        left_path_indices,
        right_path_elements,
        right_path_indices
    );
}

#[test(should_fail)]
fn test_sanctions_query_in_tree() {
    // query_key == left_key should fail (left_key < query_key is strict)
    let left_key = Field::from(100u64);
    let right_key = Field::from(200u64);
    let query_key = Field::from(100u64); // equal to left_key
    
    check_sanctions_nonmembership(
        Field::from(0u64),
        query_key,
        left_key,
        right_key,
        [0; 20],
        [0; 20],
        [0; 20],
        [0; 20]
    );
}

#[test(should_fail)]
fn test_sanctions_non_adjacent() {
    // left at index 0, right at index 2 (not adjacent) should fail
    let left_key = Field::from(100u64);
    let right_key = Field::from(300u64);
    let query_key = Field::from(200u64);
    
    let mut left_indices: [Field; 20] = [0; 20];
    let mut right_indices: [Field; 20] = [0; 20];
    left_indices[0] = Field::from(0u64); // index 0
    right_indices[0] = Field::from(0u64); // also index 0 at level 0
    right_indices[1] = Field::from(1u64); // but index 2 overall (binary: 10)
    
    check_sanctions_nonmembership(
        Field::from(0u64),
        query_key,
        left_key,
        right_key,
        [0; 20],
        left_indices,
        [0; 20],
        right_indices
    );
}
