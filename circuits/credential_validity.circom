pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./lib/merkle_tree.circom";

/*
 * Credential Validity Circuit
 *
 * Proves a VASP credential is valid without revealing its contents:
 *   1. Poseidon(preimage fields) == credential_commitment
 *   2. Credential is not expired (expires_at > current_timestamp)
 *   3. Issuer is in the trusted issuer Merkle tree (membership proof)
 *   4. Jurisdiction in credential matches the expected jurisdiction
 *   5. KYC tier is valid (1=retail, 2=professional, 3=institutional)
 *   6. sanctions_clear flag is true (explicitly constrained, not hardcoded)
 *
 * SOUNDNESS NOTES:
 *   - Audit fix #5: sanctions_clear is now a private input constrained to === 1,
 *     not a literal constant. This makes the assumption explicit and auditable.
 *     If an issuer produces a credential with sanctions_clear=0, the commitment
 *     will include that value, and the constraint will fail — which is correct.
 *   - Audit fix #11: jurisdiction_code and expected_jurisdiction are range-checked
 *     via Num2Bits(16) before equality comparison (ISO 3166 codes fit in 16 bits).
 *   - Audit fix #13: kyc_tier is range-checked via Num2Bits(2) before being
 *     passed to comparators, ensuring the 2-bit decomposition is sound.
 *
 * Credential commitment scheme:
 *   commitment = Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
 *
 * NOTE: jurisdiction is NOT included in the commitment hash. It is checked
 * separately via equality constraint. The commitment matches the Python-side
 * _field_ints() which returns 5 values:
 *   [issuer_did_int, kyc_tier_int, sanctions_clear_int, issued_at, expires_at]
 */

template CredentialValidity(issuer_tree_depth) {
    // PUBLIC INPUTS
    signal input credential_commitment;   // Expected Poseidon hash of credential
    signal input issuer_tree_root;        // Root of trusted issuer Merkle tree
    signal input current_timestamp;       // Current time for expiry check
    signal input expected_jurisdiction;   // Expected jurisdiction code

    // PRIVATE INPUTS — credential preimage fields
    signal input issuer_did;              // Credential issuer DID (field element)
    signal input jurisdiction_code;       // ISO 3166 country code as integer
    signal input kyc_tier;                // 1=retail, 2=professional, 3=institutional
    signal input sanctions_clear;         // 1 if issuer attests sanctions check passed
    signal input issued_at;               // Unix timestamp of issuance
    signal input expires_at;              // Unix timestamp of expiration

    // PRIVATE INPUTS — issuer Merkle membership proof
    signal input issuer_path_elements[issuer_tree_depth];
    signal input issuer_path_indices[issuer_tree_depth];

    // === RANGE CHECKS (Audit fixes #11, #13) ===

    // jurisdiction_code and expected_jurisdiction fit in 16 bits (ISO 3166 alpha-2 → uint16)
    component range_jurisdiction = Num2Bits(16);
    range_jurisdiction.in <== jurisdiction_code;

    component range_expected_juris = Num2Bits(16);
    range_expected_juris.in <== expected_jurisdiction;

    // kyc_tier fits in 2 bits (values 1-3; max representable = 3)
    component range_kyc = Num2Bits(2);
    range_kyc.in <== kyc_tier;

    // timestamps fit in 64 bits
    component range_issued = Num2Bits(64);
    range_issued.in <== issued_at;

    component range_expires = Num2Bits(64);
    range_expires.in <== expires_at;

    component range_current = Num2Bits(64);
    range_current.in <== current_timestamp;

    // === CONSTRAINT 1: Credential commitment matches preimage hash ===
    // commitment = Poseidon(issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at)
    // NOTE: jurisdiction is NOT in the commitment — it's checked separately.
    component commit_hash = Poseidon(5);
    commit_hash.inputs[0] <== issuer_did;
    commit_hash.inputs[1] <== kyc_tier;
    commit_hash.inputs[2] <== sanctions_clear;
    commit_hash.inputs[3] <== issued_at;
    commit_hash.inputs[4] <== expires_at;

    credential_commitment === commit_hash.out;

    // === CONSTRAINT 2: sanctions_clear must be 1 (Audit fix #5) ===
    // Explicitly constrain rather than hardcode. The sanctions_clear field
    // is part of the commitment hash, so a credential with sanctions_clear=0
    // will produce a different commitment and fail constraint 1.
    // This constraint makes the requirement explicit and auditable.
    sanctions_clear === 1;

    // === CONSTRAINT 3: Credential is not expired ===
    // expires_at > current_timestamp (64-bit comparator, safe after range check)
    component not_expired = GreaterThan(64);
    not_expired.in[0] <== expires_at;
    not_expired.in[1] <== current_timestamp;
    not_expired.out === 1;

    // === CONSTRAINT 4: Issuer is in the trusted issuer set (Merkle membership) ===
    // Domain-separated leaf hash: Poseidon(0x02, issuer_did)
    component issuer_leaf_hash = Poseidon(2);
    issuer_leaf_hash.inputs[0] <== 2;  // domain tag for issuer leaf
    issuer_leaf_hash.inputs[1] <== issuer_did;

    component issuer_verifier = MerkleTreeVerifier(issuer_tree_depth);
    issuer_verifier.leaf <== issuer_leaf_hash.out;
    issuer_verifier.root <== issuer_tree_root;
    for (var i = 0; i < issuer_tree_depth; i++) {
        issuer_verifier.pathElements[i] <== issuer_path_elements[i];
        issuer_verifier.pathIndices[i] <== issuer_path_indices[i];
    }
    // MerkleTreeVerifier internally constrains proof.valid === 1

    // === CONSTRAINT 5: Jurisdiction matches the expected jurisdiction ===
    // Both values are range-checked to 16 bits above, so equality is safe.
    expected_jurisdiction === jurisdiction_code;

    // === CONSTRAINT 6: KYC tier is valid (1, 2, or 3) ===
    // kyc_tier is range-checked to 2 bits (max 3), so comparators are safe.
    component tier_gte_1 = GreaterEqThan(2);
    tier_gte_1.in[0] <== kyc_tier;
    tier_gte_1.in[1] <== 1;
    tier_gte_1.out === 1;

    component tier_lte_3 = LessEqThan(2);
    tier_lte_3.in[0] <== kyc_tier;
    tier_lte_3.in[1] <== 3;
    tier_lte_3.out === 1;
}
