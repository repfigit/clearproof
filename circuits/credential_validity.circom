pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
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
 *
 * PUBLIC INPUTS (via parent circuit):
 *   - credential_commitment: expected Poseidon hash of credential fields
 *   - issuer_tree_root: Merkle root of trusted credential issuers
 *   - current_timestamp: Unix timestamp of the transfer
 *   - expected_jurisdiction: jurisdiction code the transfer claims
 *
 * PRIVATE INPUTS:
 *   - issuer_did: DID of the credential issuer (field element)
 *   - jurisdiction_code: ISO 3166 country code encoded as integer
 *   - kyc_tier: 1, 2, or 3
 *   - issued_at: Unix timestamp when credential was issued
 *   - expires_at: Unix timestamp when credential expires
 *   - issuer_path_elements[]: Merkle path siblings for issuer membership
 *   - issuer_path_indices[]:  Merkle path direction bits
 *
 * Credential commitment scheme:
 *   commitment = Poseidon(issuer_did, jurisdiction_code, kyc_tier, issued_at, expires_at)
 *
 * Issuer leaf hashing uses domain separation:
 *   issuer_leaf = Poseidon(0x02, issuer_did)
 *   where 0x02 is the domain tag for issuer leaves
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
    signal input issued_at;               // Unix timestamp of issuance
    signal input expires_at;              // Unix timestamp of expiration

    // PRIVATE INPUTS — issuer Merkle membership proof
    signal input issuer_path_elements[issuer_tree_depth];
    signal input issuer_path_indices[issuer_tree_depth];

    // --- CONSTRAINT 1: Credential commitment matches preimage hash ---
    // commitment = Poseidon(issuer_did, jurisdiction_code, kyc_tier, issued_at, expires_at)
    component commit_hash = Poseidon(5);
    commit_hash.inputs[0] <== issuer_did;
    commit_hash.inputs[1] <== jurisdiction_code;
    commit_hash.inputs[2] <== kyc_tier;
    commit_hash.inputs[3] <== issued_at;
    commit_hash.inputs[4] <== expires_at;

    // Hard constraint: computed hash must equal the public commitment
    credential_commitment === commit_hash.out;

    // --- CONSTRAINT 2: Credential is not expired ---
    // expires_at must be strictly greater than the transfer timestamp.
    // Uses 64-bit comparator (sufficient for Unix timestamps through year 2554).
    component not_expired = GreaterThan(64);
    not_expired.in[0] <== expires_at;
    not_expired.in[1] <== current_timestamp;
    not_expired.out === 1;

    // --- CONSTRAINT 3: Issuer is in the trusted issuer set (Merkle membership) ---
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

    // --- CONSTRAINT 4: Jurisdiction matches the expected jurisdiction ---
    // The jurisdiction encoded in the credential must match the transfer's jurisdiction
    expected_jurisdiction === jurisdiction_code;

    // --- CONSTRAINT 5: KYC tier is valid (1, 2, or 3) ---
    component tier_gte_1 = GreaterEqThan(8);
    tier_gte_1.in[0] <== kyc_tier;
    tier_gte_1.in[1] <== 1;
    tier_gte_1.out === 1;

    component tier_lte_3 = LessEqThan(8);
    tier_lte_3.in[0] <== kyc_tier;
    tier_lte_3.in[1] <== 3;
    tier_lte_3.out === 1;
}
