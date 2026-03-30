pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./lib/merkle_tree.circom";
include "./sanctions_nonmembership.circom";
include "./credential_validity.circom";
include "./amount_tier.circom";

/*
 * Main Compliance Circuit — ZK Travel Rule Compliance Bridge
 *
 * Composes all subcircuits to prove the following statements simultaneously
 * without revealing any private inputs:
 *
 * PROVEN STATEMENTS:
 *   1. Credential commitment matches Poseidon hash of preimage fields
 *   2. Credential is not expired (expires_at > transfer_timestamp)
 *   3. Issuer is in the trusted issuer Merkle tree
 *   4. Jurisdiction in credential matches the transfer jurisdiction
 *   5. sanctions_clear flag in credential is true
 *   6. Wallet address hash is NOT in the sanctions Merkle tree (gap proof)
 *   7. Amount tier is correctly assigned for the actual amount
 *   8. SAR review flag is set when tier >= 3
 *
 * PUBLIC INPUTS:
 *   - sanctions_tree_root: Merkle root of current OFAC/UN/EU sanctions list
 *   - issuer_tree_root: Merkle root of trusted credential issuers
 *   - amount_tier: 1, 2, 3, or 4 (not the exact amount)
 *   - transfer_timestamp: Unix timestamp of the transfer
 *   - jurisdiction_code: ISO 3166 country code encoded as integer
 *   - credential_commitment: expected Poseidon hash of credential fields
 *   - tier2_threshold: jurisdiction-specific tier 2 boundary (verifier-supplied)
 *   - tier3_threshold: jurisdiction-specific tier 3 boundary (verifier-supplied)
 *   - tier4_threshold: jurisdiction-specific tier 4 boundary (verifier-supplied)
 *
 * PUBLIC OUTPUTS:
 *   - is_compliant: 1 if all checks pass
 *   - sar_review_flag: 1 if tier >= 3 (flags for human review)
 *
 * Merkle tree depths:
 *   - Sanctions tree: parameterized, default 20 (~1M entries)
 *   - Issuer tree: parameterized, default 10 (~1K entries)
 */

template ComplianceProof(sanctions_tree_depth, issuer_tree_depth) {
    // === PUBLIC INPUTS ===
    signal input sanctions_tree_root;
    signal input issuer_tree_root;
    signal input amount_tier;
    signal input transfer_timestamp;
    signal input jurisdiction_code;
    signal input credential_commitment;
    // Thresholds are PUBLIC (verifier-supplied) — audit fix #3
    signal input tier2_threshold;
    signal input tier3_threshold;
    signal input tier4_threshold;

    // === PUBLIC OUTPUTS ===
    signal output is_compliant;
    signal output sar_review_flag;

    // === PRIVATE INPUTS: Credential preimage ===
    signal input issuer_did;
    signal input kyc_tier;
    signal input sanctions_clear;      // Must be 1 — audit fix #5
    signal input issued_at;
    signal input expires_at;

    // === PRIVATE INPUTS: Issuer Merkle membership proof ===
    signal input issuer_path_elements[issuer_tree_depth];
    signal input issuer_path_indices[issuer_tree_depth];

    // === PRIVATE INPUTS: Sanctions non-membership (gap proof) ===
    signal input wallet_address_hash;
    signal input left_key;
    signal input right_key;
    signal input left_path_elements[sanctions_tree_depth];
    signal input left_path_indices[sanctions_tree_depth];
    signal input right_path_elements[sanctions_tree_depth];
    signal input right_path_indices[sanctions_tree_depth];
    // NOTE: left_index/right_index removed — now derived from path bits (audit fix #1)

    // === PRIVATE INPUTS: Amount tier verification ===
    signal input actual_amount;

    // ================================================================
    // SUB-CIRCUIT 1: Credential Validity
    // ================================================================
    component cred_check = CredentialValidity(issuer_tree_depth);
    cred_check.credential_commitment <== credential_commitment;
    cred_check.issuer_tree_root <== issuer_tree_root;
    cred_check.current_timestamp <== transfer_timestamp;
    cred_check.expected_jurisdiction <== jurisdiction_code;
    cred_check.issuer_did <== issuer_did;
    cred_check.jurisdiction_code <== jurisdiction_code;
    cred_check.kyc_tier <== kyc_tier;
    cred_check.sanctions_clear <== sanctions_clear;  // Audit fix #5: explicit input
    cred_check.issued_at <== issued_at;
    cred_check.expires_at <== expires_at;
    for (var i = 0; i < issuer_tree_depth; i++) {
        cred_check.issuer_path_elements[i] <== issuer_path_elements[i];
        cred_check.issuer_path_indices[i] <== issuer_path_indices[i];
    }

    // ================================================================
    // SUB-CIRCUIT 2: Sanctions Non-Membership
    // ================================================================
    component sanctions_check = SanctionsNonMembership(sanctions_tree_depth);
    sanctions_check.sanctions_root <== sanctions_tree_root;
    sanctions_check.query_key <== wallet_address_hash;
    sanctions_check.left_key <== left_key;
    sanctions_check.right_key <== right_key;
    for (var i = 0; i < sanctions_tree_depth; i++) {
        sanctions_check.left_path_elements[i] <== left_path_elements[i];
        sanctions_check.left_path_indices[i] <== left_path_indices[i];
        sanctions_check.right_path_elements[i] <== right_path_elements[i];
        sanctions_check.right_path_indices[i] <== right_path_indices[i];
    }
    // Adjacency now derived from path bits internally (audit fix #1)

    // ================================================================
    // SUB-CIRCUIT 3: Amount Tier Verification
    // ================================================================
    component tier_check = AmountTier();
    tier_check.amount_tier <== amount_tier;
    // Thresholds are public inputs (audit fix #3)
    tier_check.tier2_threshold <== tier2_threshold;
    tier_check.tier3_threshold <== tier3_threshold;
    tier_check.tier4_threshold <== tier4_threshold;
    tier_check.actual_amount <== actual_amount;

    // Wire SAR review flag from tier subcircuit to output
    sar_review_flag <== tier_check.sar_review_flag;

    // ================================================================
    // COMPLIANCE OUTPUT
    // ================================================================
    // If execution reaches this point without a constraint failure, all
    // subcircuit checks have passed. The circuit will abort (unsatisfied
    // constraint) if any check fails, so reaching here means full compliance.
    is_compliant <== 1;
}

// Default instantiation:
//   - 20-level sanctions tree (~1M entries, sufficient for OFAC + UN + EU lists)
//   - 10-level issuer tree (~1K trusted issuers)
component main {public [
    sanctions_tree_root,
    issuer_tree_root,
    amount_tier,
    transfer_timestamp,
    jurisdiction_code,
    credential_commitment,
    tier2_threshold,
    tier3_threshold,
    tier4_threshold
]} = ComplianceProof(20, 10);
