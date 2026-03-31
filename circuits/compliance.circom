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
 *   - domain_chain_id: binds proof to a specific blockchain (e.g. 1=mainnet,
 *       11155111=Sepolia). Verifier checks this matches the on-chain chainid.
 *   - domain_contract_hash: binds proof to a specific ComplianceRegistry
 *       deployment (truncated keccak of contract address). Verifier checks this
 *       matches the deployed contract.
 *   - transfer_id_hash: binds proof to a specific transfer (keccak of
 *       transferId). Prevents the same proof from being submitted for a
 *       different transfer.
 *   - credential_nullifier: one-time-use nullifier derived from
 *       Poseidon(credential_commitment, transfer_id_hash). The contract stores
 *       used nullifiers to prevent proof reuse across transfers.
 *   - proof_expires_at: Unix timestamp after which this proof is invalid.
 *       Must be > transfer_timestamp (in-circuit constraint). The verifier
 *       contract checks proof_expires_at >= block.timestamp.
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

    // === PUBLIC INPUTS: Domain binding (prevent cross-chain replay) ===
    // domain_chain_id: Ethereum chain ID that this proof is bound to.
    // The verifier contract checks this matches block.chainid on-chain.
    // No in-circuit constraint needed — security comes from the contract check.
    signal input domain_chain_id;

    // domain_contract_hash: Truncated keccak256 of the ComplianceRegistry
    // contract address. The verifier checks this matches its own address hash.
    // No in-circuit constraint needed — security comes from the contract check.
    signal input domain_contract_hash;

    // transfer_id_hash: keccak256 of the transferId, binding this proof to
    // exactly one transfer. Prevents proof reuse across different transfers.
    signal input transfer_id_hash;

    // credential_nullifier: One-time-use nullifier = Poseidon(credential_commitment,
    // transfer_id_hash). The contract stores spent nullifiers to prevent replay.
    // Constrained in-circuit to match the Poseidon hash of the two inputs.
    signal input credential_nullifier;

    // proof_expires_at: Unix timestamp after which this proof is no longer valid.
    // Constrained in-circuit: must be strictly greater than transfer_timestamp.
    // The verifier contract checks proof_expires_at >= block.timestamp.
    signal input proof_expires_at;

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
    // DOMAIN BINDING: Credential Nullifier Verification
    // ================================================================
    // Constrain credential_nullifier === Poseidon(credential_commitment, transfer_id_hash).
    // This binds the nullifier to both the credential and the specific transfer,
    // so (a) each credential+transfer pair produces a unique nullifier, and
    // (b) the contract can reject replayed proofs by checking spent nullifiers.
    component nullifier_hash = Poseidon(2);
    nullifier_hash.inputs[0] <== credential_commitment;
    nullifier_hash.inputs[1] <== transfer_id_hash;
    credential_nullifier === nullifier_hash.out;

    // NOTE: domain_chain_id and domain_contract_hash are public inputs with
    // no in-circuit constraint. Their security model relies on the verifier
    // contract checking that these values match on-chain state (block.chainid
    // and address(this)). Making them public signals ensures they are included
    // in the proof and cannot be changed without invalidating it.

    // ================================================================
    // PROOF EXPIRATION: In-circuit validity check
    // ================================================================
    // Ensure proof_expires_at > transfer_timestamp (proof can't expire before
    // it was created). The verifier contract separately checks that
    // proof_expires_at >= block.timestamp (proof hasn't expired yet).
    // Uses 64-bit comparison — sufficient for Unix timestamps until year 2554.
    component expiry_check = GreaterThan(64);
    expiry_check.in[0] <== proof_expires_at;
    expiry_check.in[1] <== transfer_timestamp;
    expiry_check.out === 1;

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
    tier4_threshold,
    domain_chain_id,
    domain_contract_hash,
    transfer_id_hash,
    credential_nullifier,
    proof_expires_at
]} = ComplianceProof(20, 10);
