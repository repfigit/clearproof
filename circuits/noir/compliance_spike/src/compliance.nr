// Main compliance circuit orchestrator
// Mirrors circuits/compliance.circom
//
// Composes all subcircuits to prove:
// 1. Credential commitment matches Poseidon hash of preimage fields
// 2. Credential is not expired
// 3. Issuer is in the trusted issuer Merkle tree
// 4. Jurisdiction matches
// 5. sanctions_clear flag is 1
// 6. Wallet address hash is NOT in the sanctions Merkle tree (gap proof)
// 7. Amount tier is correctly assigned
// 8. SAR review flag is set when tier >= 3

use dep::std;
use crate::sanctions_nonmembership::{SanctionsNonMembershipInputs, verify_sanctions_non_membership};
use crate::credential_validity::{CredentialValidityInputs, verify_credential_validity};
use crate::amount_tier::{AmountTierInputs, AmountTierOutputs, verify_amount_tier};

/// Compliance proof inputs
pub struct ComplianceInputs<let SANCTIONS_DEPTH: u32, let ISSUER_DEPTH: u32> {
    // Public inputs
    pub sanctions_tree_root: Field,
    pub issuer_tree_root: Field,
    pub amount_tier: Field,
    pub transfer_timestamp: Field,
    pub jurisdiction_code: Field,
    pub credential_commitment: Field,
    pub tier2_threshold: Field,
    pub tier3_threshold: Field,
    pub tier4_threshold: Field,
    pub domain_chain_id: Field,
    pub domain_contract_hash: Field,
    pub transfer_id_hash: Field,
    pub credential_nullifier: Field,
    pub proof_expires_at: Field,

    // Private inputs - credential
    pub issuer_did: Field,
    pub kyc_tier: Field,
    pub sanctions_clear: Field,
    pub issued_at: Field,
    pub expires_at: Field,
    pub issuer_path_elements: [Field; ISSUER_DEPTH],
    pub issuer_path_indices: [Field; ISSUER_DEPTH],

    // Private inputs - sanctions non-membership
    pub wallet_address_hash: Field,
    pub left_key: Field,
    pub right_key: Field,
    pub left_path_elements: [Field; SANCTIONS_DEPTH],
    pub left_path_indices: [Field; SANCTIONS_DEPTH],
    pub right_path_elements: [Field; SANCTIONS_DEPTH],
    pub right_path_indices: [Field; SANCTIONS_DEPTH],

    // Private inputs - amount tier
    pub actual_amount: Field,
}

/// Compliance proof outputs
pub struct ComplianceOutputs {
    pub is_compliant: Field,
    pub sar_review_flag: Field,
}

/// Main compliance proof verification
pub fn verify_compliance<let SANCTIONS_DEPTH: u32, let ISSUER_DEPTH: u32>(
    inputs: &ComplianceInputs<SANCTIONS_DEPTH, ISSUER_DEPTH>,
) -> ComplianceOutputs {
    // Constraint: proof_expires_at > transfer_timestamp
    assert(inputs.proof_expires_at > inputs.transfer_timestamp);

    // 1. Verify credential validity
    let credential_inputs = CredentialValidityInputs {
        credential_commitment: inputs.credential_commitment,
        issuer_tree_root: inputs.issuer_tree_root,
        current_timestamp: inputs.transfer_timestamp,
        expected_jurisdiction: inputs.jurisdiction_code,
        issuer_did: inputs.issuer_did,
        jurisdiction_code: inputs.jurisdiction_code,
        kyc_tier: inputs.kyc_tier,
        sanctions_clear: inputs.sanctions_clear,
        issued_at: inputs.issued_at,
        expires_at: inputs.expires_at,
        issuer_path_elements: inputs.issuer_path_elements,
        issuer_path_indices: inputs.issuer_path_indices,
    };
    verify_credential_validity(&credential_inputs);

    // 2. Verify sanctions non-membership
    let sanctions_inputs = SanctionsNonMembershipInputs {
        sanctions_root: inputs.sanctions_tree_root,
        query_key: inputs.wallet_address_hash,
        left_key: inputs.left_key,
        right_key: inputs.right_key,
        left_path_elements: inputs.left_path_elements,
        left_path_indices: inputs.left_path_indices,
        right_path_elements: inputs.right_path_elements,
        right_path_indices: inputs.right_path_indices,
    };
    verify_sanctions_non_membership(&sanctions_inputs);

    // 3. Verify amount tier
    let amount_inputs = AmountTierInputs {
        amount_tier: inputs.amount_tier,
        tier2_threshold: inputs.tier2_threshold,
        tier3_threshold: inputs.tier3_threshold,
        tier4_threshold: inputs.tier4_threshold,
        actual_amount: inputs.actual_amount,
    };
    let amount_outputs = verify_amount_tier(&amount_inputs);

    // All checks passed
    ComplianceOutputs {
        is_compliant: 1,
        sar_review_flag: amount_outputs.sar_review_flag,
    }
}
