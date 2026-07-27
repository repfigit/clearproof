// Main entry point for the compliance spike Noir circuit
// Single-file implementation for benchmarking purposes

// ============================================================
// Merkle proof verification using Poseidon hash
// ============================================================

/// Merkle membership proof verification
fn merkle_proof<let DEPTH: u32>(
    leaf: Field,
    root: Field,
    path_elements: [Field; DEPTH],
    path_indices: [Field; DEPTH],
) -> bool {
    let mut hashes: [Field; DEPTH + 1] = [0; DEPTH + 1];
    hashes[0] = leaf;

    for i in 0..DEPTH {
        // Constrain index bit to be binary
        assert(path_indices[i] * (1 - path_indices[i]) == 0);

        // Select child ordering based on path bit
        let left = if path_indices[i] == 0 { hashes[i] } else { path_elements[i] };
        let right = if path_indices[i] == 0 { path_elements[i] } else { hashes[i] };

        // Hash the ordered pair: Poseidon(left, right)
        hashes[i + 1] = std::hash::poseidon2::Poseidon2Hasher::hash_with_4_chunks([left, right, 0, 0]);
    }

    // Final computed root must equal the expected root
    hashes[DEPTH] == root
}

/// Domain-separated leaf hash for sanctions tree entries
fn sanctions_leaf_hash(key: Field) -> Field {
    std::hash::poseidon2::Poseidon2Hasher::hash_with_4_chunks([1, key, 0, 0])
}

/// Domain-separated leaf hash for issuer tree entries
fn issuer_leaf_hash(issuer_did: Field) -> Field {
    std::hash::poseidon2::Poseidon2Hasher::hash_with_4_chunks([2, issuer_did, 0, 0])
}

// ============================================================
// Sanctions non-membership proof via sorted-tree gap proof
// ============================================================

struct SanctionsNonMembershipInputs<let DEPTH: u32> {
    sanctions_root: Field,
    query_key: Field,
    left_key: Field,
    right_key: Field,
    left_path_elements: [Field; DEPTH],
    left_path_indices: [Field; DEPTH],
    right_path_elements: [Field; DEPTH],
    right_path_indices: [Field; DEPTH],
}

fn verify_sanctions_non_membership<let DEPTH: u32>(
    inputs: &SanctionsNonMembershipInputs<DEPTH>,
) -> bool {
    // Range check: all keys must be < 2^252 for LessThan soundness
    assert(inputs.left_key < 2^252);
    assert(inputs.query_key < 2^252);
    assert(inputs.right_key < 2^252);

    // Constraint 1: left_key < query_key (strict)
    assert(inputs.left_key < inputs.query_key);

    // Constraint 2: query_key < right_key (strict)
    assert(inputs.query_key < inputs.right_key);

    // Constraint 3: Adjacency derived from path bits
    let mut left_index: Field = 0;
    let mut right_index: Field = 0;
    let mut pow2: Field = 1;

    for i in 0..DEPTH {
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

    true
}

// ============================================================
// Credential validity circuit
// ============================================================

struct CredentialValidityInputs<let ISSUER_DEPTH: u32> {
    credential_commitment: Field,
    issuer_tree_root: Field,
    current_timestamp: Field,
    expected_jurisdiction: Field,
    issuer_did: Field,
    jurisdiction_code: Field,
    kyc_tier: Field,
    sanctions_clear: Field,
    issued_at: Field,
    expires_at: Field,
    issuer_path_elements: [Field; ISSUER_DEPTH],
    issuer_path_indices: [Field; ISSUER_DEPTH],
}

fn verify_credential_validity<let ISSUER_DEPTH: u32>(
    inputs: &CredentialValidityInputs<ISSUER_DEPTH>,
) -> bool {
    // Range checks
    assert(inputs.jurisdiction_code < 2^16);
    assert(inputs.expected_jurisdiction < 2^16);
    assert(inputs.kyc_tier < 4);
    assert(inputs.issued_at < 2^64);
    assert(inputs.expires_at < 2^64);
    assert(inputs.current_timestamp < 2^64);

    // Constraint 1: Credential commitment matches preimage hash
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

// ============================================================
// Amount tier verification circuit
// ============================================================

struct AmountTierInputs {
    amount_tier: Field,
    tier2_threshold: Field,
    tier3_threshold: Field,
    tier4_threshold: Field,
    actual_amount: Field,
}

struct AmountTierOutputs {
    sar_review_flag: Field,
}

fn verify_amount_tier(inputs: &AmountTierInputs) -> AmountTierOutputs {
    // Range checks
    assert(inputs.actual_amount < 2^64);
    assert(inputs.tier2_threshold < 2^64);
    assert(inputs.tier3_threshold < 2^64);
    assert(inputs.tier4_threshold < 2^64);
    assert(inputs.amount_tier < 8);

    // Constraint 1: amount_tier is in valid range [1, 4]
    assert(inputs.amount_tier >= 1);
    assert(inputs.amount_tier <= 4);

    // Constraint 2: Threshold ordering
    assert(inputs.tier2_threshold < inputs.tier3_threshold);
    assert(inputs.tier3_threshold < inputs.tier4_threshold);

    // Constraint 3: Tier encoding matches actual amount
    let lt_tier2 = if inputs.actual_amount < inputs.tier2_threshold { 1 } else { 0 };
    let lt_tier3 = if inputs.actual_amount < inputs.tier3_threshold { 1 } else { 0 };
    let lt_tier4 = if inputs.actual_amount < inputs.tier4_threshold { 1 } else { 0 };

    let expected_tier = 4 - lt_tier2 - lt_tier3 - lt_tier4;
    assert(inputs.amount_tier == expected_tier);

    // Constraint 4: SAR review flag
    let sar_review_flag = if inputs.amount_tier >= 3 { 1 } else { 0 };

    AmountTierOutputs { sar_review_flag }
}

// ============================================================
// Main compliance circuit orchestrator
// ============================================================

struct ComplianceInputs<let SANCTIONS_DEPTH: u32, let ISSUER_DEPTH: u32> {
    // Public inputs
    sanctions_tree_root: Field,
    issuer_tree_root: Field,
    amount_tier: Field,
    transfer_timestamp: Field,
    jurisdiction_code: Field,
    credential_commitment: Field,
    tier2_threshold: Field,
    tier3_threshold: Field,
    tier4_threshold: Field,
    domain_chain_id: Field,
    domain_contract_hash: Field,
    transfer_id_hash: Field,
    credential_nullifier: Field,
    proof_expires_at: Field,

    // Private inputs - credential
    issuer_did: Field,
    kyc_tier: Field,
    sanctions_clear: Field,
    issued_at: Field,
    expires_at: Field,
    issuer_path_elements: [Field; ISSUER_DEPTH],
    issuer_path_indices: [Field; ISSUER_DEPTH],

    // Private inputs - sanctions non-membership
    wallet_address_hash: Field,
    left_key: Field,
    right_key: Field,
    left_path_elements: [Field; SANCTIONS_DEPTH],
    left_path_indices: [Field; SANCTIONS_DEPTH],
    right_path_elements: [Field; SANCTIONS_DEPTH],
    right_path_indices: [Field; SANCTIONS_DEPTH],

    // Private inputs - amount tier
    actual_amount: Field,
}

struct ComplianceOutputs {
    is_compliant: Field,
    sar_review_flag: Field,
}

fn verify_compliance<let SANCTIONS_DEPTH: u32, let ISSUER_DEPTH: u32>(
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

// ============================================================
// Main function and tests
// ============================================================

/// Main function - entry point for the circuit
/// Instantiation: ComplianceProof(20, 10) — 20-level sanctions tree, 10-level issuer tree
fn main(inputs: ComplianceInputs<20, 10>) -> pub ComplianceOutputs {
    verify_compliance(&inputs)
}

#[test]
fn test_positive_case() {
    let inputs = test_positive_case_inputs();
    let outputs = verify_compliance(&inputs);
    assert(outputs.is_compliant == 1);
    assert(outputs.sar_review_flag == 0);
}

#[test(should_fail)]
fn test_expired_credential() {
    let mut inputs = test_positive_case_inputs();
    inputs.expires_at = 1700000000;
    verify_compliance(&inputs);
}

#[test(should_fail)]
fn test_sanctions_clear_zero() {
    let mut inputs = test_positive_case_inputs();
    inputs.sanctions_clear = 0;
    verify_compliance(&inputs);
}

#[test(should_fail)]
fn test_wrong_tier() {
    let mut inputs = test_positive_case_inputs();
    inputs.amount_tier = 3;
    verify_compliance(&inputs);
}

#[test(should_fail)]
fn test_jurisdiction_mismatch() {
    let mut inputs = test_positive_case_inputs();
    inputs.jurisdiction_code = 99999;
    verify_compliance(&inputs);
}

#[test]
fn test_sar_flag_tier3() {
    let mut inputs = test_positive_case_inputs();
    inputs.amount_tier = 3;
    inputs.actual_amount = 500000;
    let outputs = verify_compliance(&inputs);
    assert(outputs.sar_review_flag == 1);
}

#[test]
fn test_sar_flag_tier4() {
    let mut inputs = test_positive_case_inputs();
    inputs.amount_tier = 4;
    inputs.actual_amount = 2000000;
    let outputs = verify_compliance(&inputs);
    assert(outputs.sar_review_flag == 1);
}

fn test_positive_case_inputs() -> ComplianceInputs<20, 10> {
    ComplianceInputs {
        sanctions_tree_root: 19485189886927225448826174452960148901400409437721799234319594596150284213144,
        issuer_tree_root: 13669355367237519159663497518513536058941277231317989217194400446243591384968,
        amount_tier: 2,
        transfer_timestamp: 1711670400,
        jurisdiction_code: 21843,
        credential_commitment: 3946334516594870472864654055107878340628457451312090927820290073103136770198,
        tier2_threshold: 25000,
        tier3_threshold: 300000,
        tier4_threshold: 1000000,
        domain_chain_id: 1,
        domain_contract_hash: 12345,
        transfer_id_hash: 67890,
        credential_nullifier: 11111,
        proof_expires_at: 1711670500,
        issuer_did: 123456789,
        kyc_tier: 2,
        sanctions_clear: 1,
        issued_at: 1700000000,
        expires_at: 1800000000,
        issuer_path_elements: [
            0,
            14744269619966411208579211824598458697587494354926760081771325075741142829156,
            7423237065226347324353380772367382631490014989348495481811164164159255474657,
            11286972368698509976183087595462810875513684078608517520839298933882497716792,
            3607627140608796879659380071776844901612302623152076817094415224584923813162,
            19712377064642672829441595136074946683621277828620209496774504837737984048981,
            207756076730106271940145569684766066927294947151490278790710809376325639809,
            3396914609616007258851405644437304192397291162432396347162513310381425243293,
            21551820661461729022865262380882070649935529853313286572328683688269863701601,
            6573136701248752079028194407151022595060682063033565181951145966236778420039,
        ],
        issuer_path_indices: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        wallet_address_hash: 2570728153758525455068681255560397293445847326980545556667885052648074786431,
        left_key: 217234377348884654691879377518794323857294947151490278790710809376325639809,
        right_key: 4767571459625676338886140567802060826627379438215026793278462573473607028657,
        left_path_elements: [
            4767571459625676338886140567802060826627379438215026793278462573473607028657,
            14744269619966411208579211824598458697587494354926760081771325075741142829156,
            7423237065226347324353380772367382631490014989348495481811164164159255474657,
            11286972368698509976183087595462810875513684078608517520839298933882497716792,
            3607627140608796879659380071776844901612302623152076817094415224584923813162,
            19712377064642672829441595136074946683621277828620209496774504837737984048981,
            207756076730106271940145569684766066927294947151490278790710809376325639809,
            3396914609616007258851405644437304192397291162432396347162513310381425243293,
            21551820661461729022865262380882070649935529853313286572328683688269863701601,
            6573136701248752079028194407151022595060682063033565181951145966236778420039,
            12413880268183407374852357075976609371175688755676981206018884971008854919922,
            14271763308400718165336499097156975241954733520325982997864342600795471836726,
            20066985985293572387227381049700832219069292839614107140851619262827735677018,
            9394776414966240069580838672673694685292165040808226440647796406499139370960,
            11331146992410411304059858900317123658895005918277453009197229807340014528524,
            15819538789928229930262697811477882737253464456578333862691129291651619515538,
            19217088683336594659449020493828377907203207941212636669271704950158751593251,
            21035245323335827719745544373081896983162834604456827698288649288827293579666,
            6939770416153240137322503476966641397417391950902474480970945462551409848591,
            10941962436777715901943463195175331263348098796018438960955633645115732864202,
        ],
        left_path_indices: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        right_path_elements: [
            217234377348884654691879377518794323857294947151490278790710809376325639809,
            14744269619966411208579211824598458697587494354926760081771325075741142829156,
            7423237065226347324353380772367382631490014989348495481811164164159255474657,
            11286972368698509976183087595462810875513684078608517520839298933882497716792,
            3607627140608796879659380071776844901612302623152076817094415224584923813162,
            19712377064642672829441595136074946683621277828620209496774504837737984048981,
            207756076730106271940145569684766066927294947151490278790710809376325639809,
            3396914609616007258851405644437304192397291162432396347162513310381425243293,
            21551820661461729022865262380882070649935529853313286572328683688269863701601,
            6573136701248752079028194407151022595060682063033565181951145966236778420039,
            12413880268183407374852357075976609371175688755676981206018884971008854919922,
            14271763308400718165336499097156975241954733520325982997864342600795471836726,
            20066985985293572387227381049700832219069292839614107140851619262827735677018,
            9394776414966240069580838672673694685292165040808226440647796406499139370960,
            11331146992410411304059858900317123658895005918277453009197229807340014528524,
            15819538789928229930262697811477882737253464456578333862691129291651619515538,
            19217088683336594659449020493828377907203207941212636669271704950158751593251,
            21035245323335827719745544373081896983162834604456827698288649288827293579666,
            6939770416153240137322503476966641397417391950902474480970945462551409848591,
            10941962436777715901943463195175331263348098796018438960955633645115732864202,
        ],
        right_path_indices: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        actual_amount: 50000,
    }
}
