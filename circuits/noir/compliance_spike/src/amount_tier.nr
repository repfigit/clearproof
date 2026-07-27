// Amount tier verification circuit
// Mirrors circuits/amount_tier.circom
//
// Proves that the claimed amount_tier is correctly assigned for the actual
// transfer amount. Also outputs a SAR review flag when tier >= 3.

use dep::std;

/// Amount tier inputs
pub struct AmountTierInputs {
    pub amount_tier: Field,
    pub tier2_threshold: Field,
    pub tier3_threshold: Field,
    pub tier4_threshold: Field,
    pub actual_amount: Field,
}

/// Amount tier outputs
pub struct AmountTierOutputs {
    pub sar_review_flag: Field,
}

/// Verify amount tier assignment
///
/// Constraints:
/// 1. amount_tier in [1, 4]
/// 2. tier2 < tier3 < tier4 (threshold ordering)
/// 3. Tier encoding matches actual amount
/// 4. SAR flag = 1 if tier >= 3
pub fn verify_amount_tier(inputs: &AmountTierInputs) -> AmountTierOutputs {
    // Range checks
    // 64-bit is sufficient for USD cent amounts
    assert(inputs.actual_amount < 2^64);
    assert(inputs.tier2_threshold < 2^64);
    assert(inputs.tier3_threshold < 2^64);
    assert(inputs.tier4_threshold < 2^64);

    // amount_tier fits in 3 bits (max value 7, constrained to [1,4] below)
    assert(inputs.amount_tier < 8);

    // Constraint 1: amount_tier is in valid range [1, 4]
    assert(inputs.amount_tier >= 1);
    assert(inputs.amount_tier <= 4);

    // Constraint 2: Threshold ordering
    assert(inputs.tier2_threshold < inputs.tier3_threshold);
    assert(inputs.tier3_threshold < inputs.tier4_threshold);

    // Constraint 3: Tier encoding matches actual amount
    // Derive expected tier:
    //   amount < t2 < t3 < t4: lt2=1, lt3=1, lt4=1 → 4-3 = 1
    //   t2 ≤ amount < t3 < t4: lt2=0, lt3=1, lt4=1 → 4-2 = 2
    //   t3 ≤ amount < t4:      lt2=0, lt3=0, lt4=1 → 4-1 = 3
    //   amount ≥ t4:           lt2=0, lt3=0, lt4=0 → 4-0 = 4
    let lt_tier2 = if inputs.actual_amount < inputs.tier2_threshold { 1 } else { 0 };
    let lt_tier3 = if inputs.actual_amount < inputs.tier3_threshold { 1 } else { 0 };
    let lt_tier4 = if inputs.actual_amount < inputs.tier4_threshold { 1 } else { 0 };

    let expected_tier = 4 - lt_tier2 - lt_tier3 - lt_tier4;
    assert(inputs.amount_tier == expected_tier);

    // Constraint 4: SAR review flag
    let sar_review_flag = if inputs.amount_tier >= 3 { 1 } else { 0 };

    AmountTierOutputs { sar_review_flag }
}
