pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * Amount Tier Verification Circuit
 *
 * Proves that the claimed amount_tier is correctly assigned for the actual
 * transfer amount, without revealing the exact amount. Also outputs a SAR
 * (Suspicious Activity Report) review flag when tier >= 3.
 *
 * SOUNDNESS NOTES:
 *   - Audit fix #3: Thresholds are now PUBLIC INPUTS, not private.
 *     The verifier supplies jurisdiction-specific thresholds — the prover
 *     cannot manipulate them to get a favorable tier.
 *   - Audit fix #4: jurisdiction_code removed (was unused in constraints).
 *     Jurisdiction-specific behavior is enforced by the verifier choosing
 *     the correct threshold values as public inputs.
 *   - Audit fix #9: Threshold ordering is now enforced in-circuit
 *     (tier2 < tier3 < tier4).
 *   - Audit fix #10/#12: amount_tier and thresholds are range-checked
 *     via Num2Bits before being passed to comparators.
 *
 * PUBLIC INPUTS:
 *   - amount_tier: claimed tier (1, 2, 3, or 4)
 *   - tier2_threshold: jurisdiction-specific boundary for tier 2 (cents)
 *   - tier3_threshold: jurisdiction-specific boundary for tier 3 (cents)
 *   - tier4_threshold: jurisdiction-specific boundary for tier 4 (cents)
 *
 * PRIVATE INPUTS:
 *   - actual_amount: the real transfer amount in USD cents (integer)
 *
 * PUBLIC OUTPUTS:
 *   - sar_review_flag: 1 if tier >= 3, else 0 (flags for human review)
 */

template AmountTier() {
    // PUBLIC INPUTS (Audit fix #3: thresholds are verifier-supplied)
    signal input amount_tier;
    signal input tier2_threshold;
    signal input tier3_threshold;
    signal input tier4_threshold;

    // PUBLIC OUTPUTS
    signal output sar_review_flag;

    // PRIVATE INPUTS
    signal input actual_amount;

    // === RANGE CHECKS (Audit fix #10/#12) ===
    // Range-check all values to ensure comparators are sound.
    // 64-bit is sufficient for USD cent amounts up to ~1.8 * 10^19.
    component range_amount = Num2Bits(64);
    range_amount.in <== actual_amount;

    component range_t2 = Num2Bits(64);
    range_t2.in <== tier2_threshold;

    component range_t3 = Num2Bits(64);
    range_t3.in <== tier3_threshold;

    component range_t4 = Num2Bits(64);
    range_t4.in <== tier4_threshold;

    // Range-check amount_tier to 3 bits (max value 7, but constrained to [1,4] below)
    component range_tier = Num2Bits(3);
    range_tier.in <== amount_tier;

    // === CONSTRAINT 1: amount_tier is in the valid range [1, 4] ===
    // After Num2Bits(3), amount_tier is guaranteed < 8.
    // Now enforce [1, 4] with safe 3-bit comparators.
    component tier_gte_1 = GreaterEqThan(3);
    tier_gte_1.in[0] <== amount_tier;
    tier_gte_1.in[1] <== 1;
    tier_gte_1.out === 1;

    component tier_lte_4 = LessEqThan(3);
    tier_lte_4.in[0] <== amount_tier;
    tier_lte_4.in[1] <== 4;
    tier_lte_4.out === 1;

    // === CONSTRAINT 2: Threshold ordering (Audit fix #9) ===
    // tier2_threshold < tier3_threshold < tier4_threshold
    // Prevents malicious verifier from supplying inverted thresholds.
    component t2_lt_t3 = LessThan(64);
    t2_lt_t3.in[0] <== tier2_threshold;
    t2_lt_t3.in[1] <== tier3_threshold;
    t2_lt_t3.out === 1;

    component t3_lt_t4 = LessThan(64);
    t3_lt_t4.in[0] <== tier3_threshold;
    t3_lt_t4.in[1] <== tier4_threshold;
    t3_lt_t4.out === 1;

    // === CONSTRAINT 3: Tier encoding matches the actual amount ===
    component lt_tier2 = LessThan(64);
    lt_tier2.in[0] <== actual_amount;
    lt_tier2.in[1] <== tier2_threshold;

    component lt_tier3 = LessThan(64);
    lt_tier3.in[0] <== actual_amount;
    lt_tier3.in[1] <== tier3_threshold;

    component lt_tier4 = LessThan(64);
    lt_tier4.in[0] <== actual_amount;
    lt_tier4.in[1] <== tier4_threshold;

    // Derive expected tier:
    //   amount < t2 < t3 < t4: lt2=1, lt3=1, lt4=1 → 4-3 = 1
    //   t2 ≤ amount < t3 < t4: lt2=0, lt3=1, lt4=1 → 4-2 = 2
    //   t3 ≤ amount < t4:      lt2=0, lt3=0, lt4=1 → 4-1 = 3
    //   amount ≥ t4:           lt2=0, lt3=0, lt4=0 → 4-0 = 4
    signal expected_tier;
    expected_tier <== 4 - lt_tier2.out - lt_tier3.out - lt_tier4.out;

    amount_tier === expected_tier;

    // === CONSTRAINT 4: SAR review flag ===
    // After range check, amount_tier is guaranteed < 8, so 3-bit comparator is safe.
    component sar_check = GreaterEqThan(3);
    sar_check.in[0] <== amount_tier;
    sar_check.in[1] <== 3;
    sar_review_flag <== sar_check.out;
}
