pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * Amount Tier Verification Circuit
 *
 * Proves that the claimed amount_tier is correctly assigned for the actual
 * transfer amount, without revealing the exact amount. Also outputs a SAR
 * (Suspicious Activity Report) review flag when tier >= 3.
 *
 * Jurisdiction-specific tier mapping (computed off-chain, verified here):
 *   Tier 1 (small):  amount < tier2_threshold   → full privacy
 *   Tier 2 (medium): tier2_threshold <= amount < tier3_threshold → compliance proof required
 *   Tier 3 (large):  tier3_threshold <= amount < tier4_threshold → Travel Rule mandatory
 *   Tier 4 (high):   amount >= tier4_threshold   → SAR review flag
 *
 * Example thresholds by jurisdiction:
 *   US (FinCEN):     $250 / $3,000 / $10,000
 *   EU (MiCA):       €250 / €1,000 / €10,000
 *   SG (MAS):        $250 / $1,500 / $10,000
 *   FATF Feb 2025:   $250 in 75+ jurisdictions
 *
 * PUBLIC INPUTS:
 *   - amount_tier: claimed tier (1, 2, 3, or 4)
 *   - jurisdiction_code: ISO 3166 country code as integer
 *
 * PRIVATE INPUTS:
 *   - actual_amount: the real transfer amount in USD cents (integer)
 *   - tier2_threshold: jurisdiction-specific boundary for tier 2 (in cents)
 *   - tier3_threshold: jurisdiction-specific boundary for tier 3 (in cents)
 *   - tier4_threshold: jurisdiction-specific boundary for tier 4 (in cents)
 *
 * PUBLIC OUTPUTS:
 *   - sar_review_flag: 1 if tier >= 3, else 0 (flags for human review)
 */

template AmountTier() {
    // PUBLIC INPUTS
    signal input amount_tier;          // Claimed tier (1-4)
    signal input jurisdiction_code;    // ISO 3166 country code as integer

    // PUBLIC OUTPUTS
    signal output sar_review_flag;     // 1 if tier >= 3, else 0

    // PRIVATE INPUTS
    signal input actual_amount;        // Actual transfer amount in USD cents
    signal input tier2_threshold;      // Jurisdiction-specific tier 2 boundary (cents)
    signal input tier3_threshold;      // Jurisdiction-specific tier 3 boundary (cents)
    signal input tier4_threshold;      // Jurisdiction-specific tier 4 boundary (cents)

    // --- CONSTRAINT 1: amount_tier is in the valid range [1, 4] ---
    component tier_gte_1 = GreaterEqThan(8);
    tier_gte_1.in[0] <== amount_tier;
    tier_gte_1.in[1] <== 1;
    tier_gte_1.out === 1;

    component tier_lte_4 = LessEqThan(8);
    tier_lte_4.in[0] <== amount_tier;
    tier_lte_4.in[1] <== 4;
    tier_lte_4.out === 1;

    // --- CONSTRAINT 2: Tier encoding matches the actual amount ---
    // Compare actual_amount against each threshold boundary.
    // LessThan outputs 1 if in[0] < in[1], else 0.
    //
    // For 64-bit comparators: sufficient for amounts up to ~1.8 * 10^19 cents.

    component lt_tier2 = LessThan(64);
    lt_tier2.in[0] <== actual_amount;
    lt_tier2.in[1] <== tier2_threshold;
    // lt_tier2.out == 1 means amount < tier2_threshold → tier should be 1

    component lt_tier3 = LessThan(64);
    lt_tier3.in[0] <== actual_amount;
    lt_tier3.in[1] <== tier3_threshold;
    // lt_tier3.out == 1 means amount < tier3_threshold → tier should be 1 or 2

    component lt_tier4 = LessThan(64);
    lt_tier4.in[0] <== actual_amount;
    lt_tier4.in[1] <== tier4_threshold;
    // lt_tier4.out == 1 means amount < tier4_threshold → tier should be 1, 2, or 3

    // Derive expected tier from the comparator outputs:
    //
    //   amount < tier2 < tier3 < tier4: lt2=1, lt3=1, lt4=1 → 4-3 = 1
    //   tier2 <= amount < tier3 < tier4: lt2=0, lt3=1, lt4=1 → 4-2 = 2
    //   tier3 <= amount < tier4:         lt2=0, lt3=0, lt4=1 → 4-1 = 3
    //   amount >= tier4:                 lt2=0, lt3=0, lt4=0 → 4-0 = 4
    //
    // Formula: expected_tier = 4 - lt_tier2.out - lt_tier3.out - lt_tier4.out
    signal expected_tier;
    expected_tier <== 4 - lt_tier2.out - lt_tier3.out - lt_tier4.out;

    // The claimed tier must match the computed expected tier
    amount_tier === expected_tier;

    // --- CONSTRAINT 3: SAR review flag ---
    // sar_review_flag = 1 when amount_tier >= 3 (tiers 3 and 4 require human review)
    component sar_check = GreaterEqThan(8);
    sar_check.in[0] <== amount_tier;
    sar_check.in[1] <== 3;
    sar_review_flag <== sar_check.out;
}
