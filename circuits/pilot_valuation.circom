pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Multiply two unsigned 128-bit integers into four little-endian 64-bit
// limbs. Every multiplication is <=128 bits and intermediate sum <=129
// bits: no constraint relies on a 256-bit product reduced modulo BN254.
template PilotMultiply128() {
    signal input a;
    signal input b;
    signal output limbs[4];
    component a_bits = Num2Bits(128);
    component b_bits = Num2Bits(128);
    a_bits.in <== a;
    b_bits.in <== b;
    signal av[2];
    signal bv[2];
    for (var part = 0; part < 2; part++) {
        var al = 0;
        var bl = 0;
        for (var bit = 0; bit < 64; bit++) {
            al += a_bits.out[part*64+bit] * (2**bit);
            bl += b_bits.out[part*64+bit] * (2**bit);
        }
        av[part] <== al;
        bv[part] <== bl;
    }
    signal products[4];
    products[0] <== av[0] * bv[0];
    products[1] <== av[0] * bv[1];
    products[2] <== av[1] * bv[0];
    products[3] <== av[1] * bv[1];
    signal carry[2];
    signal middle;
    signal high;
    limbs[0] <-- products[0] % (2**64);
    carry[0] <-- products[0] \ (2**64);
    products[0] === limbs[0] + carry[0] * (2**64);
    middle <== products[1] + products[2] + carry[0];
    limbs[1] <-- middle % (2**64);
    carry[1] <-- middle \ (2**64);
    middle === limbs[1] + carry[1] * (2**64);
    high <== products[3] + carry[1];
    limbs[2] <-- high % (2**64);
    limbs[3] <-- high \ (2**64);
    high === limbs[2] + limbs[3] * (2**64);
    component ranges[4];
    for (var i = 0; i < 4; i++) {
        ranges[i] = Num2Bits(64);
        ranges[i].in <== limbs[i];
    }
    component carry0 = Num2Bits(64);
    carry0.in <== carry[0];
    component carry1 = Num2Bits(65);
    carry1.in <== carry[1];
}

// Prove q=floor(amount*numerator/denominator) in integer arithmetic.
// The composed circuit must bind these private values to the transfer and
// approved valuation; this template does not authenticate a price source.
template PilotValuation() {
    signal input amount_base_units;
    signal input numerator;
    signal input denominator;
    signal input usd_cents;
    signal input remainder;
    component amount_product = PilotMultiply128();
    amount_product.a <== amount_base_units;
    amount_product.b <== numerator;
    component quotient_product = PilotMultiply128();
    quotient_product.a <== usd_cents;
    quotient_product.b <== denominator;
    component positive[4];
    positive[0] = IsZero();
    positive[0].in <== amount_base_units;
    positive[1] = IsZero();
    positive[1].in <== numerator;
    positive[2] = IsZero();
    positive[2].in <== denominator;
    positive[3] = IsZero();
    positive[3].in <== usd_cents;
    for (var i = 0; i < 4; i++) { positive[i].out === 0; }
    component r_bits = Num2Bits(128);
    r_bits.in <== remainder;
    component remainder_bound = LessThan(128);
    remainder_bound.in[0] <== remainder;
    remainder_bound.in[1] <== denominator;
    remainder_bound.out === 1;
    signal r_limbs[4];
    for (var part = 0; part < 2; part++) {
        var rl = 0;
        for (var bit = 0; bit < 64; bit++) {
            rl += r_bits.out[part*64+bit] * (2**bit);
        }
        r_limbs[part] <== rl;
    }
    r_limbs[2] <== 0;
    r_limbs[3] <== 0;
    signal carry[5];
    carry[0] <== 0;
    for (var i = 0; i < 4; i++) {
        carry[i+1] <-- (quotient_product.limbs[i] + r_limbs[i] + carry[i]) \ (2**64);
        carry[i+1] * (carry[i+1]-1) === 0;
        quotient_product.limbs[i] + r_limbs[i] + carry[i] ===
            amount_product.limbs[i] + carry[i+1] * (2**64);
    }
    carry[4] === 0;
}

// Private tier predicate for the new profile. No SAR output or public tier.
// The parent must bind thresholds to its approved policy and keep tier private.
template PilotAmountTier() {
    signal input usd_cents;
    signal input thresholds[3];
    signal input tier;
    component amount_range = Num2Bits(128);
    amount_range.in <== usd_cents;
    component amount_zero = IsZero();
    amount_zero.in <== usd_cents;
    amount_zero.out === 0;
    component ranges[3];
    component lower[3];
    component positive[3];
    for (var i = 0; i < 3; i++) {
        ranges[i] = Num2Bits(128);
        ranges[i].in <== thresholds[i];
        positive[i] = IsZero();
        positive[i].in <== thresholds[i];
        positive[i].out === 0;
        lower[i] = LessThan(128);
        lower[i].in[0] <== usd_cents;
        lower[i].in[1] <== thresholds[i];
    }
    component ordered[2];
    for (var i = 0; i < 2; i++) {
        ordered[i] = LessThan(128);
        ordered[i].in[0] <== thresholds[i];
        ordered[i].in[1] <== thresholds[i+1];
        ordered[i].out === 1;
    }
    tier === 4 - lower[0].out - lower[1].out - lower[2].out;
}
