pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./pilot_valuation.circom";

function PilotProjectionWidth(i) {
    if (i == 10 || i == 11 || i == 13 || i == 27) { return 160; }
    if (i == 12 || i == 26) { return 64; }
    if (i == 14) { return 5; }
    if (i >= 19 && i <= 23) { return 53; }
    if (i == 24) { return 17; }
    if (i == 25) { return 16; }
    if (i == 35) { return 3; }
    if (i == 38 || i == 41) { return 1; }
    return 128;
}

// Private projection, matched exactly by src/prover/pilot_projection.py.
// The verifier must recompute projection_commitment from validated records,
// catalog and approved policy. Caller-selected digests/quotes are not trusted.
template PilotTransferProjection() {
    signal input transfer_fields[48];
    signal input valuation_remainder;
    signal input projection_commitment;
    signal output authorization_scope;

    component ranges[48];
    for (var i = 0; i < 48; i++) {
        ranges[i] = Num2Bits(PilotProjectionWidth(i));
        ranges[i].in <== transfer_fields[i];
    }
    signal states[7];
    states[0] <== 201;
    component commits[6];
    for (var chunk = 0; chunk < 6; chunk++) {
        commits[chunk] = Poseidon(9);
        commits[chunk].inputs[0] <== states[chunk];
        for (var i = 0; i < 8; i++) {
            commits[chunk].inputs[i+1] <== transfer_fields[chunk*8+i];
        }
        states[chunk+1] <== commits[chunk].out;
    }
    projection_commitment === states[6];

    component valuation = PilotValuation();
    valuation.amount_base_units <== transfer_fields[15];
    valuation.numerator <== transfer_fields[16];
    valuation.denominator <== transfer_fields[17];
    valuation.usd_cents <== transfer_fields[18];
    valuation.remainder <== valuation_remainder;
    component tier = PilotAmountTier();
    tier.usd_cents <== transfer_fields[18];
    tier.tier <== transfer_fields[35];
    for (var i = 0; i < 3; i++) { tier.thresholds[i] <== transfer_fields[32+i]; }

    // observation <= creation <= evaluation < transfer expiry <= quote expiry
    component time_checks[3];
    for (var i = 0; i < 3; i++) { time_checks[i] = LessEqThan(53); }
    time_checks[0].in[0] <== transfer_fields[19];
    time_checks[0].in[1] <== transfer_fields[21];
    time_checks[1].in[0] <== transfer_fields[21];
    time_checks[1].in[1] <== transfer_fields[23];
    time_checks[2].in[0] <== transfer_fields[22];
    time_checks[2].in[1] <== transfer_fields[20];
    for (var i = 0; i < 3; i++) { time_checks[i].out === 1; }
    component unexpired = LessThan(53);
    unexpired.in[0] <== transfer_fields[23];
    unexpired.in[1] <== transfer_fields[22];
    unexpired.out === 1;
    component age = LessEqThan(53);
    age.in[0] <== transfer_fields[23] - transfer_fields[21];
    age.in[1] <== transfer_fields[24];
    age.out === 1;
    component max_age = LessEqThan(17);
    max_age.in[0] <== transfer_fields[24];
    max_age.in[1] <== 86400;
    max_age.out === 1;
    transfer_fields[12] === transfer_fields[26];
    component decimals = LessEqThan(5);
    decimals.in[0] <== transfer_fields[14];
    decimals.in[1] <== 18;
    decimals.out === 1;
    component nonzero[5];
    var positive_indices[5] = [10, 11, 12, 13, 27];
    for (var i = 0; i < 5; i++) {
        nonzero[i] = IsZero();
        nonzero[i].in <== transfer_fields[positive_indices[i]];
        nonzero[i].out === 0;
    }
    // A self-hosted participant cannot carry VASP identity limbs.
    transfer_fields[36] * (1-transfer_fields[38]) === 0;
    transfer_fields[37] * (1-transfer_fields[38]) === 0;
    transfer_fields[39] * (1-transfer_fields[41]) === 0;
    transfer_fields[40] * (1-transfer_fields[41]) === 0;

    // Stable across re-evaluation/quote/policy changes for this tenant's transfer
    // ID + nonce + deployment. The parent binds holder knowledge to this scope.
    component scope = Poseidon(9);
    scope.inputs[0] <== 202;
    for (var i = 0; i < 6; i++) { scope.inputs[i+1] <== transfer_fields[4+i]; }
    scope.inputs[7] <== transfer_fields[26];
    scope.inputs[8] <== transfer_fields[27];
    authorization_scope <== scope.out;
}
