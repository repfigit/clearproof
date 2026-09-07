pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./lib/merkle_tree.circom";

// Development subcircuit only. Root authentication, enrollment consent,
// revocation and transfer authorization belong to the composed verifier.
// Field layout MUST match PilotCredential.fields(), excluding constant tag 102.
template PilotCredentialValidity(issuance_depth, issuer_depth) {
    signal input fields[13];
    signal input holder_secret;
    signal input credential_commitment;
    signal input authorized_issuer_root;
    signal input issuance_root;
    signal input issuance_siblings[issuance_depth];
    signal input issuance_indices[issuance_depth];
    signal input issuer_siblings[issuer_depth];
    signal input issuer_indices[issuer_depth];
    signal input expected_tenant[2];
    signal input expected_subject;
    signal input expected_jurisdiction;
    signal input evaluated_at;

    // issuer limbs, tenant limbs, nonce limbs are each 128-bit integers.
    component limbs[6];
    for (var i = 0; i < 6; i++) {
        limbs[i] = Num2Bits(128);
        limbs[i].in <== fields[i];
    }
    component wallet = Num2Bits(160);
    wallet.in <== fields[6];
    component nonzero_wallet = IsZero();
    nonzero_wallet.in <== fields[6];
    nonzero_wallet.out === 0;
    component nonce_zero[2];
    for (var i = 0; i < 2; i++) {
        nonce_zero[i] = IsZero();
        nonce_zero[i].in <== fields[4+i];
    }
    nonce_zero[0].out * nonce_zero[1].out === 0;
    // Canonical uppercase ASCII jurisdiction bytes, matching the Python model.
    component country = Num2Bits(16);
    country.in <== fields[8];
    signal country_bytes[2];
    var low = 0;
    var high = 0;
    for (var i = 0; i < 8; i++) {
        low += country.out[i] * (2**i);
        high += country.out[8+i] * (2**i);
    }
    country_bytes[0] <== high;
    country_bytes[1] <== low;
    component country_min[2];
    component country_max[2];
    for (var i = 0; i < 2; i++) {
        country_min[i] = GreaterEqThan(8);
        country_min[i].in[0] <== country_bytes[i];
        country_min[i].in[1] <== 65;
        country_min[i].out === 1;
        country_max[i] = LessEqThan(8);
        country_max[i].in[0] <== country_bytes[i];
        country_max[i].in[1] <== 90;
        country_max[i].out === 1;
    }
    component tier = Num2Bits(2);
    tier.in <== fields[9];
    component tier_zero = IsZero();
    tier_zero.in <== fields[9];
    tier_zero.out === 0;
    component times[3];
    times[0] = Num2Bits(53);
    times[0].in <== fields[10];
    times[1] = Num2Bits(53);
    times[1].in <== fields[11];
    times[2] = Num2Bits(53);
    times[2].in <== evaluated_at;
    component issued = LessEqThan(53);
    issued.in[0] <== fields[10];
    issued.in[1] <== evaluated_at;
    issued.out === 1;
    component unexpired = GreaterThan(53);
    unexpired.in[0] <== fields[11];
    unexpired.in[1] <== evaluated_at;
    unexpired.out === 1;
    fields[12] === 1;
    fields[2] === expected_tenant[0];
    fields[3] === expected_tenant[1];
    fields[6] === expected_subject;
    fields[8] === expected_jurisdiction;

    component secret_zero = IsZero();
    secret_zero.in <== holder_secret;
    secret_zero.out === 0;
    component holder = Poseidon(2);
    holder.inputs[0] <== 101;
    holder.inputs[1] <== holder_secret;
    holder.out === fields[7];
    component holder_zero = IsZero();
    holder_zero.in <== fields[7];
    holder_zero.out === 0;

    component commitment = Poseidon(14);
    commitment.inputs[0] <== 102;
    for (var i = 0; i < 13; i++) {
        commitment.inputs[i+1] <== fields[i];
    }
    commitment.out === credential_commitment;
    component issuance = MerkleTreeVerifier(issuance_depth);
    issuance.leaf <== commitment.out;
    issuance.root <== issuance_root;
    for (var i = 0; i < issuance_depth; i++) {
        issuance.pathElements[i] <== issuance_siblings[i];
        issuance.pathIndices[i] <== issuance_indices[i];
    }
    component issuer_leaf = Poseidon(4);
    issuer_leaf.inputs[0] <== 103;
    issuer_leaf.inputs[1] <== fields[0];
    issuer_leaf.inputs[2] <== fields[1];
    issuer_leaf.inputs[3] <== issuance_root;
    component issuer = MerkleTreeVerifier(issuer_depth);
    issuer.leaf <== issuer_leaf.out;
    issuer.root <== authorized_issuer_root;
    for (var i = 0; i < issuer_depth; i++) {
        issuer.pathElements[i] <== issuer_siblings[i];
        issuer.pathIndices[i] <== issuer_indices[i];
    }
}
