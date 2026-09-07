pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "./lib/merkle_tree.circom";

// New raw-address profile. This is deliberately incompatible with legacy
// sorted hashes: leaves are Poseidon(301, raw key), with sentinel keys 0, 2^160.
template PilotSanctionsGap(depth) {
    signal input wallet;
    signal input root;
    signal input left_key;
    signal input right_key;
    signal input left_siblings[depth];
    signal input right_siblings[depth];
    signal input left_indices[depth];
    signal input right_indices[depth];
    component wallet_bits = Num2Bits(160);
    wallet_bits.in <== wallet;
    component left_bits = Num2Bits(161);
    left_bits.in <== left_key;
    component right_bits = Num2Bits(161);
    right_bits.in <== right_key;
    component lower = LessThan(161);
    lower.in[0] <== left_key;
    lower.in[1] <== wallet;
    lower.out === 1;
    component upper = LessThan(161);
    upper.in[0] <== wallet;
    upper.in[1] <== right_key;
    upper.out === 1;
    component sentinel_bound = LessEqThan(161);
    sentinel_bound.in[0] <== right_key;
    sentinel_bound.in[1] <== 2**160;
    sentinel_bound.out === 1;
    component left_leaf = Poseidon(2);
    left_leaf.inputs[0] <== 301;
    left_leaf.inputs[1] <== left_key;
    component right_leaf = Poseidon(2);
    right_leaf.inputs[0] <== 301;
    right_leaf.inputs[1] <== right_key;
    component left = MerkleTreeVerifier(depth);
    left.leaf <== left_leaf.out;
    left.root <== root;
    component right = MerkleTreeVerifier(depth);
    right.leaf <== right_leaf.out;
    right.root <== root;
    var left_index = 0;
    var right_index = 0;
    for (var i = 0; i < depth; i++) {
        left.pathElements[i] <== left_siblings[i];
        left.pathIndices[i] <== left_indices[i];
        right.pathElements[i] <== right_siblings[i];
        right.pathIndices[i] <== right_indices[i];
        left_index += left_indices[i] * (2**i);
        right_index += right_indices[i] * (2**i);
    }
    right_index === left_index + 1;
}
