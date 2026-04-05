pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./lib/merkle_tree.circom";

/*
 * Sanctions Non-Membership Proof
 *
 * Proves that a wallet address hash is NOT a member of the sanctions
 * Merkle tree, without revealing the wallet address itself.
 *
 * Uses a sorted-tree "gap proof" approach:
 *   1. The prover supplies two adjacent leaves (left_key, right_key) from
 *      the sorted sanctions tree such that left_key < query_key < right_key.
 *   2. Both leaves are verified as valid members of the tree.
 *   3. Adjacency is DERIVED from Merkle path indices (not free inputs) and
 *      enforced as a circuit constraint.
 *   4. All keys are range-checked to < 2^252 for LessThan soundness.
 *
 * SOUNDNESS NOTES:
 *   - Audit issue #1: Adjacency is now derived from path bits, not free inputs.
 *     leaf_index = sum(path_indices[i] * 2^i). This binds the claimed index
 *     to the actual Merkle path, preventing the prover from choosing arbitrary
 *     "adjacent" leaves that are actually far apart.
 *   - Audit issue #2: All keys are range-checked via Num2Bits(252) before
 *     LessThan comparison. Without this, field element wrapping makes
 *     LessThan unsound for values >= 2^252.
 *   - Audit issue #8: valid output is bound to subcircuit constraint success.
 */

// Domain-separated leaf hash for sanctions tree entries
template SanctionsLeafHash() {
    signal input key;
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== 1; // domain tag 0x01 for sanctions leaf
    hasher.inputs[1] <== key;
    out <== hasher.out;
}

// Derive leaf index from Merkle path direction bits
// index = sum(indices[i] * 2^i) for i in [0, depth)
template PathToIndex(depth) {
    signal input indices[depth];
    signal output index;

    var acc = 0;
    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
        // indices[i] are already constrained to boolean by MerkleProof
        acc += indices[i] * pow2;
        pow2 = pow2 * 2;
    }
    index <== acc;
}

template SanctionsNonMembership(tree_depth) {
    // PUBLIC INPUTS
    signal input sanctions_root;     // Merkle root of sorted sanctions tree

    // PRIVATE INPUTS
    signal input query_key;          // Wallet address hash to prove is NOT sanctioned
    signal input left_key;           // Largest key in tree < query_key
    signal input right_key;          // Smallest key in tree > query_key
    signal input left_path_elements[tree_depth];
    signal input left_path_indices[tree_depth];
    signal input right_path_elements[tree_depth];
    signal input right_path_indices[tree_depth];

    // OUTPUT
    signal output valid;

    // === RANGE CHECKS (Audit fix #2) ===
    // All keys must be < 2^252 for LessThan(252) to be sound.
    // Num2Bits decomposes the value into bits and constrains each to {0,1},
    // which implicitly proves the value fits in n bits.
    component range_left = Num2Bits(252);
    range_left.in <== left_key;

    component range_query = Num2Bits(252);
    range_query.in <== query_key;

    component range_right = Num2Bits(252);
    range_right.in <== right_key;

    // === CONSTRAINT 1: left_key < query_key (strict ordering) ===
    component lt_left = LessThan(252);
    lt_left.in[0] <== left_key;
    lt_left.in[1] <== query_key;
    lt_left.out === 1;

    // === CONSTRAINT 2: query_key < right_key (strict ordering) ===
    component lt_right = LessThan(252);
    lt_right.in[0] <== query_key;
    lt_right.in[1] <== right_key;
    lt_right.out === 1;

    // === CONSTRAINT 3: Adjacency derived from path bits (Audit fix #1) ===
    // Derive actual leaf indices from Merkle path direction bits.
    // This binds the indices to the actual Merkle proof paths,
    // preventing the prover from claiming false adjacency.
    component left_idx = PathToIndex(tree_depth);
    for (var i = 0; i < tree_depth; i++) {
        left_idx.indices[i] <== left_path_indices[i];
    }

    component right_idx = PathToIndex(tree_depth);
    for (var i = 0; i < tree_depth; i++) {
        right_idx.indices[i] <== right_path_indices[i];
    }

    // Enforce adjacency: right leaf is exactly one position after left leaf
    right_idx.index === left_idx.index + 1;

    // === CONSTRAINT 4: left_key is a valid leaf in the sanctions tree ===
    // left_key is already domain-separated (Poseidon(1, addr_int)) by the tree builder.
    // No re-hashing needed — the leaf value IS the hash.
    component left_verifier = MerkleTreeVerifier(tree_depth);
    left_verifier.leaf <== left_key;
    left_verifier.root <== sanctions_root;
    for (var i = 0; i < tree_depth; i++) {
        left_verifier.pathElements[i] <== left_path_elements[i];
        left_verifier.pathIndices[i] <== left_path_indices[i];
    }
    // MerkleTreeVerifier internally constrains proof.valid === 1

    // === CONSTRAINT 5: right_key is a valid leaf in the sanctions tree ===
    // right_key is already domain-separated (Poseidon(1, addr_int)) by the tree builder.
    component right_verifier = MerkleTreeVerifier(tree_depth);
    right_verifier.leaf <== right_key;
    right_verifier.root <== sanctions_root;
    for (var i = 0; i < tree_depth; i++) {
        right_verifier.pathElements[i] <== right_path_elements[i];
        right_verifier.pathIndices[i] <== right_path_indices[i];
    }
    // MerkleTreeVerifier internally constrains proof.valid === 1

    // All constraints passed — wallet is provably not in the sanctions tree.
    // This output is cosmetic; the real security comes from the constraints
    // above, which abort the circuit on failure.
    valid <== 1;
}
