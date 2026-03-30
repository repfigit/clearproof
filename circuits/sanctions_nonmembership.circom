pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
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
 *   3. Adjacency is enforced (right_index == left_index + 1).
 *   4. Since the tree is sorted and leaves are adjacent, query_key cannot
 *      exist in the tree.
 *
 * The sorted Merkle tree is rebuilt daily from OFAC SDN, UN consolidated,
 * and EU asset freeze lists. Leaves use domain-separated hashing:
 *   leaf_hash = Poseidon(0x01, key)
 *
 * PUBLIC INPUTS (via parent circuit):
 *   - sanctions_root: Merkle root of current sanctions list
 *
 * PRIVATE INPUTS:
 *   - query_key: Poseidon hash of wallet address (the key to prove absent)
 *   - left_key: largest key in tree less than query_key
 *   - right_key: smallest key in tree greater than query_key
 *   - left_path_elements[]: Merkle path siblings for left_key
 *   - left_path_indices[]:  Merkle path direction bits for left_key
 *   - right_path_elements[]: Merkle path siblings for right_key
 *   - right_path_indices[]:  Merkle path direction bits for right_key
 *   - left_index: leaf index of left_key in the sorted tree
 *   - right_index: leaf index of right_key in the sorted tree
 */

// Domain-separated leaf hash for sanctions tree entries
template SanctionsLeafHash() {
    signal input key;
    signal output out;

    // Domain tag 0x01 distinguishes sanctions leaf hashes from other uses
    component hasher = Poseidon(2);
    hasher.inputs[0] <== 1; // domain tag for sanctions leaf
    hasher.inputs[1] <== key;
    out <== hasher.out;
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
    signal input left_index;         // Leaf index of left_key
    signal input right_index;        // Leaf index of right_key

    // OUTPUT
    signal output valid;

    // --- CONSTRAINT 1: left_key < query_key (strict inequality) ---
    // Uses 252-bit comparator to handle BN254 field element range
    component lt_left = LessThan(252);
    lt_left.in[0] <== left_key;
    lt_left.in[1] <== query_key;
    lt_left.out === 1;

    // --- CONSTRAINT 2: query_key < right_key (strict inequality) ---
    component lt_right = LessThan(252);
    lt_right.in[0] <== query_key;
    lt_right.in[1] <== right_key;
    lt_right.out === 1;

    // --- CONSTRAINT 3: left_key != query_key (explicit, redundant with LessThan) ---
    component neq_left = IsEqual();
    neq_left.in[0] <== left_key;
    neq_left.in[1] <== query_key;
    neq_left.out === 0;

    // --- CONSTRAINT 4: right_key != query_key (explicit, redundant with LessThan) ---
    component neq_right = IsEqual();
    neq_right.in[0] <== right_key;
    neq_right.in[1] <== query_key;
    neq_right.out === 0;

    // --- CONSTRAINT 5: Adjacency — the two leaves are neighbors in the sorted tree ---
    right_index === left_index + 1;

    // --- CONSTRAINT 6: left_key is a valid leaf in the sanctions tree ---
    component left_leaf_hash = SanctionsLeafHash();
    left_leaf_hash.key <== left_key;

    component left_verifier = MerkleTreeVerifier(tree_depth);
    left_verifier.leaf <== left_leaf_hash.out;
    left_verifier.root <== sanctions_root;
    for (var i = 0; i < tree_depth; i++) {
        left_verifier.pathElements[i] <== left_path_elements[i];
        left_verifier.pathIndices[i] <== left_path_indices[i];
    }

    // --- CONSTRAINT 7: right_key is a valid leaf in the sanctions tree ---
    component right_leaf_hash = SanctionsLeafHash();
    right_leaf_hash.key <== right_key;

    component right_verifier = MerkleTreeVerifier(tree_depth);
    right_verifier.leaf <== right_leaf_hash.out;
    right_verifier.root <== sanctions_root;
    for (var i = 0; i < tree_depth; i++) {
        right_verifier.pathElements[i] <== right_path_elements[i];
        right_verifier.pathIndices[i] <== right_path_indices[i];
    }

    // All constraints passed — wallet is provably not in the sanctions tree
    valid <== 1;
}
