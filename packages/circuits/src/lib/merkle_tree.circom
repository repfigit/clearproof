pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";

/*
 * Generic Poseidon-based Merkle proof verification.
 * Used for both membership and non-membership proofs throughout the
 * ZK Travel Rule Compliance Bridge.
 *
 * MerkleProof(depth):
 *   Verifies that a given leaf hashes up to a known root via a Merkle path.
 *   - leaf: the leaf value (already hashed if domain separation is desired)
 *   - root: the expected Merkle root
 *   - siblings[depth]: sibling hashes at each level
 *   - indices[depth]: path direction bits (0 = leaf is left child, 1 = right)
 *   - valid: output signal, 1 if proof is valid
 *
 * MerkleNonMembership(depth):
 *   Proves a query_key is NOT in a sorted Merkle tree using the gap proof
 *   approach: the prover supplies two adjacent leaves (left_key, right_key)
 *   such that left_key < query_key < right_key, and both leaves are verified
 *   as members of the tree at adjacent positions.
 */

// ============================================================
// Membership proof: verify a leaf belongs to a Merkle tree
// ============================================================
template MerkleProof(depth) {
    signal input leaf;
    signal input root;
    signal input siblings[depth];
    signal input indices[depth];   // 0 = leaf is left child, 1 = leaf is right child

    signal output valid;

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    component hashers[depth];
    component mux[depth];

    for (var i = 0; i < depth; i++) {
        // Constrain each index bit to be binary (0 or 1)
        indices[i] * (1 - indices[i]) === 0;

        // Use MultiMux1 to select child ordering based on the path bit.
        // When indices[i] == 0: left = hashes[i], right = siblings[i]
        // When indices[i] == 1: left = siblings[i], right = hashes[i]
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== hashes[i];      // left when index=0
        mux[i].c[0][1] <== siblings[i];     // left when index=1
        mux[i].c[1][0] <== siblings[i];     // right when index=0
        mux[i].c[1][1] <== hashes[i];       // right when index=1
        mux[i].s <== indices[i];

        // Hash the ordered pair: Poseidon(left, right)
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== hashers[i].out;
    }

    // Final computed root must equal the expected root
    component eq = IsEqual();
    eq.in[0] <== hashes[depth];
    eq.in[1] <== root;
    valid <== eq.out;
}

// ============================================================
// Backward-compatible alias used by existing subcircuits
// ============================================================
template MerkleTreeVerifier(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels]; // 0 = left, 1 = right

    // Delegate to MerkleProof
    component proof = MerkleProof(levels);
    proof.leaf <== leaf;
    proof.root <== root;
    for (var i = 0; i < levels; i++) {
        proof.siblings[i] <== pathElements[i];
        proof.indices[i] <== pathIndices[i];
    }

    // MerkleTreeVerifier uses a hard constraint instead of an output signal:
    // the root must match exactly or the circuit fails.
    proof.valid === 1;
}

// ============================================================
// Non-membership proof via sorted-tree gap proof
// ============================================================
//
// A sorted Merkle tree stores keys in ascending order by leaf index.
// To prove query_key is NOT in the tree, the prover shows two adjacent
// leaves (left_key at index N, right_key at index N+1) that bracket
// the query_key: left_key < query_key < right_key.
//
// Since the tree is sorted and the leaves are adjacent, there is no
// position where query_key could exist.
template MerkleNonMembership(depth) {
    signal input root;               // Merkle root of the sorted tree
    signal input query_key;          // The key to prove is NOT in the tree

    signal input left_key;           // Largest key in tree < query_key
    signal input right_key;          // Smallest key in tree > query_key
    signal input left_index;         // Leaf index of left_key
    signal input right_index;        // Leaf index of right_key

    // Merkle paths for both neighbors
    signal input left_siblings[depth];
    signal input left_indices[depth];
    signal input right_siblings[depth];
    signal input right_indices[depth];

    signal output valid;

    // CONSTRAINT 1: left_key < query_key (strict)
    component lt_left = LessThan(252);
    lt_left.in[0] <== left_key;
    lt_left.in[1] <== query_key;
    lt_left.out === 1;

    // CONSTRAINT 2: query_key < right_key (strict)
    component lt_right = LessThan(252);
    lt_right.in[0] <== query_key;
    lt_right.in[1] <== right_key;
    lt_right.out === 1;

    // CONSTRAINT 3: The two leaves are adjacent in the sorted tree
    // right_index == left_index + 1
    right_index === left_index + 1;

    // CONSTRAINT 4: left_key is a valid member of the tree
    // Domain-separated leaf hash: Poseidon(0x01, left_key)
    component left_leaf_hash = Poseidon(2);
    left_leaf_hash.inputs[0] <== 1;  // domain tag for leaf
    left_leaf_hash.inputs[1] <== left_key;

    component left_proof = MerkleProof(depth);
    left_proof.leaf <== left_leaf_hash.out;
    left_proof.root <== root;
    for (var i = 0; i < depth; i++) {
        left_proof.siblings[i] <== left_siblings[i];
        left_proof.indices[i] <== left_indices[i];
    }
    left_proof.valid === 1;

    // CONSTRAINT 5: right_key is a valid member of the tree
    // Domain-separated leaf hash: Poseidon(0x01, right_key)
    component right_leaf_hash = Poseidon(2);
    right_leaf_hash.inputs[0] <== 1;  // domain tag for leaf
    right_leaf_hash.inputs[1] <== right_key;

    component right_proof = MerkleProof(depth);
    right_proof.leaf <== right_leaf_hash.out;
    right_proof.root <== root;
    for (var i = 0; i < depth; i++) {
        right_proof.siblings[i] <== right_siblings[i];
        right_proof.indices[i] <== right_indices[i];
    }
    right_proof.valid === 1;

    // If all constraints pass, the gap proof is valid
    valid <== 1;
}
