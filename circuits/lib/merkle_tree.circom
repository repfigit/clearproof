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
