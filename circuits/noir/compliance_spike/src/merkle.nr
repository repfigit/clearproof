// Merkle proof verification using Poseidon hash
// Mirrors circuits/lib/merkle_tree.circom

use dep::std;

/// Merkle membership proof verification
/// Verifies that a leaf hashes up to a known root via a Merkle path
pub fn merkle_proof<let DEPTH: u32>(
    leaf: Field,
    root: Field,
    path_elements: [Field; DEPTH],
    path_indices: [Field; DEPTH],
) -> bool {
    let mut hashes: [Field; DEPTH + 1] = [0; DEPTH + 1];
    hashes[0] = leaf;

    for i in 0..DEPTH {
        // Constrain index bit to be binary
        assert(path_indices[i] * (1 - path_indices[i]) == 0);

        // Select child ordering based on path bit
        let left = if path_indices[i] == 0 { hashes[i] } else { path_elements[i] };
        let right = if path_indices[i] == 0 { path_elements[i] } else { hashes[i] };

        // Hash the ordered pair: Poseidon(left, right)
        hashes[i + 1] = std::hash::poseidon2::Poseidon2Hasher::hash_with_4_chunks([left, right, 0, 0]);
    }

    // Final computed root must equal the expected root
    hashes[DEPTH] == root
}

/// Domain-separated leaf hash for sanctions tree entries
/// Poseidon(domain_tag=1, key)
pub fn sanctions_leaf_hash(key: Field) -> Field {
    std::hash::poseidon2::Poseidon2Hasher::hash_with_4_chunks([1, key, 0, 0])
}

/// Domain-separated leaf hash for issuer tree entries
/// Poseidon(domain_tag=2, issuer_did)
pub fn issuer_leaf_hash(issuer_did: Field) -> Field {
    std::hash::poseidon2::Poseidon2Hasher::hash_with_4_chunks([2, issuer_did, 0, 0])
}
