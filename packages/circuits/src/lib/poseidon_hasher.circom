pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/*
 * Thin wrapper around circomlib's Poseidon hash for a consistent interface
 * across the ZK Travel Rule compliance circuits.
 *
 * Provides domain-separated hashing variants:
 *   - PoseidonHasher(n): raw Poseidon hash of n inputs
 *   - DomainPoseidon(n): Poseidon(domain_tag, input_0, ..., input_{n-1})
 *     where domain_tag is prepended to prevent cross-protocol hash collisions
 *
 * Domain tags used in this project:
 *   0x01 = sanctions leaf hash
 *   0x02 = issuer leaf hash
 *   0x03 = credential commitment (reserved, currently uses raw Poseidon(5))
 */

// Raw Poseidon wrapper with n inputs. Exposes a single `out` signal.
template PoseidonHasher(n_inputs) {
    signal input in[n_inputs];
    signal output out;

    component hasher = Poseidon(n_inputs);
    for (var i = 0; i < n_inputs; i++) {
        hasher.inputs[i] <== in[i];
    }
    out <== hasher.out;
}

// Domain-separated Poseidon: prepends a domain tag to the input array.
// Total Poseidon width = n_inputs + 1 (domain tag + n_inputs data fields).
template DomainPoseidon(n_inputs) {
    signal input domain_tag;
    signal input in[n_inputs];
    signal output out;

    component hasher = Poseidon(n_inputs + 1);
    hasher.inputs[0] <== domain_tag;
    for (var i = 0; i < n_inputs; i++) {
        hasher.inputs[i + 1] <== in[i];
    }
    out <== hasher.out;
}
