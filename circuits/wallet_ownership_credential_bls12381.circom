pragma circom 2.1.6;

include "./lib/poseidon_bls12381.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Pre-audit BLS12-381 wallet-ownership extension (AIF-67, ADR 0002 task 3).
// Uses curve-correct BLS12-381 Poseidon(6) constants rather than circomlib's
// BN254-derived Poseidon. No trusted setup or deployed verifier accepts this
// pre-audit circuit yet; the BN254 pilot path remains unchanged.
// Layout: domain (111), base credential, attestation digest, issued_at, expires_at, flag.
template WalletOwnershipCredentialBls12381() {
    signal input fields[6];
    signal input extension_commitment;
    signal input expected_credential_commitment;
    signal input expected_attestation_digest;
    signal input evaluated_at;

    fields[0] === 111;
    fields[1] === expected_credential_commitment;
    fields[2] === expected_attestation_digest;
    fields[5] === 1;

    component credential_nonzero = IsZero();
    credential_nonzero.in <== fields[1];
    credential_nonzero.out === 0;
    component attestation_nonzero = IsZero();
    attestation_nonzero.in <== fields[2];
    attestation_nonzero.out === 0;

    component commitment = PoseidonBls(6);
    for (var i = 0; i < 6; i++) {
        commitment.inputs[i] <== fields[i];
    }
    extension_commitment === commitment.out;

    component issued_range = Num2Bits(53);
    issued_range.in <== fields[3];
    component expiry_range = Num2Bits(53);
    expiry_range.in <== fields[4];
    component now_range = Num2Bits(53);
    now_range.in <== evaluated_at;
    component issued = LessEqThan(53);
    issued.in[0] <== fields[3];
    issued.in[1] <== evaluated_at;
    issued.out === 1;
    component unexpired = LessThan(53);
    unexpired.in[0] <== evaluated_at;
    unexpired.in[1] <== fields[4];
    unexpired.out === 1;
}

component main { public [extension_commitment, expected_credential_commitment,
                        expected_attestation_digest, evaluated_at] } = WalletOwnershipCredentialBls12381();
