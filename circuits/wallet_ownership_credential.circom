pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Staged extension only. No existing verifier accepts this profile.
// The verifier must independently authenticate both expected commitments and
// current revocation/eligibility. This circuit does NOT verify EIP-191 signatures.
// Layout: domain, base credential, attestation digest, issued_at, expires_at, flag.
template WalletOwnershipCredential() {
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
    component commitment = Poseidon(6);
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
                        expected_attestation_digest, evaluated_at] } = WalletOwnershipCredential();
