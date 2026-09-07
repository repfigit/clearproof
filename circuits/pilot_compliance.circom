pragma circom 2.1.6;
include "./pilot_transfer.circom";
include "./pilot_credential.circom";
include "./pilot_sanctions.circom";

// Development profile pilot-transfer-v2. Eight public inputs; no SAR/tier output.
// State/authority, quote/policy provenance, revocation and consumption are
// verifier responsibilities. See ADR 0006 before enabling authorization.
template PilotCompliance(issuance_depth, issuer_depth, sanctions_depth) {
    signal input projection_commitment;
    signal input authorized_issuer_root;
    signal input sanctions_root;
    signal input authorization_nullifier;
    signal input evaluated_at;
    signal input proof_expires_at;
    signal input domain_chain_id;
    signal input domain_registry;

    signal input transfer_fields[48];
    signal input transfer_projection_commitment;
    signal input valuation_remainder;
    signal input credential_fields[13];
    signal input credential_commitment;
    signal input holder_secret;
    signal input issuance_root;
    signal input issuance_siblings[issuance_depth];
    signal input issuance_indices[issuance_depth];
    signal input issuer_siblings[issuer_depth];
    signal input issuer_indices[issuer_depth];
    signal input sanctions_left_keys[2];
    signal input sanctions_right_keys[2];
    signal input sanctions_left_siblings[2][sanctions_depth];
    signal input sanctions_right_siblings[2][sanctions_depth];
    signal input sanctions_left_indices[2][sanctions_depth];
    signal input sanctions_right_indices[2][sanctions_depth];

    component transfer = PilotTransferProjection();
    for (var i = 0; i < 48; i++) { transfer.transfer_fields[i] <== transfer_fields[i]; }
    transfer.valuation_remainder <== valuation_remainder;
    transfer.projection_commitment <== transfer_projection_commitment;
    component bound = Poseidon(4);
    bound.inputs[0] <== 204;
    bound.inputs[1] <== transfer_projection_commitment;
    bound.inputs[2] <== credential_commitment;
    bound.inputs[3] <== issuance_root;
    projection_commitment === bound.out;
    evaluated_at === transfer_fields[23];
    domain_chain_id === transfer_fields[26];
    domain_registry === transfer_fields[27];

    component credential = PilotCredentialValidity(issuance_depth, issuer_depth);
    for (var i = 0; i < 13; i++) { credential.fields[i] <== credential_fields[i]; }
    credential.holder_secret <== holder_secret;
    credential.credential_commitment <== credential_commitment;
    credential.authorized_issuer_root <== authorized_issuer_root;
    credential.issuance_root <== issuance_root;
    for (var i = 0; i < issuance_depth; i++) {
        credential.issuance_siblings[i] <== issuance_siblings[i];
        credential.issuance_indices[i] <== issuance_indices[i];
    }
    for (var i = 0; i < issuer_depth; i++) {
        credential.issuer_siblings[i] <== issuer_siblings[i];
        credential.issuer_indices[i] <== issuer_indices[i];
    }
    credential.expected_tenant[0] <== transfer_fields[4];
    credential.expected_tenant[1] <== transfer_fields[5];
    credential.expected_subject <== transfer_fields[10];
    credential.expected_jurisdiction <== transfer_fields[25];
    credential.evaluated_at <== evaluated_at;

    component sanctions[2];
    for (var party = 0; party < 2; party++) {
        sanctions[party] = PilotSanctionsGap(sanctions_depth);
        sanctions[party].wallet <== transfer_fields[10+party];
        sanctions[party].root <== sanctions_root;
        sanctions[party].left_key <== sanctions_left_keys[party];
        sanctions[party].right_key <== sanctions_right_keys[party];
        for (var i = 0; i < sanctions_depth; i++) {
            sanctions[party].left_siblings[i] <== sanctions_left_siblings[party][i];
            sanctions[party].right_siblings[i] <== sanctions_right_siblings[party][i];
            sanctions[party].left_indices[i] <== sanctions_left_indices[party][i];
            sanctions[party].right_indices[i] <== sanctions_right_indices[party][i];
        }
    }
    component nullifier = Poseidon(3);
    nullifier.inputs[0] <== 203;
    nullifier.inputs[1] <== holder_secret;
    nullifier.inputs[2] <== transfer.authorization_scope;
    authorization_nullifier === nullifier.out;

    component expiry_bits = Num2Bits(53);
    expiry_bits.in <== proof_expires_at;
    component fresh = LessThan(53);
    fresh.in[0] <== evaluated_at;
    fresh.in[1] <== proof_expires_at;
    fresh.out === 1;
    component expiry_limits[3];
    for (var i = 0; i < 3; i++) { expiry_limits[i] = LessEqThan(53); }
    expiry_limits[0].in[0] <== proof_expires_at;
    expiry_limits[0].in[1] <== transfer_fields[22];
    expiry_limits[1].in[0] <== proof_expires_at;
    expiry_limits[1].in[1] <== credential_fields[11];
    expiry_limits[2].in[0] <== proof_expires_at - evaluated_at;
    expiry_limits[2].in[1] <== 300;
    for (var i = 0; i < 3; i++) { expiry_limits[i].out === 1; }
}

component main {public [projection_commitment, authorized_issuer_root, sanctions_root,
    authorization_nullifier, evaluated_at, proof_expires_at, domain_chain_id, domain_registry]} = PilotCompliance(8, 8, 8);
