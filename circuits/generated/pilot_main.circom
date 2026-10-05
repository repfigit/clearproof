pragma circom 2.1.6;
// Generated: specs/pilot-signals-v3.json; SHA256 4932f8bc2948340926aeb23c7ed202bb47615ba9c570c2731daea64366206948.
component main {public [projection_commitment, authorized_issuer_root, sanctions_root, authorization_nullifier, evaluated_at, proof_expires_at, domain_chain_id, domain_registry]} = PilotCompliance(
    PilotIssuanceTreeDepth(), PilotIssuerTreeDepth(), PilotSanctionsTreeDepth());
