pragma circom 2.1.6;
// Generated: specs/pilot-signals-v3.json; SHA256 4932f8bc2948340926aeb23c7ed202bb47615ba9c570c2731daea64366206948.

function PilotPilotPublicSignalCount() { return 8; }
function PilotProjectionFieldCount() { return 48; }
function PilotProjectionCommitmentIndex() { return 0; }
function PilotAuthorizedIssuerRootIndex() { return 1; }
function PilotSanctionsRootIndex() { return 2; }
function PilotAuthorizationNullifierIndex() { return 3; }
function PilotEvaluatedAtIndex() { return 4; }
function PilotProofExpiresAtIndex() { return 5; }
function PilotDomainChainIdIndex() { return 6; }
function PilotDomainRegistryIndex() { return 7; }
function PilotIssuanceTreeDepth() { return 32; }
function PilotIssuerTreeDepth() { return 20; }
function PilotSanctionsTreeDepth() { return 20; }
function PilotHolderDomainTag() { return 101; }
function PilotCredentialDomainTag() { return 102; }
function PilotIssuerLeafDomainTag() { return 103; }
function PilotProjectionDomainTag() { return 201; }
function PilotAuthorizationScopeDomainTag() { return 202; }
function PilotAuthorizationNullifierDomainTag() { return 203; }
function PilotBoundProjectionDomainTag() { return 204; }
function PilotSanctionsLeafDomainTag() { return 301; }
function PilotProofLifetimeSeconds() { return 300; }
function PilotMaxTransferAgeSeconds() { return 86400; }
function PilotMaxAssetDecimals() { return 18; }
function PilotProjectionWidth(i) {
    var widths[48] = [128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 160, 160, 64, 160, 5, 128, 128, 128, 128, 53, 53, 53, 53, 53, 17, 16, 64, 160, 128, 128, 128, 128, 128, 128, 128, 3, 128, 128, 1, 128, 128, 1, 128, 128, 128, 128, 128, 128];
    return widths[i];
}
