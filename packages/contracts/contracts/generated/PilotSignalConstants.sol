// SPDX-License-Identifier: Apache-2.0
// Generated: specs/pilot-signals-v3.json; SHA256 4932f8bc2948340926aeb23c7ed202bb47615ba9c570c2731daea64366206948.
pragma solidity ^0.8.24;

uint256 constant PILOT_SIGNAL_COUNT = 8;

library PilotSignalConstants {
    string internal constant PROFILE = "pilot-transfer-v3";
    uint256 internal constant PILOT_PUBLIC_SIGNAL_COUNT = 8;
    uint256 internal constant PROJECTION_FIELD_COUNT = 48;
    uint256 internal constant PROJECTION_COMMITMENT_INDEX = 0;
    uint256 internal constant AUTHORIZED_ISSUER_ROOT_INDEX = 1;
    uint256 internal constant SANCTIONS_ROOT_INDEX = 2;
    uint256 internal constant AUTHORIZATION_NULLIFIER_INDEX = 3;
    uint256 internal constant EVALUATED_AT_INDEX = 4;
    uint256 internal constant PROOF_EXPIRES_AT_INDEX = 5;
    uint256 internal constant DOMAIN_CHAIN_ID_INDEX = 6;
    uint256 internal constant DOMAIN_REGISTRY_INDEX = 7;
    uint256 internal constant ISSUANCE_TREE_DEPTH = 32;
    uint256 internal constant ISSUER_TREE_DEPTH = 20;
    uint256 internal constant SANCTIONS_TREE_DEPTH = 20;
    uint256 internal constant HOLDER_DOMAIN_TAG = 101;
    uint256 internal constant CREDENTIAL_DOMAIN_TAG = 102;
    uint256 internal constant ISSUER_LEAF_DOMAIN_TAG = 103;
    uint256 internal constant PROJECTION_DOMAIN_TAG = 201;
    uint256 internal constant AUTHORIZATION_SCOPE_DOMAIN_TAG = 202;
    uint256 internal constant AUTHORIZATION_NULLIFIER_DOMAIN_TAG = 203;
    uint256 internal constant BOUND_PROJECTION_DOMAIN_TAG = 204;
    uint256 internal constant SANCTIONS_LEAF_DOMAIN_TAG = 301;
    uint256 internal constant PROOF_LIFETIME_SECONDS = 300;
    uint256 internal constant MAX_TRANSFER_AGE_SECONDS = 86400;
    uint256 internal constant MAX_ASSET_DECIMALS = 18;
}
