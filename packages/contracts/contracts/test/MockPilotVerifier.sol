// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @dev TEST ONLY. ABI-compatible stand-in for PilotGroth16Verifier so registry logic
/// (pause, epochs, events, domain binding) runs without circuit artifacts. It performs
/// no pairing check and must never be deployed outside a local test network.
contract MockPilotVerifier {
    bytes32 public immutable artifactManifestDigest;
    bool public result = true;

    constructor(bytes32 manifestDigest) {
        artifactManifestDigest = manifestDigest;
    }

    function setResult(bool value) external {
        result = value;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external view returns (bool) {
        return result;
    }
}
