// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @dev Mock verifier that always returns true, for testing event emission.
contract MockVerifier {
    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[16] calldata
    ) external pure returns (bool) {
        return true;
    }
}
