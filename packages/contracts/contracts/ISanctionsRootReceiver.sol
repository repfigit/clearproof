// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
pragma solidity ^0.8.24;

/**
 * @title ISanctionsRootReceiver
 * @notice Interface for contracts that accept sanctions root updates.
 *         Implement this to swap transport layers (direct relayer, CCIP,
 *         LayerZero) without redeploying the SanctionsOracle.
 */
interface ISanctionsRootReceiver {
    function receiveRoot(bytes32 newRoot, uint32 leafCount) external;
}
