// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
// LEGACY: 16-signal `compliance.circom` demo/parity path, not pilot-transfer-v3.
// Never treat proofs, roots or records accepted here as current pilot authorization.
// Kept at this path for the published @clearproof/contracts artifact layout; see
// packages/contracts/AGENTS.md ("Legacy contracts") and docs/internal/CIRCUIT_SIGNALS.md.
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
