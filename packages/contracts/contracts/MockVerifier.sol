// SPDX-License-Identifier: Apache-2.0
// LEGACY: 16-signal `compliance.circom` demo/parity path, not pilot-transfer-v3.
// Never treat proofs, roots or records accepted here as current pilot authorization.
// Kept at this path for the published @clearproof/contracts artifact layout; see
// packages/contracts/AGENTS.md ("Legacy contracts") and docs/internal/CIRCUIT_SIGNALS.md.
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
