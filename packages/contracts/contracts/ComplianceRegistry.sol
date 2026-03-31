// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Groth16Verifier.sol";

contract ComplianceRegistry {
    Groth16Verifier public immutable verifier;

    struct ProofRecord {
        bytes32 proofHash;
        uint256 timestamp;
        bool verified;
    }

    mapping(bytes32 => ProofRecord) public proofs;

    event ProofVerified(bytes32 indexed transferId, bool isCompliant, bool sarFlag);

    constructor(address _verifier) {
        verifier = Groth16Verifier(_verifier);
    }

    function verifyAndRecord(
        bytes32 transferId,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[11] calldata _pubSignals
    ) external returns (bool) {
        bool valid = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);

        proofs[transferId] = ProofRecord({
            proofHash: keccak256(abi.encode(_pA, _pB, _pC)),
            timestamp: block.timestamp,
            verified: valid
        });

        emit ProofVerified(transferId, _pubSignals[0] == 1, _pubSignals[1] == 1);

        return valid;
    }

    function isVerified(bytes32 transferId) external view returns (bool) {
        return proofs[transferId].verified;
    }
}
