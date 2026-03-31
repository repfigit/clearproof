// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./Groth16Verifier.sol";
import "./VASPRegistry.sol";
import "./SanctionsOracle.sol";

contract ComplianceRegistry is AccessControl, Pausable {
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    Groth16Verifier public immutable verifier;
    VASPRegistry public immutable vaspRegistry;
    SanctionsOracle public immutable sanctionsOracle;

    struct ProofRecord {
        bytes32 proofHash;
        uint256 timestamp;
        bool verified;
    }

    mapping(bytes32 => ProofRecord) public proofs;
    mapping(bytes32 => bool) public revokedCredentials;

    event ProofVerified(bytes32 indexed transferId, bool isCompliant, bool sarFlag);
    event CredentialRevoked(bytes32 indexed commitment, address revoker);

    constructor(address _verifier, address _vaspRegistry, address _sanctionsOracle) {
        verifier = Groth16Verifier(_verifier);
        vaspRegistry = VASPRegistry(_vaspRegistry);
        sanctionsOracle = SanctionsOracle(_sanctionsOracle);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REVOKER_ROLE, msg.sender);
    }

    function verifyAndRecord(
        bytes32 transferId,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[11] calldata _pubSignals,
        bytes32 vaspDidHash
    ) external whenNotPaused returns (bool) {
        // Debate gate fix: prevent transferId replay/overwrite
        require(proofs[transferId].timestamp == 0, "Transfer already recorded");
        require(!sanctionsOracle.isStale(), "Sanctions oracle is stale");
        require(vaspRegistry.isActive(vaspDidHash), "VASP not active");

        // Debate gate fix: bind msg.sender to registered VASP wallet
        (address vaspWallet,,, ) = vaspRegistry.vasps(vaspDidHash);
        require(msg.sender == vaspWallet, "Sender is not registered VASP wallet");

        bool valid = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);

        proofs[transferId] = ProofRecord({
            proofHash: keccak256(abi.encode(_pA, _pB, _pC)),
            timestamp: block.timestamp,
            verified: valid
        });

        emit ProofVerified(transferId, _pubSignals[0] == 1, _pubSignals[1] == 1);

        return valid;
    }

    function revokeCredential(bytes32 commitment) external onlyRole(REVOKER_ROLE) {
        require(!revokedCredentials[commitment], "Already revoked");
        revokedCredentials[commitment] = true;
        emit CredentialRevoked(commitment, msg.sender);
    }

    function isRevoked(bytes32 commitment) external view returns (bool) {
        return revokedCredentials[commitment];
    }

    function isVerified(bytes32 transferId) external view returns (bool) {
        return proofs[transferId].verified;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
