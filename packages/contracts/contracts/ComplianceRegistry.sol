// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./VASPRegistry.sol";
import "./SanctionsOracle.sol";

/// @dev Interface for the Groth16 verifier with 15 public signals.
/// The concrete Groth16Verifier.sol will be regenerated after circuit recompilation.
interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[15] calldata _pubSignals
    ) external view returns (bool);
}

contract ComplianceRegistry is AccessControl, Pausable {
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    IGroth16Verifier public immutable verifier;
    VASPRegistry public immutable vaspRegistry;
    SanctionsOracle public immutable sanctionsOracle;

    /// @dev Maximum age of a proof (seconds) before it is considered expired.
    /// Matches the 300s TTL set by the prover in proof_expires_at.
    uint256 public constant MAX_PROOF_AGE = 300;

    struct ProofRecord {
        bytes32 proofHash;
        uint256 timestamp;
        bool verified;
    }

    mapping(bytes32 => ProofRecord) public proofs;
    mapping(bytes32 => bool) public revokedCredentials;
    mapping(bytes32 => bool) public usedNullifiers;

    event ProofVerified(bytes32 indexed transferId, bytes32 indexed nullifier, bool isCompliant, bool sarFlag);
    event CredentialRevoked(bytes32 indexed commitment, address revoker);

    constructor(address _verifier, address _vaspRegistry, address _sanctionsOracle) {
        // M-7: Zero-address validation
        require(_verifier != address(0), "Zero verifier");
        require(_vaspRegistry != address(0), "Zero registry");
        require(_sanctionsOracle != address(0), "Zero oracle");

        verifier = IGroth16Verifier(_verifier);
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
        uint[15] calldata _pubSignals,
        bytes32 vaspDidHash
    ) external whenNotPaused returns (bool) {
        // Replay prevention
        require(proofs[transferId].timestamp == 0, "Transfer already recorded");

        // H-6: Dependency health checks
        require(!sanctionsOracle.paused(), "Sanctions oracle paused");
        require(!vaspRegistry.paused(), "VASP registry paused");
        require(!sanctionsOracle.isStale(), "Sanctions oracle stale");
        require(vaspRegistry.isActive(vaspDidHash), "VASP not active");

        // Sender binding
        (address vaspWallet,,, ) = vaspRegistry.vasps(vaspDidHash);
        require(msg.sender == vaspWallet, "Not registered VASP wallet");

        // C-3: Domain binding (cross-chain replay protection)
        require(_pubSignals[11] == block.chainid, "Wrong chain");
        require(uint256(keccak256(abi.encodePacked(address(this)))) == _pubSignals[12], "Wrong contract");

        // Proof expiration: transfer_timestamp (signal[5]) must be within MAX_PROOF_AGE
        require(block.timestamp <= _pubSignals[5] + MAX_PROOF_AGE, "Proof expired");
        require(_pubSignals[5] <= block.timestamp, "Proof timestamp in future");

        // C-4: State binding (proof matches current on-chain roots)
        require(bytes32(_pubSignals[2]) == sanctionsOracle.currentRoot(), "Sanctions root mismatch");
        require(bytes32(_pubSignals[3]) == vaspRegistry.issuerMerkleRoot(), "Issuer root mismatch");

        // M-1: Transfer binding (proof bound to this transfer)
        require(uint256(keccak256(abi.encodePacked(transferId))) == _pubSignals[13], "Transfer ID mismatch");

        // C-5: Credential revocation check
        require(!revokedCredentials[bytes32(_pubSignals[7])], "Credential revoked");

        // M-3: Nullifier — one-time proof use (prevents same proof on different transferIds)
        bytes32 nullifier = bytes32(_pubSignals[14]);
        require(!usedNullifiers[nullifier], "Proof already used");

        // C-1: Cryptographic verification — revert on invalid proof
        bool valid = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        require(valid, "Proof verification failed");

        // Record
        usedNullifiers[nullifier] = true;
        proofs[transferId] = ProofRecord({
            proofHash: keccak256(abi.encode(_pA, _pB, _pC, _pubSignals)),  // H-1: includes pubSignals
            timestamp: block.timestamp,
            verified: true  // Always true now (we revert on invalid)
        });

        // Hash the nullifier before emitting to prevent blockchain observers
        // from correlating transfer patterns across ProofVerified events.
        bytes32 blindedNullifier = keccak256(abi.encodePacked(nullifier));
        emit ProofVerified(transferId, blindedNullifier, _pubSignals[0] == 1, _pubSignals[1] == 1);
        return true;
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
