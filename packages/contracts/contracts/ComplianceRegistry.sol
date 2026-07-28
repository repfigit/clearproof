// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./VASPRegistry.sol";
import "./SanctionsOracle.sol";

/// @dev Interface for the Groth16 verifier with 16 public signals.
/// The concrete Groth16Verifier.sol will be regenerated after circuit recompilation.
interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[16] calldata _pubSignals
    ) external view returns (bool);
}

contract ComplianceRegistry is AccessControl, Pausable {
    // Custom errors
    error ZeroVerifier();
    error ZeroRegistry();
    error ZeroOracle();
    error TransferAlreadyRecorded();
    error SanctionsOraclePaused();
    error VASPRegistryPaused();
    error SanctionsOracleStale();
    error VASPNotActive();
    error NotRegisteredVASPWallet();
    error WrongChain();
    error WrongContract();
    error ProofExpired();
    error ProofTimestampInFuture();
    error SanctionsRootMismatch();
    error IssuerRootMismatch();
    error TransferIDMismatch();
    error CredentialAlreadyRevoked();
    error ProofAlreadyUsed();
    error ProofVerificationFailed();
    error AlreadyRevoked();

    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    IGroth16Verifier public immutable verifier;
    VASPRegistry public immutable vaspRegistry;
    SanctionsOracle public immutable sanctionsOracle;

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
        if (_verifier == address(0)) revert ZeroVerifier();
        if (_vaspRegistry == address(0)) revert ZeroRegistry();
        if (_sanctionsOracle == address(0)) revert ZeroOracle();

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
        uint[16] calldata _pubSignals,
        bytes32 vaspDidHash
    ) external whenNotPaused returns (bool) {
        // Replay prevention
        if (proofs[transferId].timestamp != 0) revert TransferAlreadyRecorded();

        // H-6: Dependency health checks
        if (sanctionsOracle.paused()) revert SanctionsOraclePaused();
        if (vaspRegistry.paused()) revert VASPRegistryPaused();
        if (sanctionsOracle.isStale()) revert SanctionsOracleStale();
        if (!vaspRegistry.isActive(vaspDidHash)) revert VASPNotActive();

        // Sender binding
        (address vaspWallet,,,, ) = vaspRegistry.vasps(vaspDidHash);
        if (msg.sender != vaspWallet) revert NotRegisteredVASPWallet();

        // C-3: Domain binding (cross-chain replay protection)
        if (_pubSignals[11] != block.chainid) revert WrongChain();
        // Circuit signals are reduced mod BN128 scalar field order (r).
        // keccak256 produces 256-bit values that may exceed r, so we must
        // reduce the contract-side hash to match what the circuit stores.
        uint256 BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        if (uint256(keccak256(abi.encodePacked(address(this)))) % BN128_R != _pubSignals[12]) revert WrongContract();

        // Proof expiration: proof_expires_at (signal[15]) is a circuit public signal.
        // The circuit constrains proof_expires_at > transfer_timestamp.
        // Here we check the proof hasn't expired yet.
        if (block.timestamp > _pubSignals[15]) revert ProofExpired();
        if (_pubSignals[5] > block.timestamp) revert ProofTimestampInFuture();

        // C-4: State binding (proof matches current on-chain roots)
        if (bytes32(_pubSignals[2]) != sanctionsOracle.currentRoot()) revert SanctionsRootMismatch();
        if (bytes32(_pubSignals[3]) != vaspRegistry.issuerMerkleRoot()) revert IssuerRootMismatch();

        // M-1: Transfer binding (proof bound to this transfer)
        if (uint256(keccak256(abi.encodePacked(transferId))) % BN128_R != _pubSignals[13]) revert TransferIDMismatch();

        // C-5: Credential revocation check
        if (revokedCredentials[bytes32(_pubSignals[7])]) revert CredentialAlreadyRevoked();

        // M-3: Nullifier — one-time proof use (prevents same proof on different transferIds)
        bytes32 nullifier = bytes32(_pubSignals[14]);
        if (usedNullifiers[nullifier]) revert ProofAlreadyUsed();

        // C-1: Cryptographic verification — revert on invalid proof
        bool valid = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        if (!valid) revert ProofVerificationFailed();

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
        if (revokedCredentials[commitment]) revert AlreadyRevoked();
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
