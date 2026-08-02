// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

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

contract VerifierRouter is AccessControl, Pausable, ReentrancyGuard {
    // Custom errors
    error ZeroAddress();
    error VerifierNotFound();
    error VerifierAlreadyDisabled();
    error Unauthorized();
    
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    
    // Minimum timelock period (in seconds)
    uint256 public minTimelock;
    
    struct VerifierInfo {
        address verifier;           // Address of the verifier contract
        uint256 registeredAt;       // Timestamp when verifier was registered
        uint256 disabledAt;         // Timestamp when verifier was disabled (0 if active)
        bool active;                // Whether the verifier is currently active
        string name;                // Human-readable name for the verifier
    }
    
    // Mapping from selector to verifier info
    mapping(bytes32 => VerifierInfo) public verifiers;
    
    // Timelock for verifier registration and retirement
    mapping(bytes32 => uint256) public timelocks;
    mapping(bytes32 => address) public pendingRegistrations;
    mapping(bytes32 => bool) public pendingRetirements;
    
    // Event declarations
    event VerifierRegistered(bytes32 indexed selector, address verifier, string name, uint256 timelock);
    event VerifierActivated(bytes32 indexed selector, address verifier);
    event VerifierDisabled(bytes32 indexed selector, address verifier);
    event VerifierRetired(bytes32 indexed selector, address verifier);
    event TimelockUpdated(uint256 newTimelock);
    
    constructor(uint256 _minTimelock) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
        minTimelock = _minTimelock;
    }
    
    /// @notice Register a new verifier with a selector
    /// @param selector Unique identifier for the verifier (e.g., keccak256("groth16-bn254-v1"))
    /// @param verifier Address of the verifier contract
    /// @param name Human-readable name for the verifier
    function registerVerifier(bytes32 selector, address verifier, string memory name) 
        external 
        onlyRole(ADMIN_ROLE)
    {
        if (verifier == address(0)) revert ZeroAddress();
        
        // Set timelock for the registration
        timelocks[selector] = block.timestamp + minTimelock;
        pendingRegistrations[selector] = verifier;
        
        emit VerifierRegistered(selector, verifier, name, timelocks[selector]);
    }
    
    /// @notice Activate a verifier after the timelock period
    /// @param selector Unique identifier for the verifier
    function activateVerifier(bytes32 selector, string memory name) 
        external 
        onlyRole(ADMIN_ROLE)
    {
        if (block.timestamp < timelocks[selector]) revert Unauthorized();
        if (pendingRegistrations[selector] == address(0)) revert VerifierNotFound();
        
        address verifier = pendingRegistrations[selector];
        
        verifiers[selector] = VerifierInfo({
            verifier: verifier,
            registeredAt: block.timestamp,
            disabledAt: 0,
            active: true,
            name: name
        });
        
        delete pendingRegistrations[selector];
        delete timelocks[selector];
        
        emit VerifierActivated(selector, verifier);
    }
    
    /// @notice Disable a verifier immediately (emergency kill switch)
    /// @param selector Unique identifier for the verifier
    function disableVerifier(bytes32 selector) 
        external 
        onlyRole(EMERGENCY_ROLE)
    {
        if (verifiers[selector].verifier == address(0)) revert VerifierNotFound();
        if (!verifiers[selector].active) revert VerifierAlreadyDisabled();
        
        verifiers[selector].active = false;
        verifiers[selector].disabledAt = block.timestamp;
        
        emit VerifierDisabled(selector, verifiers[selector].verifier);
    }
    
    /// @notice Schedule retirement of a verifier with timelock
    /// @param selector Unique identifier for the verifier
    function scheduleRetirement(bytes32 selector) 
        external 
        onlyRole(ADMIN_ROLE)
    {
        if (verifiers[selector].verifier == address(0)) revert VerifierNotFound();
        
        // Set timelock for retirement
        timelocks[selector] = block.timestamp + minTimelock;
        pendingRetirements[selector] = true;
        
        emit VerifierRetired(selector, verifiers[selector].verifier);
    }
    
    /// @notice Complete retirement of a verifier after timelock
    /// @param selector Unique identifier for the verifier
    function completeRetirement(bytes32 selector) 
        external 
        onlyRole(ADMIN_ROLE)
    {
        if (block.timestamp < timelocks[selector]) revert Unauthorized();
        if (!pendingRetirements[selector]) revert VerifierNotFound();
        
        // Disable the verifier
        verifiers[selector].active = false;
        verifiers[selector].disabledAt = block.timestamp;
        
        delete pendingRetirements[selector];
        delete timelocks[selector];
    }
    
    /// @notice Verify a proof using the specified verifier
    /// @param selector Unique identifier for the verifier
    /// @param _pA First parameter for proof verification
    /// @param _pB Second parameter for proof verification
    /// @param _pC Third parameter for proof verification
    /// @param _pubSignals Array of public signals
    /// @return Whether the proof is valid
    function verifyProof(
        bytes32 selector,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[16] calldata _pubSignals
    ) external view whenNotPaused returns (bool) {
        VerifierInfo memory info = verifiers[selector];
        if (info.verifier == address(0)) revert VerifierNotFound();
        if (!info.active) revert VerifierAlreadyDisabled();
        
        return IGroth16Verifier(info.verifier).verifyProof(_pA, _pB, _pC, _pubSignals);
    }
    
    /// @notice Get the address of a verifier
    /// @param selector Unique identifier for the verifier
    /// @return Address of the verifier contract
    function getVerifier(bytes32 selector) external view returns (address) {
        return verifiers[selector].verifier;
    }
    
    /// @notice Check if a verifier is active
    /// @param selector Unique identifier for the verifier
    /// @return Whether the verifier is active
    function isVerifierActive(bytes32 selector) external view returns (bool) {
        return verifiers[selector].active;
    }
    
    /// @notice Update the timelock period
    /// @param newTimelock New timelock period in seconds
    function updateTimelock(uint256 newTimelock) 
        external 
        onlyRole(ADMIN_ROLE)
    {
        minTimelock = newTimelock;
        emit TimelockUpdated(newTimelock);
    }
    
    /// @notice Pause the router (emergency stop)
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }
    
    /// @notice Unpause the router
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}