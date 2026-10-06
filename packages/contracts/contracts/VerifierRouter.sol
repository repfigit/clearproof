// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
// LEGACY: 16-signal `compliance.circom` demo/parity path, not pilot-transfer-v3.
// Never treat proofs, roots or records accepted here as current pilot authorization.
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[16] calldata _pubSignals
    ) external view returns (bool);
}

/// @notice Permanent scheme/version bindings for the legacy Groth16 interface.
/// A different proof-system ABI requires a separately reviewed adapter/router.
contract VerifierRouter is AccessControl, Pausable {
    error ZeroAddress();
    error InvalidSelector();
    error InvalidTimelock();
    error VerifierNotContract();
    error VerifierCodeChanged();
    error SelectorAlreadyReserved();
    error VerifierNotFound();
    error VerifierAlreadyDisabled();
    error VerifierAlreadyRetiring();
    error Unauthorized();

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    uint256 public constant RETIREMENT_GRACE = 1 days;
    uint256 public immutable timelockFloor;
    uint256 public minTimelock;
    uint256 public pendingTimelock;
    uint256 public timelockUpdateAfter;

    struct VerifierInfo {
        address verifier;
        uint256 registeredAt;
        uint256 disabledAt; // Emergency disable only; never grants a grace period.
        bool active;       // Eligible for a new default selection.
        string name;
        bytes32 codeHash;
        uint256 retiredAt;
        uint256 graceEndsAt;
    }

    mapping(bytes32 => VerifierInfo) public verifiers;
    // Registration and retirement cannot overlap: selectors are reserved once.
    mapping(bytes32 => uint256) public timelocks;
    mapping(bytes32 => address) public pendingRegistrations;
    mapping(bytes32 => bool) public pendingRetirements;
    mapping(bytes32 => bytes32) public pendingCodeHashes;

    event VerifierRegistered(bytes32 indexed selector, address verifier, string name, uint256 timelock);
    event VerifierActivated(bytes32 indexed selector, address verifier);
    event VerifierDisabled(bytes32 indexed selector, address verifier);
    event VerifierRetired(bytes32 indexed selector, address verifier);
    event RetirementCompleted(bytes32 indexed selector, uint256 graceEndsAt);
    event TimelockUpdateScheduled(uint256 newTimelock, uint256 executeAfter);
    event TimelockUpdated(uint256 newTimelock);

    constructor(uint256 _minTimelock) {
        if (_minTimelock == 0) revert InvalidTimelock();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
        timelockFloor = _minTimelock;
        minTimelock = _minTimelock;
    }

    /// @notice Reserve a scheme/version selector, e.g. keccak256("groth16-bn254-v2").
    /// Neither pending nor activated bindings can ever be overwritten or reused.
    function registerVerifier(bytes32 selector, address verifier, string memory name) external onlyRole(ADMIN_ROLE) {
        if (selector == bytes32(0)) revert InvalidSelector();
        if (verifier == address(0)) revert ZeroAddress();
        if (verifier.code.length == 0) revert VerifierNotContract();
        if (verifiers[selector].verifier != address(0) || pendingRegistrations[selector] != address(0)) {
            revert SelectorAlreadyReserved();
        }
        timelocks[selector] = block.timestamp + minTimelock;
        pendingRegistrations[selector] = verifier;
        pendingCodeHashes[selector] = verifier.codehash;
        emit VerifierRegistered(selector, verifier, name, timelocks[selector]);
    }

    function activateVerifier(bytes32 selector, string memory name) external onlyRole(ADMIN_ROLE) {
        address verifier = pendingRegistrations[selector];
        if (verifier == address(0)) revert VerifierNotFound();
        if (block.timestamp < timelocks[selector]) revert Unauthorized();
        bytes32 codeHash = pendingCodeHashes[selector];
        if (verifier.codehash != codeHash) revert VerifierCodeChanged();
        verifiers[selector] = VerifierInfo({
            verifier: verifier, registeredAt: block.timestamp, disabledAt: 0,
            active: true, name: name, codeHash: codeHash, retiredAt: 0, graceEndsAt: 0
        });
        delete pendingRegistrations[selector];
        delete pendingCodeHashes[selector];
        delete timelocks[selector];
        emit VerifierActivated(selector, verifier);
    }

    /// @notice Immediately reject all proofs, including those within retirement grace.
    function disableVerifier(bytes32 selector) external onlyRole(EMERGENCY_ROLE) {
        VerifierInfo storage info = verifiers[selector];
        if (info.verifier == address(0)) revert VerifierNotFound();
        if (info.disabledAt != 0) revert VerifierAlreadyDisabled();
        info.active = false;
        info.disabledAt = block.timestamp;
        emit VerifierDisabled(selector, info.verifier);
    }

    function scheduleRetirement(bytes32 selector) external onlyRole(ADMIN_ROLE) {
        VerifierInfo storage info = verifiers[selector];
        if (info.verifier == address(0)) revert VerifierNotFound();
        if (!info.active) revert VerifierAlreadyDisabled();
        if (pendingRetirements[selector]) revert VerifierAlreadyRetiring();
        timelocks[selector] = block.timestamp + minTimelock;
        pendingRetirements[selector] = true;
        emit VerifierRetired(selector, info.verifier);
    }

    function completeRetirement(bytes32 selector) external onlyRole(ADMIN_ROLE) {
        if (!pendingRetirements[selector]) revert VerifierNotFound();
        if (block.timestamp < timelocks[selector]) revert Unauthorized();
        VerifierInfo storage info = verifiers[selector];
        if (info.disabledAt != 0) revert VerifierAlreadyDisabled();
        info.active = false;
        info.retiredAt = block.timestamp;
        info.graceEndsAt = block.timestamp + RETIREMENT_GRACE;
        delete pendingRetirements[selector];
        delete timelocks[selector];
        emit RetirementCompleted(selector, info.graceEndsAt);
    }

    function verifyProof(
        bytes32 selector,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[16] calldata _pubSignals
    ) external view whenNotPaused returns (bool) {
        VerifierInfo storage info = verifiers[selector];
        if (info.verifier == address(0)) revert VerifierNotFound();
        if (!isVerifierResolvable(selector)) revert VerifierAlreadyDisabled();
        if (info.verifier.codehash != info.codeHash) revert VerifierCodeChanged();
        // Grace accepts the old declared transfer-time cutoff, not new transfers.
        // This does not independently attest the wall-clock time of proof creation.
        if (!info.active && _pubSignals[5] > info.retiredAt) revert VerifierAlreadyDisabled();
        return IGroth16Verifier(info.verifier).verifyProof(_pA, _pB, _pC, _pubSignals);
    }

    /// @notice Historical addresses remain discoverable after all acceptance ends.
    function getVerifier(bytes32 selector) external view returns (address) {
        return verifiers[selector].verifier;
    }

    function isVerifierActive(bytes32 selector) external view returns (bool) {
        return verifiers[selector].active;
    }

    function isVerifierResolvable(bytes32 selector) public view returns (bool) {
        VerifierInfo storage info = verifiers[selector];
        return info.verifier != address(0) && info.disabledAt == 0 &&
            (info.active || (info.graceEndsAt != 0 && block.timestamp <= info.graceEndsAt));
    }

    /// @notice Schedule a delay change; the constructor floor can never be lowered.
    function updateTimelock(uint256 newTimelock) external onlyRole(ADMIN_ROLE) {
        if (newTimelock < timelockFloor) revert InvalidTimelock();
        pendingTimelock = newTimelock;
        timelockUpdateAfter = block.timestamp + minTimelock;
        emit TimelockUpdateScheduled(newTimelock, timelockUpdateAfter);
    }

    function completeTimelockUpdate() external onlyRole(ADMIN_ROLE) {
        if (timelockUpdateAfter == 0 || block.timestamp < timelockUpdateAfter) revert Unauthorized();
        minTimelock = pendingTimelock;
        delete pendingTimelock;
        delete timelockUpdateAfter;
        emit TimelockUpdated(minTimelock);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) { _pause(); }
    function unpause() external onlyRole(ADMIN_ROLE) { _unpause(); }
}
