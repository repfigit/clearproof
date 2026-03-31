// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract SanctionsOracle is AccessControl, Pausable {
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    bytes32 public currentRoot;
    uint64 public lastUpdated;
    uint32 public leafCount;
    uint256 public gracePeriod = 24 hours;  // M-2: Configurable (changed from 72h constant per audit)
    uint256 public constant UPDATE_COOLDOWN = 1 hours;

    // H-2: Ring buffer for root history
    uint256 public constant MAX_HISTORY = 1000;
    RootRecord[] public rootHistory;
    uint256 public ringBufferStart;  // Index of oldest entry when buffer is full

    struct RootRecord {
        bytes32 root;
        uint64 timestamp;
        uint32 leafCount;
    }

    event SanctionsRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint32 leafCount,
        uint64 timestamp
    );
    event GracePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);

    constructor(address admin, bytes32 initialRoot, uint32 initialLeafCount) {
        // M-7: Zero-address validation
        require(admin != address(0), "Zero admin");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ORACLE_ROLE, admin);
        currentRoot = initialRoot;
        lastUpdated = uint64(block.timestamp);
        leafCount = initialLeafCount;
        rootHistory.push(RootRecord(initialRoot, uint64(block.timestamp), initialLeafCount));
    }

    function updateRoot(bytes32 newRoot, uint32 _leafCount) external onlyRole(ORACLE_ROLE) whenNotPaused {
        require(newRoot != bytes32(0), "Zero root");
        require(block.timestamp >= lastUpdated + UPDATE_COOLDOWN, "Cooldown active");

        // H-3: Leaf count floor — prevent silently clearing the sanctions list
        require(_leafCount >= leafCount / 2, "Leaf count decreased too much");

        bytes32 old = currentRoot;
        currentRoot = newRoot;
        lastUpdated = uint64(block.timestamp);
        leafCount = _leafCount;

        // H-2: Ring buffer — cap history at MAX_HISTORY
        if (rootHistory.length < MAX_HISTORY) {
            rootHistory.push(RootRecord(newRoot, uint64(block.timestamp), _leafCount));
        } else {
            uint256 idx = ringBufferStart % MAX_HISTORY;
            rootHistory[idx] = RootRecord(newRoot, uint64(block.timestamp), _leafCount);
            ringBufferStart++;
        }

        emit SanctionsRootUpdated(old, newRoot, _leafCount, uint64(block.timestamp));
    }

    // M-2: Allow admin to configure grace period within bounds
    function setGracePeriod(uint256 newPeriod) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newPeriod >= 6 hours && newPeriod <= 168 hours, "Period out of bounds");
        uint256 oldPeriod = gracePeriod;
        gracePeriod = newPeriod;
        emit GracePeriodUpdated(oldPeriod, newPeriod);
    }

    function isStale() public view returns (bool) {
        return block.timestamp > lastUpdated + gracePeriod;
    }

    function historyLength() external view returns (uint256) {
        return rootHistory.length;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
