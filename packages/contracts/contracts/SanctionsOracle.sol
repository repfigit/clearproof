// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract SanctionsOracle is AccessControl, Pausable {
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    bytes32 public currentRoot;
    uint64 public lastUpdated;
    uint32 public leafCount;
    uint256 public constant GRACE_PERIOD = 72 hours;
    uint256 public constant UPDATE_COOLDOWN = 1 hours;

    struct RootRecord {
        bytes32 root;
        uint64 timestamp;
        uint32 leafCount;
    }
    RootRecord[] public rootHistory;

    event SanctionsRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint32 leafCount,
        uint64 timestamp
    );

    constructor(address admin, bytes32 initialRoot, uint32 initialLeafCount) {
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

        bytes32 old = currentRoot;
        currentRoot = newRoot;
        lastUpdated = uint64(block.timestamp);
        leafCount = _leafCount;
        rootHistory.push(RootRecord(newRoot, uint64(block.timestamp), _leafCount));

        emit SanctionsRootUpdated(old, newRoot, _leafCount, uint64(block.timestamp));
    }

    function isStale() public view returns (bool) {
        return block.timestamp > lastUpdated + GRACE_PERIOD;
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
