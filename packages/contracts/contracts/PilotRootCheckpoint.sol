// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// @notice Current root approval checkpoints independent of the credential DB.
/// @dev Scoped publishers authenticate registrar JSON/Ed25519 approvals off-chain.
/// This contract neither parses those approvals nor verifies ZK proofs.
contract PilotRootCheckpoint is AccessControl {
    uint256 private constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint64 private constant MAX_SAFE_INTEGER = 9007199254740991;
    error InvalidScope();
    error UnauthorizedPublisher();
    error StaleRevision();
    error InvalidApproval();

    struct Checkpoint {
        bytes32 snapshotDigest;
        uint256 root;
        uint64 revision;
        uint64 validFrom;
        uint64 validUntil;
        uint64 publishedAt;
    }
    mapping(bytes32 tenantHash => address) public publishers;
    mapping(bytes32 key => Checkpoint) private _heads;
    event PublisherChanged(bytes32 indexed tenantHash, address indexed publisher);
    event RootCheckpointPublished(
        bytes32 indexed tenantHash, bytes32 indexed rootScope, bytes32 indexed snapshotDigest,
        uint256 root, uint64 revision, uint64 validFrom, uint64 validUntil
    );

    constructor(address admin) {
        if (admin == address(0)) revert InvalidScope();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function setPublisher(bytes32 tenantHash, address publisher) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tenantHash == bytes32(0)) revert InvalidScope();
        // Zero address deliberately disables publication for this tenant.
        publishers[tenantHash] = publisher;
        emit PublisherChanged(tenantHash, publisher);
    }

    function head(bytes32 tenantHash, bytes32 rootScope) external view returns (Checkpoint memory) {
        return _heads[keccak256(abi.encode(tenantHash, rootScope))];
    }

    function publish(
        bytes32 tenantHash, bytes32 rootScope, bytes32 snapshotDigest, uint256 root,
        uint64 expectedRevision, uint64 approvalRevision, uint64 validFrom, uint64 validUntil
    ) external {
        if (tenantHash == bytes32(0) || rootScope == bytes32(0)) revert InvalidScope();
        if (msg.sender != publishers[tenantHash]) revert UnauthorizedPublisher();
        bytes32 key = keccak256(abi.encode(tenantHash, rootScope));
        Checkpoint storage previous = _heads[key];
        if (expectedRevision != previous.revision || approvalRevision <= previous.revision) revert StaleRevision();
        if (
            snapshotDigest == bytes32(0) || root >= SCALAR_FIELD || approvalRevision > MAX_SAFE_INTEGER ||
            validFrom > block.timestamp || validFrom < previous.validFrom || validUntil <= block.timestamp ||
            validUntil <= validFrom || validUntil - validFrom > 1 days || validUntil > MAX_SAFE_INTEGER
        ) revert InvalidApproval();
        _heads[key] = Checkpoint(snapshotDigest, root, approvalRevision, validFrom, validUntil, uint64(block.timestamp));
        emit RootCheckpointPublished(tenantHash, rootScope, snapshotDigest, root, approvalRevision, validFrom, validUntil);
    }
}
