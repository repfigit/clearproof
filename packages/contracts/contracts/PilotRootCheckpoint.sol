// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AccessControlDefaultAdminRules} from
    "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @notice Current root approval checkpoints independent of the credential DB.
/// @dev Scoped publishers authenticate registrar JSON/Ed25519 approvals off-chain.
/// This contract neither parses those approvals nor verifies ZK proofs.
/// Every `setPublisher` call increments the tenant's publisher epoch. A head is current
/// only while its recorded epoch equals the tenant epoch and the publisher is nonzero;
/// readers must check both (see `isCurrent`). Administration uses two-step default-admin
/// transfer with a delay; PAUSER_ROLE halts publication while views stay readable.
contract PilotRootCheckpoint is AccessControlDefaultAdminRules, Pausable {
    uint256 private constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint64 private constant MAX_SAFE_INTEGER = 9007199254740991;
    /// @notice Role allowed to pause publication. Only the default admin unpauses.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    /// @notice Initial delay before an accepted default-admin transfer can complete.
    uint48 public constant INITIAL_ADMIN_DELAY = 2 days;
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
        uint64 publisherEpoch;
    }
    mapping(bytes32 tenantHash => address) public publishers;
    mapping(bytes32 tenantHash => uint64) public publisherEpochs;
    mapping(bytes32 key => Checkpoint) private _heads;
    event PublisherChanged(bytes32 indexed tenantHash, address indexed publisher, uint64 epoch);
    event RootCheckpointPublished(
        bytes32 indexed tenantHash, bytes32 indexed rootScope, bytes32 indexed snapshotDigest,
        uint256 root, uint64 revision, uint64 validFrom, uint64 validUntil, uint64 publisherEpoch
    );

    /// @dev A zero admin reverts in AccessControlDefaultAdminRules before this body runs.
    constructor(address admin) AccessControlDefaultAdminRules(INITIAL_ADMIN_DELAY, admin) {
        _grantRole(PAUSER_ROLE, admin);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @dev Deliberately not pausable, so an admin can disable a compromised publisher during a pause.
    function setPublisher(bytes32 tenantHash, address publisher) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tenantHash == bytes32(0)) revert InvalidScope();
        // Zero address deliberately disables publication for this tenant. Any call,
        // including reassigning the same address, supersedes every existing head.
        publishers[tenantHash] = publisher;
        publisherEpochs[tenantHash] += 1;
        emit PublisherChanged(tenantHash, publisher, publisherEpochs[tenantHash]);
    }

    function head(bytes32 tenantHash, bytes32 rootScope) external view returns (Checkpoint memory) {
        return _heads[keccak256(abi.encode(tenantHash, rootScope))];
    }

    /// @notice Whether a published head exists under the tenant's current, enabled publisher epoch.
    /// @dev Does not check validity times; readers compare them with their own trusted clock.
    function isCurrent(bytes32 tenantHash, bytes32 rootScope) external view returns (bool) {
        Checkpoint storage current = _heads[keccak256(abi.encode(tenantHash, rootScope))];
        return current.revision != 0 && publishers[tenantHash] != address(0) &&
            current.publisherEpoch == publisherEpochs[tenantHash];
    }

    /// @dev Revisions stay monotonic across epochs: after a publisher change, a superseded
    /// approval cannot be republished; the registrar must sign a newer approval revision.
    function publish(
        bytes32 tenantHash, bytes32 rootScope, bytes32 snapshotDigest, uint256 root,
        uint64 expectedRevision, uint64 approvalRevision, uint64 validFrom, uint64 validUntil
    ) external whenNotPaused {
        if (tenantHash == bytes32(0) || rootScope == bytes32(0)) revert InvalidScope();
        if (msg.sender != publishers[tenantHash]) revert UnauthorizedPublisher();
        bytes32 key = keccak256(abi.encode(tenantHash, rootScope));
        Checkpoint storage previous = _heads[key];
        if (expectedRevision != previous.revision || approvalRevision <= previous.revision) revert StaleRevision();
        // The clock bounds imply validUntil > validFrom before subtraction.
        if (
            snapshotDigest == bytes32(0) || root >= SCALAR_FIELD || approvalRevision > MAX_SAFE_INTEGER ||
            validFrom > block.timestamp || validFrom < previous.validFrom || validUntil <= block.timestamp ||
            validUntil - validFrom > 1 days || validUntil > MAX_SAFE_INTEGER
        ) revert InvalidApproval();
        uint64 epoch = publisherEpochs[tenantHash];
        _heads[key] = Checkpoint(
            snapshotDigest, root, approvalRevision, validFrom, validUntil, uint64(block.timestamp), epoch
        );
        emit RootCheckpointPublished(
            tenantHash, rootScope, snapshotDigest, root, approvalRevision, validFrom, validUntil, epoch
        );
    }
}
