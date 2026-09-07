// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {PilotGroth16Verifier} from "./PilotGroth16Verifier.sol";

/// @notice Development current-state checkpoints, proof inspection and local consumption.
/// @dev Publishers authenticate private source records off-chain (ADR 0006).
/// This contract verifies their versioned bindings, not JSON/Ed25519 source signatures.
contract PilotCurrentRegistry is AccessControl {
    uint256 private constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint64 private constant MAX_SAFE = 9007199254740991;
    enum Kind { Issuance, Issuers, Sanctions, Credential, Policy, Valuation, Participants, Authorization }
    struct Head {
        bytes32 digest;
        uint256 value;
        uint64 revision;
        uint64 validFrom;
        uint64 validUntil;
        uint64 publisherEpoch;
        bool enabled;
    }
    struct Pin { bytes32 scope; bytes32 digest; uint64 revision; }
    struct Statement {
        bytes32 contextDigest;
        bytes32 transferDigest;
        uint256 projectionCommitment;
        uint64 evaluatedAt;
        uint64 validUntil;
        address consumer;
        Pin[8] pins;
    }
    struct Approval { Statement statement; uint64 publisherEpoch; bool exists; }

    PilotGroth16Verifier public immutable verifier;
    bytes32 public immutable verifierCodeHash;
    bytes32 public immutable artifactManifestDigest;
    mapping(bytes32 => address) public publishers;
    mapping(bytes32 => uint64) public publisherEpochs;
    mapping(bytes32 => Head) private _heads;
    mapping(bytes32 => Approval) private _statements;
    mapping(bytes32 => mapping(uint256 => bool)) public consumed;

    error InvalidScope();
    error InvalidState();
    error UnauthorizedPublisher();
    error InvalidStatement();
    error StatementExists();
    error UnauthorizedConsumer();
    error AuthorizationUnavailable();
    error AlreadyConsumed();
    error InvalidProof();

    event PublisherChanged(bytes32 indexed tenant, address publisher, uint64 epoch);
    event HeadPublished(bytes32 indexed tenant, Kind indexed kind, bytes32 indexed scope, uint64 revision, bytes32 digest);
    event StatementPublished(bytes32 indexed tenant, bytes32 indexed statementId, bytes32 contextDigest);
    event AuthorizationConsumed(bytes32 indexed tenant, bytes32 indexed statementId, uint256 indexed nullifier);

    constructor(address admin, PilotGroth16Verifier pairing) {
        if (admin == address(0) || address(pairing).code.length == 0) revert InvalidScope();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        verifier = pairing;
        verifierCodeHash = address(pairing).codehash;
        artifactManifestDigest = pairing.artifactManifestDigest();
        if (artifactManifestDigest == bytes32(0)) revert InvalidScope();
    }

    function setPublisher(bytes32 tenant, address publisher) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tenant == bytes32(0)) revert InvalidScope();
        publishers[tenant] = publisher;
        publisherEpochs[tenant] += 1;
        emit PublisherChanged(tenant, publisher, publisherEpochs[tenant]);
    }

    function _headKey(bytes32 tenant, Kind kind, bytes32 scope) private pure returns (bytes32) {
        return keccak256(abi.encode(tenant, kind, scope));
    }

    function head(bytes32 tenant, Kind kind, bytes32 scope) external view returns (Head memory) {
        return _heads[_headKey(tenant, kind, scope)];
    }

    function publishHead(bytes32 tenant, Kind kind, bytes32 scope, bytes32 digest, uint256 value,
        uint64 expectedRevision, uint64 validFrom, uint64 validUntil, bool enabled) external {
        if (msg.sender != publishers[tenant]) revert UnauthorizedPublisher();
        if (scope == bytes32(0) || digest == bytes32(0) || validFrom > block.timestamp ||
            validUntil <= block.timestamp || validUntil > MAX_SAFE || validUntil <= validFrom ||
            validUntil - validFrom > 1 days || value >= R ||
            (uint8(kind) >= 3 && kind != Kind.Authorization && value != 0) ||
            (kind == Kind.Authorization && value > 1)) revert InvalidState();
        bytes32 key = _headKey(tenant, kind, scope);
        Head storage previous = _heads[key];
        if (previous.revision != expectedRevision || expectedRevision >= MAX_SAFE || validFrom < previous.validFrom) {
            revert InvalidState();
        }
        _heads[key] = Head(digest, value, expectedRevision + 1, validFrom, validUntil, publisherEpochs[tenant], enabled);
        emit HeadPublished(tenant, kind, scope, expectedRevision + 1, digest);
    }

    function statementId(bytes32 tenant, Statement calldata statement) public pure returns (bytes32) {
        return keccak256(abi.encode(tenant, statement));
    }

    function _currentHead(bytes32 tenant, Kind kind, Pin memory pin, uint64 evaluatedAt)
        private view returns (Head memory current) {
        current = _heads[_headKey(tenant, kind, pin.scope)];
        if (pin.scope == bytes32(0) || pin.digest == bytes32(0) || pin.revision == 0 || !current.enabled ||
            current.digest != pin.digest || current.revision != pin.revision ||
            current.publisherEpoch != publisherEpochs[tenant] || current.validFrom > evaluatedAt ||
            block.timestamp >= current.validUntil) revert InvalidState();
    }

    function publishStatement(bytes32 tenant, Statement calldata statement) external returns (bytes32 id) {
        if (msg.sender != publishers[tenant]) revert UnauthorizedPublisher();
        if (statement.contextDigest == bytes32(0) || statement.transferDigest == bytes32(0) ||
            statement.projectionCommitment == 0 || statement.projectionCommitment >= R ||
            statement.consumer == address(0) || statement.evaluatedAt > block.timestamp ||
            statement.validUntil <= block.timestamp || statement.validUntil > MAX_SAFE ||
            statement.validUntil > uint256(statement.evaluatedAt) + 300 ||
            statement.pins[7].scope != statement.contextDigest) revert InvalidStatement();
        for (uint8 i; i < 7; ++i) _currentHead(tenant, Kind(i), statement.pins[i], statement.evaluatedAt);
        id = statementId(tenant, statement);
        if (_statements[id].exists) revert StatementExists();
        Approval storage approved = _statements[id];
        approved.publisherEpoch = publisherEpochs[tenant];
        approved.exists = true;
        approved.statement.contextDigest = statement.contextDigest;
        approved.statement.transferDigest = statement.transferDigest;
        approved.statement.projectionCommitment = statement.projectionCommitment;
        approved.statement.evaluatedAt = statement.evaluatedAt;
        approved.statement.validUntil = statement.validUntil;
        approved.statement.consumer = statement.consumer;
        for (uint8 i; i < 8; ++i) approved.statement.pins[i] = statement.pins[i];
        emit StatementPublished(tenant, id, statement.contextDigest);
    }

    function _inspect(bytes32 tenant, bytes32 id, uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[8] calldata signals) private view returns (bool) {
        Approval storage approved = _statements[id];
        if (!approved.exists || publishers[tenant] == address(0) || approved.publisherEpoch != publisherEpochs[tenant] ||
            address(verifier).codehash != verifierCodeHash) revert InvalidStatement();
        Statement memory statement = approved.statement;
        if (keccak256(abi.encode(tenant, statement)) != id || statement.evaluatedAt > block.timestamp ||
            signals[0] != statement.projectionCommitment || signals[3] == 0 ||
            signals[4] != statement.evaluatedAt || signals[5] <= block.timestamp ||
            signals[5] > statement.validUntil || signals[6] != block.chainid || signals[7] != uint160(address(this))) {
            revert InvalidStatement();
        }
        for (uint8 i; i < 7; ++i) {
            Head memory current = _currentHead(tenant, Kind(i), statement.pins[i], statement.evaluatedAt);
            if ((i == 1 && signals[1] != current.value) || (i == 2 && signals[2] != current.value)) revert InvalidStatement();
        }
        return verifier.verifyProof(a, b, c, signals);
    }

    function inspect(bytes32 tenant, bytes32 id, uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[8] calldata signals) external view returns (bool) {
        return _inspect(tenant, id, a, b, c, signals);
    }

    function consume(bytes32 tenant, bytes32 id, uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[8] calldata signals) external {
        Approval storage approved = _statements[id];
        if (!approved.exists || msg.sender != approved.statement.consumer) revert UnauthorizedConsumer();
        if (consumed[tenant][signals[3]]) revert AlreadyConsumed();
        if (!_inspect(tenant, id, a, b, c, signals)) revert InvalidProof();
        Head memory decision = _currentHead(tenant, Kind.Authorization, approved.statement.pins[7], approved.statement.evaluatedAt);
        if (decision.value != 1) revert AuthorizationUnavailable();
        consumed[tenant][signals[3]] = true;
        emit AuthorizationConsumed(tenant, id, signals[3]);
    }
}
