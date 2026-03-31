// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract VASPRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    struct VASP {
        address wallet;
        string jurisdiction;
        bool active;
        uint64 registeredAt;
    }

    mapping(bytes32 => VASP) public vasps; // keccak256(did) => VASP
    bytes32[] public vaspIds;
    bytes32 public issuerMerkleRoot;
    uint64 public issuerRootVersion;

    event VASPRegistered(bytes32 indexed didHash, address wallet, string jurisdiction);
    event VASPRevoked(bytes32 indexed didHash);
    event IssuerRootUpdated(bytes32 oldRoot, bytes32 newRoot, uint64 version);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
    }

    function registerVASP(
        bytes32 didHash,
        address wallet,
        string calldata jurisdiction
    ) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        require(vasps[didHash].registeredAt == 0, "Already registered");
        vasps[didHash] = VASP(wallet, jurisdiction, true, uint64(block.timestamp));
        vaspIds.push(didHash);
        emit VASPRegistered(didHash, wallet, jurisdiction);
    }

    function revokeVASP(bytes32 didHash) external onlyRole(REGISTRAR_ROLE) {
        require(vasps[didHash].active, "Not active");
        vasps[didHash].active = false;
        emit VASPRevoked(didHash);
    }

    function updateIssuerRoot(bytes32 newRoot) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        bytes32 old = issuerMerkleRoot;
        issuerMerkleRoot = newRoot;
        issuerRootVersion++;
        emit IssuerRootUpdated(old, newRoot, issuerRootVersion);
    }

    function isActive(bytes32 didHash) external view returns (bool) {
        return vasps[didHash].active;
    }

    function vaspCount() external view returns (uint256) {
        return vaspIds.length;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
