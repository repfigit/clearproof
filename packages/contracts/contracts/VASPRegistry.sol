// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract VASPRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    struct VASP {
        address wallet;
        string jurisdiction;
        string discoveryEndpoint; // e.g. "https://vasp.example/.well-known/clearproof"
        bool active;
        uint64 registeredAt;
    }

    mapping(bytes32 => VASP) public vasps; // keccak256(did) => VASP
    bytes32[] public vaspIds;
    bytes32 public issuerMerkleRoot;
    uint64 public issuerRootVersion;
    uint256 public activeVaspCount;  // M-6: Track active VASP count

    event VASPRegistered(bytes32 indexed didHash, address wallet, string jurisdiction, string discoveryEndpoint);
    event VASPRevoked(bytes32 indexed didHash);
    event VASPReactivated(bytes32 indexed didHash, address newWallet);  // H-5
    event DiscoveryEndpointUpdated(bytes32 indexed didHash, string endpoint);
    event IssuerRootUpdated(bytes32 oldRoot, bytes32 newRoot, uint64 version);

    constructor(address admin) {
        // M-7: Zero-address validation
        require(admin != address(0), "Zero admin");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
    }

    function registerVASP(
        bytes32 didHash,
        address wallet,
        string calldata jurisdiction,
        string calldata discoveryEndpoint
    ) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        require(vasps[didHash].registeredAt == 0, "Already registered");
        vasps[didHash] = VASP(wallet, jurisdiction, discoveryEndpoint, true, uint64(block.timestamp));
        vaspIds.push(didHash);
        activeVaspCount++;  // M-6
        emit VASPRegistered(didHash, wallet, jurisdiction, discoveryEndpoint);
    }

    function updateDiscoveryEndpoint(
        bytes32 didHash,
        string calldata newEndpoint
    ) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        require(vasps[didHash].active, "Not active");
        vasps[didHash].discoveryEndpoint = newEndpoint;
        emit DiscoveryEndpointUpdated(didHash, newEndpoint);
    }

    function getDiscoveryEndpoint(bytes32 didHash) external view returns (string memory) {
        return vasps[didHash].discoveryEndpoint;
    }

    // M-8: Added whenNotPaused — revocation requires explicit unpause for safety
    function revokeVASP(bytes32 didHash) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        require(vasps[didHash].active, "Not active");
        vasps[didHash].active = false;
        activeVaspCount--;  // M-6
        emit VASPRevoked(didHash);
    }

    // H-5: Reactivate a previously revoked VASP with a new wallet
    function reactivateVASP(bytes32 didHash, address newWallet) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        require(vasps[didHash].registeredAt != 0, "Not registered");
        require(!vasps[didHash].active, "Already active");
        vasps[didHash].active = true;
        vasps[didHash].wallet = newWallet;
        activeVaspCount++;  // M-6
        emit VASPReactivated(didHash, newWallet);
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

    /// @notice Returns the number of currently active (non-revoked) VASPs.
    function getActiveVaspCount() external view returns (uint256) {
        return activeVaspCount;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
