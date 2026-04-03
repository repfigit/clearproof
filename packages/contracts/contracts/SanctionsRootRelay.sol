// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./SanctionsOracle.sol";
import "./ISanctionsRootReceiver.sol";

/**
 * @title SanctionsRootRelay
 * @notice Adapter that receives sanctions root updates from an authorized
 *         source (relayer EOA, CCIP receiver, LayerZero endpoint) and
 *         forwards them to the SanctionsOracle.
 *
 *         This contract holds ORACLE_ROLE on the SanctionsOracle.
 *         Transport-layer authorization is managed via RELAYER_ROLE.
 *
 *         To upgrade the transport layer:
 *         1. Deploy new relay contract (e.g., SanctionsRootRelayCCIP)
 *         2. Grant ORACLE_ROLE on SanctionsOracle to the new relay
 *         3. Revoke ORACLE_ROLE from the old relay
 *         4. No oracle redeployment needed
 */
contract SanctionsRootRelay is ISanctionsRootReceiver, AccessControl {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    SanctionsOracle public immutable oracle;

    event RootRelayed(bytes32 indexed root, uint32 leafCount, address indexed relayer);

    constructor(address admin, address oracleAddress) {
        require(admin != address(0), "Zero admin");
        require(oracleAddress != address(0), "Zero oracle");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        oracle = SanctionsOracle(oracleAddress);
    }

    /**
     * @notice Receive a root update and forward to the oracle.
     *         Called by the relayer EOA (phase 1) or bridge receiver (phase 2+).
     */
    function receiveRoot(bytes32 newRoot, uint32 leafCount) external onlyRole(RELAYER_ROLE) {
        oracle.updateRoot(newRoot, leafCount);
        emit RootRelayed(newRoot, leafCount, msg.sender);
    }
}
