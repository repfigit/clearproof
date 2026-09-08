// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Pairing} from "./Pairing.sol";

/// @dev Test-only access to internal library operations; not an authorization verifier.
contract PairingHarness {
    function generators() external pure returns (Pairing.G1Point memory, Pairing.G2Point memory) {
        return (Pairing.P1(), Pairing.P2());
    }

    function negate(Pairing.G1Point memory p) external pure returns (Pairing.G1Point memory) {
        return Pairing.negate(p);
    }

    function add(Pairing.G1Point memory a, Pairing.G1Point memory b) external view returns (Pairing.G1Point memory) {
        return Pairing.add(a, b);
    }

    function multiply(Pairing.G1Point memory p, uint256 scalar) external view returns (Pairing.G1Point memory) {
        return Pairing.scalar_mul(p, scalar);
    }

    function pairing(Pairing.G1Point[] memory a, Pairing.G2Point[] memory b) external view returns (bool) {
        return Pairing.pairing(a, b);
    }
}
