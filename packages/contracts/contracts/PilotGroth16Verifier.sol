// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Pairing} from "./Pairing.sol";

/// @notice Fixed eight-signal Groth16 pairing for the development pilot profile.
/// @dev Key material is immutable after deployment. This does not approve that key,
/// reconstruct current statements, authenticate policy facts or consume nullifiers.
contract PilotGroth16Verifier {
    uint256 private constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 private constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct VerificationKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[2][9] ic;
    }

    VerificationKey private _key;
    bytes32 public immutable verificationKeyCommitment;
    bytes32 public immutable artifactManifestDigest;
    string public constant proofProfile = "pilot-transfer-v2";
    string public constant assurance = "development-unapproved";

    error InvalidCoordinate();
    error InvalidKey();
    error NoncanonicalSignal();

    constructor(VerificationKey memory key, bytes32 manifestDigest) {
        if (manifestDigest == bytes32(0)) revert InvalidKey();
        _validateG1(key.alpha);
        for (uint256 i; i < 9; ++i) _validateG1(key.ic[i]);
        _validateG2(key.beta);
        _validateG2(key.gamma);
        _validateG2(key.delta);
        _key = key;
        verificationKeyCommitment = keccak256(abi.encode(key));
        artifactManifestDigest = manifestDigest;
    }

    function _g1(uint256[2] memory p) private pure returns (Pairing.G1Point memory) {
        if (p[0] >= Q || p[1] >= Q) revert InvalidCoordinate();
        return Pairing.G1Point(p[0], p[1]);
    }

    function _g2(uint256[2][2] memory p) private pure returns (Pairing.G2Point memory) {
        for (uint256 i; i < 2; ++i) {
            for (uint256 j; j < 2; ++j) if (p[i][j] >= Q) revert InvalidCoordinate();
        }
        return Pairing.G2Point(p[0], p[1]);
    }

    function _validateG1(uint256[2] memory p) private view {
        if (p[0] == 0 && p[1] == 0) revert InvalidKey();
        Pairing.scalar_mul(_g1(p), 1); // Precompile validates curve membership.
    }

    function _validateG2(uint256[2][2] memory p) private view {
        if (p[0][0] == 0 && p[0][1] == 0 && p[1][0] == 0 && p[1][1] == 0) revert InvalidKey();
        Pairing.G1Point[] memory left = new Pairing.G1Point[](2);
        Pairing.G2Point[] memory right = new Pairing.G2Point[](2);
        left[0] = Pairing.P1();
        left[1] = Pairing.negate(Pairing.P1());
        right[0] = _g2(p);
        right[1] = right[0];
        if (!Pairing.pairing(left, right)) revert InvalidKey();
    }

    /// @dev G2 coordinates use EVM precompile order, the reverse of snarkjs JSON pairs.
    /// Invalid encodings may revert; false means a well-encoded failed pairing.
    function verifyProof(
        uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c,
        uint256[8] calldata signals
    ) external view returns (bool) {
        // Check before negation so noncanonical y + Q cannot be silently reduced.
        Pairing.G1Point memory pointA = _g1(a);
        Pairing.G2Point memory pointB = _g2(b);
        Pairing.G1Point memory pointC = _g1(c);
        Pairing.G1Point memory accumulator = _g1(_key.ic[0]);
        for (uint256 i; i < 8; ++i) {
            if (signals[i] >= R) revert NoncanonicalSignal();
            accumulator = Pairing.add(accumulator, Pairing.scalar_mul(_g1(_key.ic[i + 1]), signals[i]));
        }
        return Pairing.pairingProd4(
            Pairing.negate(pointA), pointB,
            _g1(_key.alpha), _g2(_key.beta),
            accumulator, _g2(_key.gamma),
            pointC, _g2(_key.delta)
        );
    }
}
