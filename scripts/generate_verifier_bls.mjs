#!/usr/bin/env node
/**
 * generate_verifier_bls.mjs — render Groth16VerifierBLS.sol (BLS12-381,
 * EIP-2537 precompiles) from a snarkjs verification key.
 *
 * Benchmark/preview implementation for ADR 0002 (docs/adr/0002-bls12381-migration.md).
 * BLS12-381 Groth16 verification on the EVM requires the Pectra (Prague)
 * hardfork; the emitted contract calls precompiles G1MSM (0x0c) and
 * PAIRING (0x0f) directly.
 *
 * Usage:
 *   node scripts/generate_verifier_bls.mjs <verification_key_bls.json> <output.sol>
 */
import fs from 'fs';

const [vkeyPath, outPath] = process.argv.slice(2);
if (!vkeyPath || !outPath) {
  console.error('usage: node scripts/generate_verifier_bls.mjs <verification_key_bls.json> <output.sol>');
  process.exit(1);
}

const vk = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
if (vk.protocol !== 'groth16' || vk.curve !== 'bls12381') {
  console.error(`unsupported key: protocol=${vk.protocol} curve=${vk.curve} (expected groth16/bls12381)`);
  process.exit(1);
}
const nPublic = vk.IC.length - 1;

// BLS12-381 base field modulus q (381 bits), split into 256-bit limbs for
// the G1 negation (q - y) the contract performs in assembly.
const Q = BigInt('0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab');
const Q_HI = Q >> 256n;
const Q_LO = Q & ((1n << 256n) - 1n);

// Encode an Fp element as a 64-byte big-endian limb (EIP-2537 encoding).
const fp = (v) => BigInt(v).toString(16).padStart(128, '0');

// G1 point -> 128 bytes (x || y), G2 point -> 256 bytes.
// snarkjs encodes Fp2 coordinates as [c1, c0] relative to the order the
// pairing precompile expects (same convention as BN128); swap each pair.
const g1Hex = (p) => `hex"${fp(p[0])}${fp(p[1])}"`;
const g2Hex = (p) => `hex"${fp(p[0][0])}${fp(p[0][1])}${fp(p[1][0])}${fp(p[1][1])}"`;

const alpha = g1Hex(vk.vk_alpha_1);
const beta = g2Hex(vk.vk_beta_2);
const gamma = g2Hex(vk.vk_gamma_2);
const delta = g2Hex(vk.vk_delta_2);
const IC = vk.IC.map(g1Hex);

const icConstants = IC.map((h, i) => `    bytes constant IC${i} = ${h};`).join('\n');

// MSM input: IC0 scaled by 1, IC[i+1] scaled by pubSignals[i].
// Split into chunks to avoid "stack too deep" in a single encodePacked.
const chunks = [];
for (let c = 0; c < IC.length; c += 6) {
  const parts = [];
  for (let i = c; i < Math.min(c + 6, IC.length); i++) {
    const scalar = i === 0 ? 'bytes32(uint256(1))' : `bytes32(_pubSignals[${i - 1}])`;
    parts.push(`IC${i}, ${scalar}`);
  }
  chunks.push(`abi.encodePacked(${parts.join(', ')})`);
}
const msmParts = chunks.join(',\n            ');

const contract = `// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 clearproof contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// -----------------------------------------------------------------------------
// GENERATED FILE — do not edit constants by hand.
// Regenerate: node scripts/generate_verifier_bls.mjs <vkey.json> <output.sol>
//
// Groth16 (BLS12-381) verifier over the EIP-2537 precompiles (Pectra+).
// Benchmark implementation for ADR 0002; not yet audited.
//
// Points use EIP-2537 encoding: Fp = 64-byte BE limb; G1 = 128 bytes (x||y);
// G2 = 256 bytes ((x_c0, x_c1), (y_c0, y_c1)).
pragma solidity ^0.8.24;

contract Groth16VerifierBLS {
    // EIP-2537 precompile addresses
    address internal constant G1MSM_PRECOMPILE = address(0x0c);
    address internal constant PAIRING_PRECOMPILE = address(0x0f);

    // BLS12-381 base field modulus, 256-bit limbs (for G1 negation)
    uint256 internal constant Q_HI = ${Q_HI};
    uint256 internal constant Q_LO = ${Q_LO};

    uint256 internal constant N_PUBLIC = ${nPublic};

    // Verification key (EIP-2537 encodings)
    bytes constant ALPHA = ${alpha};
    bytes constant BETA = ${beta};
    bytes constant GAMMA = ${gamma};
    bytes constant DELTA = ${delta};
${icConstants}

    /// @notice Verify a Groth16 proof over BLS12-381.
    /// @param _proof 576-byte proof: pA (G1, 128B) || pB (G2, 256B) || pC (G1, 128B)
    /// @param _pubSignals public signals (each < BLS12-381 scalar field r)
    function verifyProof(
        bytes calldata _proof,
        uint256[] calldata _pubSignals
    ) external view returns (bool) {
        require(_proof.length == 512, "Proof must be 512 bytes (G1 || G2 || G1)");
        require(_pubSignals.length == N_PUBLIC, "Wrong public signal count");

        bytes memory vkX = _computeVkX(_pubSignals);
        bytes memory negA = _negateG1(_proof[0:128]);
        return _pairingCheck(negA, _proof[128:384], vkX, _proof[384:512]);
    }

    /// @dev vk_x = IC0 + sum(pubSignals[i] * IC[i+1]) via the G1MSM precompile.
    function _computeVkX(uint256[] calldata _pubSignals) internal view returns (bytes memory vkX) {
        bytes memory msmInput = bytes.concat(
            ${msmParts}
        );
        vkX = new bytes(128);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x0c, add(msmInput, 32), mload(msmInput), add(vkX, 32), 128)
        }
        require(ok, "G1MSM precompile failed");
    }

    /// @dev Negate a G1 point: (x, y) -> (x, q - y), 384-bit limb arithmetic.
    function _negateG1(bytes calldata point) internal pure returns (bytes memory neg) {
        neg = point[:];
        assembly {
            let dst := add(neg, 32)
            // y limb: [64:96]=hi (16B used), [96:128]=lo; y' = q - y
            let yHi := mload(add(dst, 64))
            let yLo := mload(add(dst, 96))
            let borrow := lt(Q_LO, yLo)
            mstore(add(dst, 64), sub(sub(Q_HI, yHi), borrow))
            mstore(add(dst, 96), sub(Q_LO, yLo))
        }
    }

    /// @dev e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    function _pairingCheck(
        bytes memory negA,
        bytes calldata pB,
        bytes memory vkX,
        bytes calldata pC
    ) internal view returns (bool) {
        bytes memory pairingInput = bytes.concat(
            negA, pB,
            ALPHA, BETA,
            vkX, GAMMA,
            pC, DELTA
        );
        bytes memory result = new bytes(32);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x0f, add(pairingInput, 32), mload(pairingInput), add(result, 32), 32)
        }
        require(ok, "PAIRING precompile failed");
        return abi.decode(result, (uint256)) == 1;
    }
}
`;

fs.writeFileSync(outPath, contract);
console.log(`Wrote ${outPath} (BLS12-381, ${nPublic} public signals, ${IC.length} IC points)`);
