#!/usr/bin/env node
/**
 * generate_verifier.mjs — render Groth16Verifier.sol from a verification key.
 *
 * Replaces `snarkjs zkey export solidityverifier` (whose output iden3 licenses
 * GPL-3.0 — see docs/adr/0001-groth16-verifier-licensing.md). The emitted
 * contract is clearproof's own Apache-2.0 implementation on top of the
 * MIT-licensed Pairing library (contracts/Pairing.sol).
 *
 * Usage:
 *   node scripts/generate_verifier.mjs <verification_key.json> <output.sol>
 */
import fs from 'fs';

const [vkeyPath, outPath] = process.argv.slice(2);
if (!vkeyPath || !outPath) {
  console.error('usage: node scripts/generate_verifier.mjs <verification_key.json> <output.sol>');
  process.exit(1);
}

const vk = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
if (vk.protocol !== 'groth16' || vk.curve !== 'bn128') {
  console.error(`unsupported key: protocol=${vk.protocol} curve=${vk.curve}`);
  process.exit(1);
}
const nPublic = vk.IC.length - 1;
if (vk.nPublic !== nPublic) {
  console.error(`IC length ${vk.IC.length} inconsistent with nPublic=${vk.nPublic}`);
  process.exit(1);
}

// snarkjs JSON encodes Fq2 as [c1, c0] relative to the order the pairing
// precompile expects; the contract constants below swap each pair.
const g1 = (p) => ({ x: p[0], y: p[1] });
const g2 = (p) => ({ x1: p[0][1], x2: p[0][0], y1: p[1][1], y2: p[1][0] });

const alpha = g1(vk.vk_alpha_1);
const beta = g2(vk.vk_beta_2);
const gamma = g2(vk.vk_gamma_2);
const delta = g2(vk.vk_delta_2);
const IC = vk.IC.map(g1);

const icConstants = IC.map(
  (p, i) => `    uint256 constant IC${i}x = ${p.x};\n    uint256 constant IC${i}y = ${p.y};`,
).join('\n');

const vkXAccumulation = IC.slice(1)
  .map(
    (p, i) =>
      `        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC${i + 1}x, IC${i + 1}y), _pubSignals[${i}]));`,
  )
  .join('\n');

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
// Regenerate: node scripts/generate_verifier.mjs <verification_key.json> <output>
//
// Independent Groth16 (BN128) verifier, implemented from the protocol
// specification on the MIT-licensed Pairing library. This is NOT the
// snarkjs-generated verifier (GPL-3.0); see
// docs/adr/0001-groth16-verifier-licensing.md.
//
// Security properties (clearproof implementation):
//   - Public-signal count is enforced at the ABI level: the fixed-size
//     uint256[${nPublic}] parameter makes mismatched signal counts inexpressible.
//   - Every public signal is range-checked to be a canonical scalar-field
//     element (< SNARK_SCALAR_FIELD) before use.
//   - Malformed curve points are rejected by the pairing precompiles
//     (staticcall success checks in Pairing.sol).
// -----------------------------------------------------------------------------

pragma solidity ^0.8.24;

import {Pairing} from "./Pairing.sol";

contract Groth16Verifier {
    /// The prime q of the base field F_q for G1.
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    /// The order r of the scalar field. Public signals must be < r.
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Verification key (${nPublic} public signals)
    uint256 constant alphax = ${alpha.x};
    uint256 constant alphay = ${alpha.y};
    uint256 constant betax1 = ${beta.x1};
    uint256 constant betax2 = ${beta.x2};
    uint256 constant betay1 = ${beta.y1};
    uint256 constant betay2 = ${beta.y2};
    uint256 constant gammax1 = ${gamma.x1};
    uint256 constant gammax2 = ${gamma.x2};
    uint256 constant gammay1 = ${gamma.y1};
    uint256 constant gammay2 = ${gamma.y2};
    uint256 constant deltax1 = ${delta.x1};
    uint256 constant deltax2 = ${delta.x2};
    uint256 constant deltay1 = ${delta.y1};
    uint256 constant deltay2 = ${delta.y2};

${icConstants}

    /// Verifies a Groth16 proof: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    /// where vk_x = IC[0] + sum(pubSignals[i] * IC[i+1]).
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[${nPublic}] calldata _pubSignals
    ) public view returns (bool) {
        // Every public signal must be a canonical scalar-field element.
        for (uint256 i = 0; i < ${nPublic}; i++) {
            require(_pubSignals[i] < SNARK_SCALAR_FIELD, "public signal >= scalar field");
        }

        // vk_x = IC[0] + sum(_pubSignals[i] * IC[i+1])
        Pairing.G1Point memory vk_x = Pairing.G1Point(IC0x, IC0y);
${vkXAccumulation}

        return Pairing.pairingProd4(
            Pairing.negate(Pairing.G1Point(_pA[0], _pA[1])),
            Pairing.G2Point([_pB[0][0], _pB[0][1]], [_pB[1][0], _pB[1][1]]),
            Pairing.G1Point(alphax, alphay),
            Pairing.G2Point([betax1, betax2], [betay1, betay2]),
            vk_x,
            Pairing.G2Point([gammax1, gammax2], [gammay1, gammay2]),
            Pairing.G1Point(_pC[0], _pC[1]),
            Pairing.G2Point([deltax1, deltax2], [deltay1, deltay2])
        );
    }
}
`;

fs.writeFileSync(outPath, contract);
console.log(`Wrote ${outPath} (${nPublic} public signals, ${vk.IC.length} IC points)`);
