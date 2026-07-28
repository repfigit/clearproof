// SPDX-License-Identifier: Apache-2.0
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
//     uint256[16] parameter makes mismatched signal counts inexpressible.
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

    error PublicSignalExceedsScalarField();

    // Verification key (16 public signals)
    uint256 constant alphax = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1 = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2 = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1 = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2 = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 2974186555623760423529748672821583607714957426956571055135612844089429893870;
    uint256 constant deltax2 = 10588375097153901518979627187992625042736109069865402096572190734982036093711;
    uint256 constant deltay1 = 19115075767386990942872361475791754451415243780542039672791181011695122963135;
    uint256 constant deltay2 = 18453349290665075967093640302238344548421058363254922932792497598489616969577;

    uint256 constant IC0x = 6320402867178631099034713396176179451169551424584359885242680780062854313975;
    uint256 constant IC0y = 12016981516162831151117332517423047432593407400633746641027498150956858122565;
    uint256 constant IC1x = 11612237236320519487896771099790526467887475109294186289524281630804072429406;
    uint256 constant IC1y = 7999839460413247993360782590113275912584779806878799416462766939520137639535;
    uint256 constant IC2x = 12280131130311826237142059690896611329869781654965583809961877760208273069403;
    uint256 constant IC2y = 9399360826546113839157339166720212670529248622766662980114806038413885652858;
    uint256 constant IC3x = 235935767589638843194484738243440001651123719488028140224836726857790519651;
    uint256 constant IC3y = 2160074695756937055821624156818221966620846012533340843583511119564723227710;
    uint256 constant IC4x = 12514246984824863364758552430836523508948000400805705561132660558269013329159;
    uint256 constant IC4y = 8945897447706496697377206577330970302367473625029100631207071646435059801435;
    uint256 constant IC5x = 1189399182198744218913760200992678095171745662013576670869990791892545436293;
    uint256 constant IC5y = 6495546434115721275101647085365813133542869615625241945312901482264615433839;
    uint256 constant IC6x = 10852884109112385564176798557474108019600651273901031232533851695900032864529;
    uint256 constant IC6y = 20830004315685083046625079539648450488706248669953412069712423076825951549686;
    uint256 constant IC7x = 10150767544867940420531954861024490000403260053457110444319334803025267336461;
    uint256 constant IC7y = 15685868690474432476213057508226220120370964243711934272720816712590593060511;
    uint256 constant IC8x = 6568431607906919604133178408719368061437873761574527145194457801753462867956;
    uint256 constant IC8y = 14965819811456168747166295731527048661157583795095892966695425054879365318527;
    uint256 constant IC9x = 8131547615539762335919635735768678633166277457617611262734969038548935034116;
    uint256 constant IC9y = 3399714098683786366859385881819469574234036914629453607257089628144504182669;
    uint256 constant IC10x = 15083630918786638323142689808247084816374306976825016157081370961887072467317;
    uint256 constant IC10y = 4438386490422326385664846404774488749327696290779541432879151283661196090365;
    uint256 constant IC11x = 309911936085896535057858717570325200365353133859764045799523133901255375510;
    uint256 constant IC11y = 19785558823022412308387222151439800711675018385330293294550125182809042015308;
    uint256 constant IC12x = 17543212907982774739311131046950606295948219458798572917256884642868723900762;
    uint256 constant IC12y = 19838531576599264607634108702569591756612307345341381380769640013212898709452;
    uint256 constant IC13x = 4790067396140997324588919591499385551328501244947053437187646201064870312065;
    uint256 constant IC13y = 11219960598651965672927988423602403606193103659584051801608879290720510853399;
    uint256 constant IC14x = 15029229329386664858469073229692196307020303139700296259611287945944374494349;
    uint256 constant IC14y = 3011509882340193522254314032372601948391997411360066844129855731121346236444;
    uint256 constant IC15x = 4354478154068368148539165334446003847224901342262632115463185234997584487774;
    uint256 constant IC15y = 14795618889726955301866756601200732031875743112673123496281953558764626394980;
    uint256 constant IC16x = 12701746237094998839908554589470563785756504432109953255149349188041401300810;
    uint256 constant IC16y = 20987001795982597851013441126000106920440396942492066466689462984572210970139;

    /// Verifies a Groth16 proof: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    /// where vk_x = IC[0] + sum(pubSignals[i] * IC[i+1]).
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[16] calldata _pubSignals
    ) public view returns (bool) {
        // Every public signal must be a canonical scalar-field element.
        for (uint256 i = 0; i < 16; i++) {
            if (_pubSignals[i] >= SNARK_SCALAR_FIELD) revert PublicSignalExceedsScalarField();
        }

        // vk_x = IC[0] + sum(_pubSignals[i] * IC[i+1])
        Pairing.G1Point memory vk_x = Pairing.G1Point(IC0x, IC0y);
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC1x, IC1y), _pubSignals[0]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC2x, IC2y), _pubSignals[1]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC3x, IC3y), _pubSignals[2]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC4x, IC4y), _pubSignals[3]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC5x, IC5y), _pubSignals[4]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC6x, IC6y), _pubSignals[5]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC7x, IC7y), _pubSignals[6]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC8x, IC8y), _pubSignals[7]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC9x, IC9y), _pubSignals[8]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC10x, IC10y), _pubSignals[9]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC11x, IC11y), _pubSignals[10]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC12x, IC12y), _pubSignals[11]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC13x, IC13y), _pubSignals[12]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC14x, IC14y), _pubSignals[13]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC15x, IC15y), _pubSignals[14]));
        vk_x = Pairing.add(vk_x, Pairing.scalar_mul(Pairing.G1Point(IC16x, IC16y), _pubSignals[15]));

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
