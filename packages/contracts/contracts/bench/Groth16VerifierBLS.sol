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
    uint256 internal constant Q_HI = 34565483545414906068789196026815425751;
    uint256 internal constant Q_LO = 45442060874369865957053122457065728162598490762543039060009208264153100167851;

    uint256 internal constant N_PUBLIC = 16;

    // Verification key (EIP-2537 encodings)
    bytes constant ALPHA = hex"0000000000000000000000000000000007052ac25c8174d68c3ccf74a9a5aa45fcab0a85cbd744e92e49c74b309f6ba1dd514aa40c487d82e67f68312fd59baf000000000000000000000000000000000e47efdfb3aa439ddf7227dbefa230a24305cb3f1e6153363069e1ed0dd2c223ae78834227d6679a0d075304afbd667e";
    bytes constant BETA = hex"00000000000000000000000000000000176bc78390ab973aee8d3a4f1435ad04909d9329e8925700e23823afecc676f34faa0a9d03278390fcaf75203e5dd22500000000000000000000000000000000199a69c8578edb77cf1b8fdf4615122e9d7e3b8e71bbe06926066a6c3dd733d43ec894a7eef5b360ecc6d90f016b538f00000000000000000000000000000000081ea159928872494adafccaf79137c9d21b17cf95cd661b490b00149e49ac0668248bda8a909293eaeac14335a94c01000000000000000000000000000000000de272f24956ec3fae1e49bd09d379aa5974ebd66127eec1e29ed2a2e46dd04060495521560cb38d501fef7d8fd8999d";
    bytes constant GAMMA = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
    bytes constant DELTA = hex"0000000000000000000000000000000012c235cd0dff21c90a874f40194a90bb0ae28ad8a9e1e0d4bb28c867b8a9ed399774c4c4a4bbac8987895b874083209700000000000000000000000000000000051628e805cdffe595ac56d89d6980e17aeb75e7829d5f8e2238bd6971ad7d42aca6030a6922c7a0a984c6bcd42a354000000000000000000000000000000000056cb05353be57f36e8e8b3fe252d73494868849f84c5771287377c0cca83d11c62e961eaf4f39aae27585bda6e34bd7000000000000000000000000000000000af47b229fe71ec574e734d329afda71bcefd6eaf7c1f8b0520db0598d556acbeaad9bf62b5266111286a952ec351bdb";
    bytes constant IC0 = hex"000000000000000000000000000000000b44a9cf91a0819d99e675afb4991c1aeb62f16fa1684f4dcb3abbef8f93d17c801b002337bc8e85e7165bca6a19ad2c000000000000000000000000000000000bde393e39b0d8f1abbd8594e93a77b5a37ce239e32e038a5470722c7b658ddf0fc37ed6b93b4321dff90d2af3f1dfdf";
    bytes constant IC1 = hex"000000000000000000000000000000000b212f6892cbc4bbbeeab38360da635cdb7fd14eeeabb20ca6bbce4e6b7c82aa2c3809f3655471e97b583dfaab2a1f2d0000000000000000000000000000000010969cf5a414796388e99a12d2921a319a9cbe0a35b070f4e07fa5172cd96f06f83e51250dbe7fa3f8108c730121ea53";
    bytes constant IC2 = hex"000000000000000000000000000000000c47199cf838eb957a41b7b5434ae82605662e5faac49933df54922f5f430600106373503437e79dcd919d9c9b951a1a000000000000000000000000000000000116548093120fdb220f819bdbca1164cc126939ebf93f69aa9d2899f80cc08fa8da71928792867d0a58b265f9d088a3";
    bytes constant IC3 = hex"000000000000000000000000000000000288965e6de9a6fddf856ca6cd50e03c633087b6c5fd4c321ca9634b6b2abc58ea5d7505f30a07cc98e738c57f01106d0000000000000000000000000000000012f6908276cfad592e34bae58ca157dc43b78fb52902b56169bdae74d5fda9bd78336a8432533bae531cb52c26497c23";
    bytes constant IC4 = hex"00000000000000000000000000000000193fafc9ccefe38b2e62cd92ae119cde6a3d46a6d282c94ed60702a542090f1bb2613ab6f1fc8501388fe2055004e886000000000000000000000000000000001031cc6ce8e2c56a4f944fcd07a1174e59ea26cf52871da643a6ca59d49bbdee6e4f18fd1fbdf8b2c1a52b60b04bedd7";
    bytes constant IC5 = hex"000000000000000000000000000000000358050c6f5ca4b7a26012c8d9b3843fc3696f241a8ef569627a791d930f07a431625dba3c7c789b5dc123e6092bd03c0000000000000000000000000000000004c862a03af198e5d356b0d20251a7cb0a463a6caaabccd44125cc0e27d1fac434aebf392a6933e47eb7383d25fc0f80";
    bytes constant IC6 = hex"000000000000000000000000000000000cd898802f34737dda55593aa140657150dd82c296c9ff1bcb8c8ee219555729f6ea0a47d7df1379ce5647d9560ca6e10000000000000000000000000000000006243e1b4c1541e45f9b12f466aebb6a87df58dd4993a354ecd56f69478c8c91534f7cd618232c98d8c798d787d5e6f0";
    bytes constant IC7 = hex"0000000000000000000000000000000007019c05abbf779a8a77771578c7f06293328d676199e15cf604ec3e71af87b30e477b4bc4cd854e211e4f877ff89f12000000000000000000000000000000001384cc15729ce8ecf98fb9110ff0cc01767f713efd16d5b5be33caed239a51c2bd166fd5e7e1daf9d5573d0cb456466e";
    bytes constant IC8 = hex"0000000000000000000000000000000004dcddc74ede686ad7c366b7dd1b5009f60fc339a39ba20527eebfba7b6469b5d6ecd9a84c9b4e4c87e87b6cb8e97b4000000000000000000000000000000000037501970bf6aa06777d3ecb7a830e538f4e43b2a4d71104d4309e226412024b2c4dd26a2cc370e855737c186e888a41";
    bytes constant IC9 = hex"000000000000000000000000000000000ae9253f27002d5a8f1b63529ce9d9000cc9cd93bc27040fd885340c8678bfd5aeae333e97891077dfebdd766665465000000000000000000000000000000000019c356555305f804abb5bf2c8d53dc6b95dd88458ed7a934e3f49317b936c80f5652df4c0e9f817dd069214905085d2";
    bytes constant IC10 = hex"00000000000000000000000000000000028362e4bb2b941ecbb4d40b55855075288496c2781bc6785b3ddde0c3a128d0848ab60f6bb0880a3fe12c2cbca3c47800000000000000000000000000000000026d0fe733a26ce9f4a2d8109d2b62988aa60d0f96c35f35aa9ebd6b43ff69811cd685dde445f4a71ce38308252345c3";
    bytes constant IC11 = hex"0000000000000000000000000000000017a7f7ce3bf32f67348a4024a41b0bb52665f952055f297eaff649f4373e7ae524f07a1332e615793ed8009823ebf604000000000000000000000000000000000e58b2533b47262e945ac75f181dd935bf9377b5a51458bfef7ed4c8bd8e6fab48615501d8f4cec5b2ce2009e4de5053";
    bytes constant IC12 = hex"0000000000000000000000000000000015b4afad69aa5004351acdedf135ea8c119136e4a9cc5264ad5fdb7ac0e5c672e2e7db1fb78f7f199209b435805e149b00000000000000000000000000000000076c13e81b51a85b2359ec8a74e58d50dd4390caccb722e9d418f498f76b73d05258b7f6469a3d297bfd1bcce79c48a3";
    bytes constant IC13 = hex"000000000000000000000000000000000230535028c450282775bdbc473f44acaa00f66432c0b93597fdc515518ec6be771afb9aab24170f2c1c4621ec9e88160000000000000000000000000000000004d1bc54ccab6d686e6eaa1e5346b4f6da4b0a04930b215c01467daa5c70e781ea83f45a1811e4659cd6168cb0f4aedb";
    bytes constant IC14 = hex"0000000000000000000000000000000003d9483b2738978b77d9bda476ecb635dbe8606942071e73dc30ef6d2d2b6b54282f4e5a057773cd087b905f8c2bb7c500000000000000000000000000000000095aa27ee0baaedbc3e545b9001c82c80fb7b1b2f9617b3946da04f4968b426e6601f179ada9f144ab6faf97fe613c45";
    bytes constant IC15 = hex"000000000000000000000000000000000d6f250ecee36fe47789791fd7fe1c3f2be7cad885362874de470c603d0ba8ec6496d2e6b43e8649fa2a86c3471303aa0000000000000000000000000000000015675af24c902bf92fc34b4346612c7b44d2c5a6d9177aea288ce4110c97762b7927bf175211ccb26ab940920292fa45";
    bytes constant IC16 = hex"000000000000000000000000000000000e7d2f3424d49642a3aa383209d3ebf24fc08c9de6830557f8ec19e663f9db8f64205eb5ef79739a508e9991f9b56dd20000000000000000000000000000000008f89dfb735c2e849f234046630ba1f02f3634f39a3f661a9b93fd20782ae744bbbc9d705cd26929c4293fdb992bd548";

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
            abi.encodePacked(IC0, bytes32(uint256(1)), IC1, bytes32(_pubSignals[0]), IC2, bytes32(_pubSignals[1]), IC3, bytes32(_pubSignals[2]), IC4, bytes32(_pubSignals[3]), IC5, bytes32(_pubSignals[4])),
            abi.encodePacked(IC6, bytes32(_pubSignals[5]), IC7, bytes32(_pubSignals[6]), IC8, bytes32(_pubSignals[7]), IC9, bytes32(_pubSignals[8]), IC10, bytes32(_pubSignals[9]), IC11, bytes32(_pubSignals[10])),
            abi.encodePacked(IC12, bytes32(_pubSignals[11]), IC13, bytes32(_pubSignals[12]), IC14, bytes32(_pubSignals[13]), IC15, bytes32(_pubSignals[14]), IC16, bytes32(_pubSignals[15]))
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
