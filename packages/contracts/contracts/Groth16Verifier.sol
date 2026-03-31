// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 4500996473140808997150107582090149688032954465741586055839751356180483583641;
    uint256 constant alphay  = 17430749521268747036915572753819376705457231503810055508664265409530563449029;
    uint256 constant betax1  = 2526772812659508011104531087094776372710026154329117808405575419039045277794;
    uint256 constant betax2  = 3549546074545725461184578907511335789018252888764567254125743007714796910854;
    uint256 constant betay1  = 3844120833291598218518058462331369049544738176645401177547486990672754453908;
    uint256 constant betay2  = 2301259897362165345646378382440970411990335875376831036729847925668251083737;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 20271277432746895314756929004700269291735815052329960927121832335201699626393;
    uint256 constant deltax2 = 20414543331434743139472745547303012179627765324898833909614403818980814014353;
    uint256 constant deltay1 = 12802995612033797126992333860758830842758395450890489962904032206776190282800;
    uint256 constant deltay2 = 15825779081112585811513238159837811574821747280035937617841186643180964811405;

    
    uint256 constant IC0x = 2209581081672131494352942162797412709539306769830636680721657028371443598049;
    uint256 constant IC0y = 14125328322276800730069511331906176087397399988683476764303913645224491260559;
    
    uint256 constant IC1x = 13334280531909091851285047914000640814711256104918705836148488741740567048515;
    uint256 constant IC1y = 20889259958815191870996822759334508730646038964515380097329274734721222255590;
    
    uint256 constant IC2x = 4954411925156316334665910522288351754191190895891394518076361348096697160092;
    uint256 constant IC2y = 14704927671957633773727148569535652386186123326054730240781820658595133586829;
    
    uint256 constant IC3x = 15785432134075277913613579543268454892047107407580574740225812883596178144808;
    uint256 constant IC3y = 1725555535505112374141878876069619557169708201498897202215228315162072963466;
    
    uint256 constant IC4x = 3598383745918370042566489308112268741516624234180842946085504779219059698880;
    uint256 constant IC4y = 10044882206348009613566168264988966471964952489861321159796930441567077537209;
    
    uint256 constant IC5x = 15420843483180602751266789090663176545576351659566005777654884524891237052532;
    uint256 constant IC5y = 1976399901033711678748852253236899469433695601782147878329218068337025998849;
    
    uint256 constant IC6x = 3068760590716379053224961539707911880016560606163306714958321830157381332034;
    uint256 constant IC6y = 1448299629120853733538598142442043437453850196812642133537923607195630301703;
    
    uint256 constant IC7x = 21216369327084506364950496356213869206585625474629758584150186189947030273019;
    uint256 constant IC7y = 20900411725018915917063204158035652666866017904964670570151323431977877399242;
    
    uint256 constant IC8x = 16200351649038394404786273837926815808032631878296170869571786943977618782970;
    uint256 constant IC8y = 14258065099570044009453585173780611641784669667086205608088004619570012880321;
    
    uint256 constant IC9x = 8690465158327570776226787223225701507364682617833514879866915888375459288593;
    uint256 constant IC9y = 16155188955790652815463063051762749411665486040776308541246197846731351334940;
    
    uint256 constant IC10x = 133610427489434224556667319736418928602806541490741883262688720181159595846;
    uint256 constant IC10y = 7809841094977265772587879938373443370894866550468121647531558835342765580165;
    
    uint256 constant IC11x = 16229667876957385037709993219583647340002632724835747790748384806040573086156;
    uint256 constant IC11y = 7722586576968294898484863564072192712172782967051549511227556592244680022128;
    
    uint256 constant IC12x = 200670637065010857224743837676410990605208308775530980666589040004700498460;
    uint256 constant IC12y = 4429281038338346976906948148543773239476585517256462539026746641626747616727;
    
    uint256 constant IC13x = 19432190510117170547113210814795923155251811444419976607320017783249177908019;
    uint256 constant IC13y = 18367221429033785990788938806322578634896174907558138789100392987311065159309;
    
    uint256 constant IC14x = 6592005310952920494934604208120828758440059071880985021760284532168827948062;
    uint256 constant IC14y = 10416293338391579026706228969090728270098902680407223216165722309319819189655;
    
    uint256 constant IC15x = 7770077398555073224579202638394682958247071939105926008531118804138335003520;
    uint256 constant IC15y = 16064899287369201674044093319527168563776741595942348794346759239150824474800;
    
    uint256 constant IC16x = 806872467339354475546076581520333727852327497108441915018467050397061471693;
    uint256 constant IC16y = 3701994341080702171138952230036651869910259290335376953245720537038537563533;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[16] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
