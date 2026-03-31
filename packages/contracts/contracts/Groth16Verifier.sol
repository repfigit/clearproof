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
    uint256 constant alphax  = 14520529041790456786995074540012157593114958168944110579383159897030270421683;
    uint256 constant alphay  = 12190044747698844131408403166438846980657017889827211487113361059707207182672;
    uint256 constant betax1  = 3099300253378967695622319524995410925435112289546553940785697138041984453350;
    uint256 constant betax2  = 8591562137143704349741918814436587940548574783735952328854272429056062986345;
    uint256 constant betay1  = 19732336449763641045562402464710747257728246716611257381901316297113485311837;
    uint256 constant betay2  = 17725255565992761070677663510410141440524977079751397615130866129662422673787;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11208820528355933937509114257038767265250708247101889906384837742638040921911;
    uint256 constant deltax2 = 2351724291376613172494929879166749577904947733878282329485300734950500675429;
    uint256 constant deltay1 = 10071807493466688233648885001460033354886249407194332712779982294125684050067;
    uint256 constant deltay2 = 10186720019104201576680755920258602838799608381365293611527506022359293309127;

    
    uint256 constant IC0x = 12101374489738417303840181572580069764732363057515680683745090219107645090682;
    uint256 constant IC0y = 6622868140565385066376227039427993681099925034474371659030596024890146904163;
    
    uint256 constant IC1x = 3669173732190367513652034287079810078449694464897815690603816498785194709298;
    uint256 constant IC1y = 12787552409465063176671040388968071843096720382928171325958634655937745904306;
    
    uint256 constant IC2x = 10170489719246253671314687317213013791640770166137501428884495801025758736797;
    uint256 constant IC2y = 6252395882627424781706364969531995749933564822768034059098225707092062892276;
    
    uint256 constant IC3x = 10687481240706766603557091601215731928279126584360618324726499550379950672384;
    uint256 constant IC3y = 18232245990332373208670193454828315865982081800651657649905394892430114319137;
    
    uint256 constant IC4x = 21479520805308843176453350540312157689793392686894956217336144931222100248332;
    uint256 constant IC4y = 20794240477273416707592605344748314870068446001913164610390302381834843364218;
    
    uint256 constant IC5x = 1639431340488776769304709738824454095007661834601823301121609655140677204345;
    uint256 constant IC5y = 20241100315007980443635026076756163052388871674389145654353231874849036162838;
    
    uint256 constant IC6x = 121645431274525990360138477525109868662860092956168925828298462395321687784;
    uint256 constant IC6y = 794747987098961918220870106626898804586360564216491869032162762989366388476;
    
    uint256 constant IC7x = 2203372645692227215676899858833836590816324059236287726456820657448783477922;
    uint256 constant IC7y = 2207309673745076358166732988325125705730197773311277805000897437308566547524;
    
    uint256 constant IC8x = 7661536419049628598164594465666263178650205781527068355000772766824470727314;
    uint256 constant IC8y = 8811196404119343314769069609010829337590521896699063939687119401222942408654;
    
    uint256 constant IC9x = 21343499519323604545088998121814591820494318698260047386701341623495150952819;
    uint256 constant IC9y = 6690944176613940177567986909847360918607057563241644423161570806785072607212;
    
    uint256 constant IC10x = 15264014509141355058781275071990577551887158548257857606419165483731082471950;
    uint256 constant IC10y = 15216600797471553468459707999770136646723171284081709084120301846088036216358;
    
    uint256 constant IC11x = 12733780935417197072452063628052190220002459201228095695184676669312707904830;
    uint256 constant IC11y = 16298108809776740697899759704974665278820323554206358196275176082801210672419;
    
    uint256 constant IC12x = 6012479247763961858712330659591617235298186231561389312795940364358559647113;
    uint256 constant IC12y = 14721923019704138783748153829207729465935088314626429943383893818959078617779;
    
    uint256 constant IC13x = 13061379726279750555423847998978370480196471520457553871911806444367687353028;
    uint256 constant IC13y = 2975548495951886948231673481109927887365893753862741621324254610502694261941;
    
    uint256 constant IC14x = 17048825568529186912687446126032713752166726936647722462681262666976911028917;
    uint256 constant IC14y = 4770007883853892820003356098186534463380640029144851943088490003586536185193;
    
    uint256 constant IC15x = 13628101711350889888526860037192365772666344522220684297140938100564664858788;
    uint256 constant IC15y = 4355821266360537693062567273491516561731162144993540609483109600550687891933;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[15] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
