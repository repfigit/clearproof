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
    uint256 constant deltax1 = 4468543843747169471051388751983933779570926489830419187750997238341350010492;
    uint256 constant deltax2 = 9941874876408001301405549918564508459520888220638265810124873887321684617374;
    uint256 constant deltay1 = 13238758796600679516482124684671040639524082566292620650270398747510872278062;
    uint256 constant deltay2 = 452909713335083279270392877346966659991608003511141614430268655608673200572;

    
    uint256 constant IC0x = 20426907168052604872654967129427841275503605310406841376060396404119677218098;
    uint256 constant IC0y = 3547317325526572894319675920305840781813253421963503804996427225429979511236;
    
    uint256 constant IC1x = 10576053913253893970396939562762622004019865453515733452064652571962118220828;
    uint256 constant IC1y = 11287097433725117817224323216903448512332214475828046185196714403125705290030;
    
    uint256 constant IC2x = 572982129187694025355608523031459011191618100785358921991341352183285084628;
    uint256 constant IC2y = 8676703438064368824754971568770929758875524260109060095990117387543317341345;
    
    uint256 constant IC3x = 3958430438454703331417212121626216192135451444061270560544123974058969810029;
    uint256 constant IC3y = 8951123104633288787574122054923202350461711425798441459956933365659708601346;
    
    uint256 constant IC4x = 2941143434617997311994970121704759115881896436789407867957835360055191439024;
    uint256 constant IC4y = 21472869068076823601332736258526118141557032451885402521185068496235009950760;
    
    uint256 constant IC5x = 6155252863362397597046463592067159984255228067281721732082306754767946067260;
    uint256 constant IC5y = 13350799367621338923879574187455432072295408717731983045432173095892112229166;
    
    uint256 constant IC6x = 16902982845976497742136186141940236617960922289105761552150373915792957433259;
    uint256 constant IC6y = 21432592331100397974005240235962262505489026215905411152610913093936218307212;
    
    uint256 constant IC7x = 2693670771605893639942090790519802654606651365144836717107066462108780159057;
    uint256 constant IC7y = 897938580093129766883541298097977099293395604208463245886205237989038556757;
    
    uint256 constant IC8x = 10908198219586650672670057314971829760079121933406525338198534445436390843;
    uint256 constant IC8y = 16775407653400449269239994159618891186582685086851884861377040277177300008887;
    
    uint256 constant IC9x = 5331922107045973071866323466415393045245029410797518983920011828869160994005;
    uint256 constant IC9y = 3042417107413938574938091370171119373748820223548833436452938848685045774897;
    
    uint256 constant IC10x = 10481770237638998777905640109295472948852943325302993374824101940520882939514;
    uint256 constant IC10y = 9928131805793305638347178349725576439076939794167415200140432290729626804170;
    
    uint256 constant IC11x = 13373137415007482711131754366102185143075723394531733877665292927763621273755;
    uint256 constant IC11y = 2066183730742981190992301745840066846974434615529490211913691712418862331757;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[11] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
