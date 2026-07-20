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
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
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
