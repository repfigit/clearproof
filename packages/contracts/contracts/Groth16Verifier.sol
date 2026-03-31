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
    uint256 constant alphax  = 18684454301819562296747362103013247904909563675066733611848264601238709664346;
    uint256 constant alphay  = 13382596269673849011460709490273826982834575881932794785488992240206958268988;
    uint256 constant betax1  = 9369927713959446369253112845140960817273069559889791172429790728904899918096;
    uint256 constant betax2  = 7018936339641547380564548801205962972325910679402088163891495006948592464872;
    uint256 constant betay1  = 18192680457896402009106056585736590829886416492642881064592060259639186262006;
    uint256 constant betay2  = 18772142389951268793765998116630185741982332811051964345375452390107064860773;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 16066285121322798283816661155683648225017439991112020715347694895015493523206;
    uint256 constant deltax2 = 614037217300847490032117582288372304806365997874449473897067122389611050097;
    uint256 constant deltay1 = 999132498792814032884695754087775892189854734043853267260966253796598566326;
    uint256 constant deltay2 = 8766526840950424236933975030317606082570070701224728700739511563570212380686;

    
    uint256 constant IC0x = 19703754809632249201814027769049360897773771752440156313927961195680977255238;
    uint256 constant IC0y = 1863925490430054976148272770686055683655162519876480200776277689914207928337;
    
    uint256 constant IC1x = 6842328490232091184800254442267828217282426694586120268639604059623298759838;
    uint256 constant IC1y = 967714464342934108376368520755357809485356696728159664181729268436457657190;
    
    uint256 constant IC2x = 20168307450615104806507934761145093110988772994737581512365163335324124341082;
    uint256 constant IC2y = 10175921511662100555565831453583846748641455819904993446565619840555873483197;
    
    uint256 constant IC3x = 13130823847203923185744389743407601594952943279001962854157420583880242661911;
    uint256 constant IC3y = 1717961719253118057145771753432516947365256073230761126917637302458731210680;
    
    uint256 constant IC4x = 11570200420498329636975473116508042564110840984594598431680781479352690086989;
    uint256 constant IC4y = 2681790313628491490316309945974353922008319929950691351513001124290112440736;
    
    uint256 constant IC5x = 17383935142461497800455236241660532858882483738548995787211516208205825872633;
    uint256 constant IC5y = 21812547690832652944021035744811596124906251282698352572728088438967242927530;
    
    uint256 constant IC6x = 17927548420151504692167355438129654718691791355276257368295386474362061086291;
    uint256 constant IC6y = 20321310284767358151473081167596474276348875693336193985919659549761811512857;
    
    uint256 constant IC7x = 11490640138309946172119907896307159561754460075139288207159881809998896901104;
    uint256 constant IC7y = 21399015425377341114977066020036205236372213642636323424071239423311652240134;
    
    uint256 constant IC8x = 13073587098352777029611799287598219241090404838333415008565749123384053614197;
    uint256 constant IC8y = 6780096976642213192330292067106932985430455462072442264071195827463047236936;
    
    uint256 constant IC9x = 10304063069706060097949924002149390132151400007771167907675220468774489442419;
    uint256 constant IC9y = 3848734989942396280575580725247574077840617816983408962229650854147376789056;
    
    uint256 constant IC10x = 12670767716151712103223751322086902107378299370689672575360531050799429950688;
    uint256 constant IC10y = 3892214401665217432763449110039673837691522297147787147934049711723284107590;
    
    uint256 constant IC11x = 12052672264941792184464623369009224229428685304257677818833685093473604781859;
    uint256 constant IC11y = 194825330483639781015203119551849820798527497461262547171710476416288887343;
    
    uint256 constant IC12x = 8474513833967152402487822542522099684202492964316709697478913113017585715777;
    uint256 constant IC12y = 11180594191762522476791053549177803613388260607752128766664277934879987230209;
    
    uint256 constant IC13x = 2129674974467473223954430982973092343153467817398447047287805202064270480021;
    uint256 constant IC13y = 21694323122275709283006518607681778669855744651418931639024155273779308722027;
    
    uint256 constant IC14x = 3250568833007067433888350215497425008219853791906085127332832556581794453248;
    uint256 constant IC14y = 6399011481929268902517857078272758443475218531566888876695352617518549414569;
    
    uint256 constant IC15x = 21361875659190037444465592626338380323701081645088974263958258082733413038127;
    uint256 constant IC15y = 2277204784735610188074535623007303162278324355868808350267617647867247585840;
    
    uint256 constant IC16x = 3784932913228748653290327846200321674983791114501050843187248759346176565642;
    uint256 constant IC16y = 16161068570005881855813026196520856335621943638222458671868213423896093305442;
    
 
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
