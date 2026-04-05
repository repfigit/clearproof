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
    uint256 constant alphax  = 10108555655029913249387866415716418696725241177491967895085381163693768804064;
    uint256 constant alphay  = 2468703887758758633815635674475524694352586201817273265474072087000803048188;
    uint256 constant betax1  = 2856289968182565562442303771897431536925533580444631144416294802855696292369;
    uint256 constant betax2  = 3128932286249202720380940821722063707121124061129891332967336807898039237833;
    uint256 constant betay1  = 11769844876686235604852056702177616801416238601962010871466383007838298544180;
    uint256 constant betay2  = 6169224501187960315631063210573608729908824075142080517240176556736066496563;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 20941804909617285782113531426346359561332104861367073563910630047528974899901;
    uint256 constant deltax2 = 19990416962125506795504348450608549403535433706905539271269571358512202193524;
    uint256 constant deltay1 = 20116336974040653320729176680243492369528614540427193514561526352281559258741;
    uint256 constant deltay2 = 20289472342785028275726525785751194878022527799859316539410607007044002790509;

    
    uint256 constant IC0x = 18408069040231002044529531282066370755575707719726607754977326156501778933892;
    uint256 constant IC0y = 3017599953225961541692706768277720916084857658057824045088977582111547959857;
    
    uint256 constant IC1x = 17383920594263897662359888560153505281382683670510832788894356200364590810175;
    uint256 constant IC1y = 6359274848600476617642651697336072722961948569770308901610363935604101045917;
    
    uint256 constant IC2x = 10024686534231600970137924890156720509735401899164046283010225989902536354596;
    uint256 constant IC2y = 11056693413909002535471458883551886504197099317259923060521221608395016361507;
    
    uint256 constant IC3x = 9146418982968070051439629645310015792207748308917424049546020878133008091037;
    uint256 constant IC3y = 20454136279547098594824075153517557391375392300079958654042741491394378600156;
    
    uint256 constant IC4x = 15125474140913611913508813749775354332050097315024335769820563736937363224815;
    uint256 constant IC4y = 632124728973660799028871362877365107094781233665325944029784150740542914924;
    
    uint256 constant IC5x = 19325385632283922145986735192310289967728179076206511006017203275441034239760;
    uint256 constant IC5y = 17666967600405373211462156232953903835547023357845011123032620142257593129180;
    
    uint256 constant IC6x = 5640567638842566378630572838500358478626213135095892682948182475113352651785;
    uint256 constant IC6y = 9308920944737918589771910242022693302593174006594568250889570727705857594481;
    
    uint256 constant IC7x = 20538802566266355591762794924807485770582006564045633828642244749457074517010;
    uint256 constant IC7y = 5097786746340877631855635255155716377220134134124920636446594634284134662242;
    
    uint256 constant IC8x = 9725001134029877177614914272690124000015010227353821390564271956508332702306;
    uint256 constant IC8y = 8592951241007177156408094492593171346304812547919969020820587457616701228108;
    
    uint256 constant IC9x = 4091444495998585966624548382710777601691306452189798304498108411993496513724;
    uint256 constant IC9y = 6636655900576042403034334772392263857217938147177833939005956629350622251955;
    
    uint256 constant IC10x = 1658219386845514416845598582464407957753019489647875303014932603034081510367;
    uint256 constant IC10y = 763235983642668103463152417382094408107090054384708475985090540727276117660;
    
    uint256 constant IC11x = 11978521936643901573975230861476313717197172611412781535785140074667057984729;
    uint256 constant IC11y = 9406400999233352942112950487302401288678082238446864508732921504335914524954;
    
    uint256 constant IC12x = 1479558986573997730589000966076795831631566139455035768793006132731161042413;
    uint256 constant IC12y = 10349009502744471496412751790926509372049806391433420337256540578499028972890;
    
    uint256 constant IC13x = 5969931852893905541497501219290941633975463254716567624703628121118858432629;
    uint256 constant IC13y = 5821753507651533961786649515383082505537714436301488939498381883493120005547;
    
    uint256 constant IC14x = 8215273347325897027669933795085593633519252333340676720094508808502243668299;
    uint256 constant IC14y = 17693602373976219175216236150988746057785825358085262083146007135313687897646;
    
    uint256 constant IC15x = 13185322672400122522080365273758394942546113290656858307859344133421446713476;
    uint256 constant IC15y = 18541374937366916362541428362316235530155308510793507287322663119770315608072;
    
    uint256 constant IC16x = 17747834106781008359163899223831640147277899489665046971806372895146943043085;
    uint256 constant IC16y = 2420942890593997144174946843317236584819923613809239451705147430110362537549;
    
 
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
