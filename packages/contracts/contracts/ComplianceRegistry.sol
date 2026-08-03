// SPDX-License-Identifier: Apache-2.0
// clearproof — ZK-proven compliance without transmitting PII
// https://clearproof.world | https://docs.clearproof.world
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./VASPRegistry.sol";
import "./SanctionsOracle.sol";
import "./VerifierRouter.sol";

contract ComplianceRegistry is AccessControl, Pausable {
    // Custom errors
    error ZeroVerifierRouter();
    error ZeroRegistry();
    error ZeroOracle();
    error TransferAlreadyRecorded();
    error SanctionsOraclePaused();
    error VASPRegistryPaused();
    error SanctionsOracleStale();
    error VASPNotActive();
    error NotRegisteredVASPWallet();
    error WrongChain();
    error WrongContract();
    error ProofExpired();
    error ProofTimestampInFuture();
    error SanctionsRootMismatch();
    error IssuerRootMismatch();
    error TransferIDMismatch();
    error CredentialAlreadyRevoked();
    error ProofAlreadyUsed();
    error ProofVerificationFailed();
    error AlreadyRevoked();
    error MalformedJurisdictionCode();
    error ThresholdMismatch();
    error ThresholdsNotOrdered();
    error VerifierSelectorNotSet();
    // error JurisdictionCodeMismatch(); // Removed to avoid duplicate identifier error

    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");
    bytes32 public constant THRESHOLD_ADMIN_ROLE = keccak256("THRESHOLD_ADMIN_ROLE");

    /// @dev Reserved key for the FATF default. Real jurisdiction codes are the
    /// big-endian ASCII value of two uppercase letters, so they always fall in
    /// [0x4141, 0x5A5A] and can never collide with 0.
    uint16 public constant DEFAULT_JURISDICTION_KEY = 0;

    /// @notice Lower bounds for amount tiers 2, 3 and 4, in USD-equivalent.
    struct Thresholds {
        uint64 tier2;
        uint64 tier3;
        uint64 tier4;
        bool registered;
    }

    /// @notice jurisdiction_code (public signal 6) => thresholds this contract accepts.
    /// @dev Key DEFAULT_JURISDICTION_KEY holds the fallback for unregistered codes.
    mapping(uint16 => Thresholds) public jurisdictionThresholds;

    event JurisdictionThresholdsSet(uint16 indexed jurisdictionCode, uint64 tier2, uint64 tier3, uint64 tier4);
    event JurisdictionCodeMismatch(bytes32 indexed transferId, uint256 claimedJurisdictionCode, uint256 expectedJurisdictionCode);

    VerifierRouter public verifierRouter;
    bytes32 public verifierSelector;
    VASPRegistry public immutable vaspRegistry;
    SanctionsOracle public immutable sanctionsOracle;

    struct ProofRecord {
        bytes32 proofHash;
        uint256 timestamp;
        bool verified;
    }

    mapping(bytes32 => ProofRecord) public proofs;
    mapping(bytes32 => bool) public revokedCredentials;
    mapping(bytes32 => bool) public usedNullifiers;

    event ProofVerified(bytes32 indexed transferId, bytes32 indexed nullifier, bool isCompliant, bool sarFlag);
    event CredentialRevoked(bytes32 indexed commitment, address revoker);

    /// @param defaultTier2 Lower bound of tier 2 for jurisdictions with no explicit entry.
    /// @param defaultTier3 Lower bound of tier 3 for the same.
    /// @param defaultTier4 Lower bound of tier 4 for the same.
    ///
    /// @dev The default entry is set here rather than in a follow-up transaction
    /// on purpose. verifyAndRecord rejects any proof whose thresholds disagree
    /// with this table, and every lookup falls through to the default entry, so
    /// a registry deployed with an empty table accepts *nothing* — a silent,
    /// total outage with no on-chain signal. Taking the default in the
    /// constructor makes that state unrepresentable.
    constructor(
        address _verifierRouter,
        bytes32 _verifierSelector,
        address _vaspRegistry,
        address _sanctionsOracle,
        uint64 defaultTier2,
        uint64 defaultTier3,
        uint64 defaultTier4
    ) {
        // M-7: Zero-address validation
        if (_verifierRouter == address(0)) revert ZeroVerifierRouter();
        if (_vaspRegistry == address(0)) revert ZeroRegistry();
        if (_sanctionsOracle == address(0)) revert ZeroOracle();

        verifierRouter = VerifierRouter(_verifierRouter);
        verifierSelector = _verifierSelector;
        vaspRegistry = VASPRegistry(_vaspRegistry);
        sanctionsOracle = SanctionsOracle(_sanctionsOracle);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REVOKER_ROLE, msg.sender);
        _grantRole(THRESHOLD_ADMIN_ROLE, msg.sender);

        // Shares validation with the external setter, so the constructor cannot
        // install an out-of-order default.
        _setJurisdictionThresholds(DEFAULT_JURISDICTION_KEY, defaultTier2, defaultTier3, defaultTier4);
    }

    /// @notice Set the verifier selector to use
    /// @param _verifierSelector The selector for the verifier to use
    function setVerifierSelector(bytes32 _verifierSelector) external onlyRole(DEFAULT_ADMIN_ROLE) {
        verifierSelector = _verifierSelector;
    }

    /// @notice Register or update the thresholds accepted for a jurisdiction.
    /// @dev Pass DEFAULT_JURISDICTION_KEY to set the fallback used by codes with
    /// no explicit entry. Seed from config/jurisdiction_thresholds.json — the
    /// Python and TypeScript SDKs must agree with this table or proofs will
    /// verify off-chain and revert here.
    function setJurisdictionThresholds(uint16 jurisdictionCode, uint64 tier2, uint64 tier3, uint64 tier4)
        external
        onlyRole(THRESHOLD_ADMIN_ROLE)
    {
        _setJurisdictionThresholds(jurisdictionCode, tier2, tier3, tier4);
    }

    function _setJurisdictionThresholds(uint16 jurisdictionCode, uint64 tier2, uint64 tier3, uint64 tier4) internal {
        // Ordering is what makes the tier comparison meaningful; an out-of-order
        // table would silently make some tiers unreachable.
        if (!(tier2 < tier3 && tier3 < tier4)) revert ThresholdsNotOrdered();

        jurisdictionThresholds[jurisdictionCode] =
            Thresholds({tier2: tier2, tier3: tier3, tier4: tier4, registered: true});
        emit JurisdictionThresholdsSet(jurisdictionCode, tier2, tier3, tier4);
    }

    /// @notice Thresholds this contract will accept for a jurisdiction code,
    /// resolving through the default entry when the code is not registered.
    function thresholdsFor(uint16 jurisdictionCode) public view returns (Thresholds memory) {
        Thresholds memory t = jurisdictionThresholds[jurisdictionCode];
        if (t.registered) return t;
        return jurisdictionThresholds[DEFAULT_JURISDICTION_KEY];
    }

    /// @dev Reverts unless signals 8-10 carry the thresholds this contract
    /// accepts for signal 6.
    ///
    /// tier2/3/4_threshold are *unconstrained* public inputs — the circuit does
    /// not derive them, the prover supplies them. Without this check a prover
    /// submits tier2_threshold = 2**63, lands a $50M transfer in tier 1, and
    /// the proof verifies: both the tier attestation and the SAR review flag
    /// (tier >= 3) are defeated. Same class as domain binding: the security
    /// lives in the verifier, not the circuit.
    function _checkThresholds(uint[16] calldata _pubSignals) internal view {
        uint256 rawCode = _pubSignals[6];
        // Must be two uppercase ASCII letters, i.e. the encoding the circuit uses.
        if (rawCode > 0xFFFF) revert MalformedJurisdictionCode();
        uint8 hi = uint8(rawCode >> 8);
        uint8 lo = uint8(rawCode);
        if (hi < 0x41 || hi > 0x5A || lo < 0x41 || lo > 0x5A) revert MalformedJurisdictionCode();

        Thresholds memory t = thresholdsFor(uint16(rawCode));
        if (!t.registered) revert ThresholdMismatch();

        if (_pubSignals[8] != t.tier2 || _pubSignals[9] != t.tier3 || _pubSignals[10] != t.tier4) {
            revert ThresholdMismatch();
        }
    }

    function verifyAndRecord(
        bytes32 transferId,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[16] calldata _pubSignals,
        bytes32 vaspDidHash
    ) external whenNotPaused returns (bool) {
        // Replay prevention
        if (proofs[transferId].timestamp != 0) revert TransferAlreadyRecorded();

        // H-6: Dependency health checks
        if (sanctionsOracle.paused()) revert SanctionsOraclePaused();
        if (vaspRegistry.paused()) revert VASPRegistryPaused();
        if (sanctionsOracle.isStale()) revert SanctionsOracleStale();
        if (!vaspRegistry.isActive(vaspDidHash)) revert VASPNotActive();

        // Sender binding
        (address vaspWallet,,,, ) = vaspRegistry.vasps(vaspDidHash);
        if (msg.sender != vaspWallet) revert NotRegisteredVASPWallet();

        // C-3: Domain binding (cross-chain replay protection)
        if (_pubSignals[11] != block.chainid) revert WrongChain();
        // Circuit signals are reduced mod BN128 scalar field order (r).
        // keccak256 produces 256-bit values that may exceed r, so we must
        // reduce the contract-side hash to match what the circuit stores.
        uint256 BN128_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        if (uint256(keccak256(abi.encodePacked(address(this)))) % BN128_R != _pubSignals[12]) revert WrongContract();

        // Proof expiration: proof_expires_at (signal[15]) is a circuit public signal.
        // The circuit constrains proof_expires_at > transfer_timestamp.
        // Here we check the proof hasn't expired yet.
        if (block.timestamp > _pubSignals[15]) revert ProofExpired();
        if (_pubSignals[5] > block.timestamp) revert ProofTimestampInFuture();

        // C-4: State binding (proof matches current on-chain roots)
        if (bytes32(_pubSignals[2]) != sanctionsOracle.currentRoot()) revert SanctionsRootMismatch();
        if (bytes32(_pubSignals[3]) != vaspRegistry.issuerMerkleRoot()) revert IssuerRootMismatch();

        // AIF-98: Jurisdiction code verification
        // Check that the jurisdiction code in the proof matches the VASP's registered jurisdiction
        uint256 claimedJurisdictionCode = _pubSignals[6];
        (, string memory jurisdiction,,,) = vaspRegistry.vasps(vaspDidHash);
        uint256 expectedJurisdictionCode = _encodeJurisdiction(jurisdiction);
        
        if (claimedJurisdictionCode != expectedJurisdictionCode) {
            emit JurisdictionCodeMismatch(transferId, claimedJurisdictionCode, expectedJurisdictionCode);
        }

        // AIF-79: Threshold binding (prover cannot choose its own tier boundaries)
        _checkThresholds(_pubSignals);

        // C-5: Credential revocation check
        if (revokedCredentials[bytes32(_pubSignals[7])]) revert CredentialAlreadyRevoked();

        // M-3: Nullifier — one-time proof use (prevents same proof on different transferIds)
        bytes32 nullifier = bytes32(_pubSignals[14]);
        if (usedNullifiers[nullifier]) revert ProofAlreadyUsed();

        // C-1: Cryptographic verification — revert on invalid proof
        if (verifierSelector == bytes32(0)) revert VerifierSelectorNotSet();
        
        bool valid = verifierRouter.verifyProof(verifierSelector, _pA, _pB, _pC, _pubSignals);
        if (!valid) revert ProofVerificationFailed();

        // Record
        usedNullifiers[nullifier] = true;
        proofs[transferId] = ProofRecord({
            proofHash: keccak256(abi.encode(_pA, _pB, _pC, _pubSignals)),  // H-1: includes pubSignals
            timestamp: block.timestamp,
            verified: true  // Always true now (we revert on invalid)
        });

        // Hash the nullifier before emitting to prevent blockchain observers
        // from correlating transfer patterns across ProofVerified events.
        bytes32 blindedNullifier = keccak256(abi.encodePacked(nullifier));
        emit ProofVerified(transferId, blindedNullifier, _pubSignals[0] == 1, _pubSignals[1] == 1);
        return true;
    }

    function revokeCredential(bytes32 commitment) external onlyRole(REVOKER_ROLE) {
        if (revokedCredentials[commitment]) revert AlreadyRevoked();
        revokedCredentials[commitment] = true;
        emit CredentialRevoked(commitment, msg.sender);
    }

    function isRevoked(bytes32 commitment) external view returns (bool) {
        return revokedCredentials[commitment];
    }

    function isVerified(bytes32 transferId) external view returns (bool) {
        return proofs[transferId].verified;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _encodeJurisdiction(string memory code) internal pure returns (uint256) {
        bytes memory codeBytes = bytes(code);
        require(codeBytes.length == 2, "Jurisdiction code must be 2 characters");
        uint8 hi = uint8(codeBytes[0]);
        uint8 lo = uint8(codeBytes[1]);
        // Check that both characters are uppercase ASCII letters
        require(hi >= 0x41 && hi <= 0x5A, "First character must be uppercase ASCII");
        require(lo >= 0x41 && lo <= 0x5A, "Second character must be uppercase ASCII");
        return (uint256(hi) << 8) | uint256(lo);
    }
}