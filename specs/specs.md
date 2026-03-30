# ZK Travel Rule Compliance Bridge — Agentic Coding Specification

## Overview

This document is a complete agentic coding specification for an AI coding agent (Claude Code, Cursor, Codex, or equivalent) to implement the ZK Travel Rule Compliance Bridge from scratch. It defines system architecture, data models, ZK circuit specifications, external protocol integrations, test requirements, and deployment configuration — with enough precision that a capable coding agent can execute it without human clarification.

**Product goal**: Provide privacy-preserving compliance infrastructure for FATF Travel Rule obligations. For any stablecoin transfer above the applicable threshold, the originating VASP generates a ZK proof that both parties are KYC-compliant and sanctions-clear. This proof travels alongside encrypted PII (via TRISA mTLS or AES-256-GCM) — the ZK attestation is a machine-verifiable compliance claim; the encrypted PII satisfies the regulatory "transmit" requirement.

**Primary regulatory obligation addressed**: FATF Recommendation 16, implemented in 98 jurisdictions as of 2025; the GENIUS Act's BSA obligations for U.S. stablecoin issuers; GENIUS Act implementation deadline of January 18, 2027. The U.S. Travel Rule threshold is $3,000; FATF's February 2025 update set a stricter $250 threshold in many jurisdictions.[^1][^2][^3][^4][^5]

**Regulatory positioning**: This system is **privacy-preserving compliance infrastructure** — not privacy technology. ZK proofs demonstrate that compliance was performed correctly. Encrypted PII satisfies the regulatory obligation to transmit originator/beneficiary information. Both artifacts travel together in a hybrid payload. Initial target jurisdictions: Singapore (MAS), UAE (VARA). EU (MiCA) after MVP.

**Target users**:
- **Stablecoin issuers** (GENIUS Act-registered payment stablecoin issuers)
- **VASPs** (crypto exchanges, custodial wallet providers, MSBs, PSPs)[^6]
- **Tokenized deposit platforms** (e.g., Cari Network and successors)[^7][^8]

***

## Part I: System Architecture

### High-Level Component Map

```
┌──────────────────────────────────────────────────────────────┐
│                    ZK Travel Rule Bridge                     │
│                                                              │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │  zkKYC      │   │  Compliance  │   │  IVMS101 Proof   │  │
│  │  Credential │   │  Circuits    │   │  Gateway API     │  │
│  │  Registry   │   │  (Circom)    │   │  (REST + gRPC)   │  │
│  └──────┬──────┘   └──────┬───────┘   └────────┬─────────┘  │
│         │                  │                     │            │
│  ┌──────▼──────────────────▼─────────────────────▼─────────┐ │
│  │              Local Proving Layer (SnarkJS)               │ │
│  │  Circom circuits → Groth16 proofs                       │ │
│  │  VASP-local proof generation (no external network)      │ │
│  │  HSM key management for SAR encryption                  │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         External Protocol Bridges                    │   │
│  │  TRISA ◄──► TRP/OpenVASP ◄──► TRUST ◄──► TAIP-10    │   │
│  │  (hybrid payload: ZK proof + encrypted PII)          │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Technology |
|---|---|---|
| zkKYC Credential Registry | Issue, revoke, and verify zkKYC commitments | Merkle tree (Poseidon hash), on-chain root |
| Compliance Circuits | Generate ZK proof of sanctions-clear + limit-compliant status | Circom + circomlib, Groth16 via SnarkJS |
| Proof Gateway API | Accept transfer requests, generate proofs locally, bridge to TRISA/TRP | FastAPI, gRPC |
| Local Prover | Execute ZK proof generation on VASP infrastructure | SnarkJS (Node.js/WASM), Circom compiler |
| SAR/Audit Module | Generate SAR review flags, manage encrypted audit trail | AES-256-GCM encryption, HSM key management |
| Protocol Bridge | Translate hybrid payload (ZK proof + encrypted PII) into TRISA/TRP/TRUST wire messages | Go (TRISA gRPC[^14]), Python (TRP REST[^15]) |

### Data Flow for a Single Compliant Transfer

```
1. Originator VASP calls POST /proof/generate
   → passes: wallet_address, amount, currency, jurisdiction, credential_id

2. Bridge looks up zkKYC credential commitment for credential_id
   → validates credential not revoked (Merkle non-membership proof)
   → validates credential issuer is in trusted issuer set

3. Bridge generates ZK proof locally via SnarkJS
   → runs Circom compliance circuit
   → produces Groth16 proof: "credential is valid, amount ≤ jurisdiction_limit,
                              address not in sanctions set"

4. Proof verified locally (deterministic, <1ms)
   → if valid: returns ComplianceProof + encrypted PII as hybrid payload

5. Originator includes hybrid payload in transfer message
   → ZK proof as machine-verifiable compliance attestation
   → encrypted PII (AES-256-GCM or TRISA mTLS) satisfying "transmit" requirement
   → originator_vasp_did for identity

6. Beneficiary VASP calls POST /proof/verify
   → verifies Groth16 proof locally (deterministic, <1ms)
   → decrypts PII via mTLS or shared key for record-keeping
   → confirms originator is sanctions-clear and KYC-verified

7. Both VASPs retain proof + encrypted PII + transfer hash in audit log
   → regulator queries audit log under legal process
   → SAR review flags trigger human review for suspicious activity
   → encrypted payload decrypted via HSM-managed keys under warrant
```

***

## Part II: Repository Structure

```
zk-travel-rule/
├── README.md
├── pyproject.toml                  # Python deps: fastapi, pydantic, cryptography
├── package.json                    # Node deps: snarkjs, circomlib
├── Makefile                        # dev, test, lint, deploy targets
│
├── circuits/                       # Circom circuit definitions
│   ├── compliance.circom           # Main compliance circuit (composed)
│   ├── sanctions_nonmembership.circom  # Merkle non-membership proof circuit
│   ├── credential_validity.circom  # Credential expiry + issuer verification circuit
│   ├── amount_tier.circom          # Tiered amount threshold circuit
│   └── lib/                        # Shared circuit components
│       ├── poseidon_hasher.circom  # Poseidon hash wrapper (from circomlib)
│       └── merkle_tree.circom      # Merkle proof verification (from circomlib)
│
├── protocol/                       # Wire protocol definitions
│   ├── ivms101.py                  # IVMS101 data model (Pydantic)
│   ├── compliance_proof.py         # ComplianceProof output schema
│   ├── hybrid_payload.py           # Hybrid payload: ZK proof + encrypted PII
│   └── bridges/
│       ├── trisa_bridge.py         # TRISA gRPC translation layer
│       ├── trp_bridge.py           # TRP/OpenVASP REST translation layer
│       └── taip10_bridge.py        # TAIP-10 selective disclosure bridge
│
├── prover/                         # Local proving infrastructure
│   ├── snarkjs_prover.py           # Python wrapper around SnarkJS CLI/WASM
│   ├── circuit_compiler.py         # Circom compilation + trusted setup
│   └── verifier.py                 # Groth16 verification (SnarkJS)
│
├── registry/
│   ├── credential_registry.py      # zkKYC credential issuance + Merkle tree management
│   ├── sanctions_list.py           # Sanctions list → Merkle tree builder (OFAC, UN, EU)
│   └── issuer_registry.py          # Trusted credential issuer DID registry
│
├── sar/
│   ├── sar_review.py               # SAR review flag logic (activity-based, not automatic)
│   ├── audit_log.py                # Encrypted audit trail management
│   └── encryption.py               # AES-256-GCM encryption + HSM key management
│
├── api/
│   ├── main.py                     # FastAPI entrypoint
│   ├── routes/
│   │   ├── proof.py                # POST /proof/generate, POST /proof/verify
│   │   ├── credential.py           # POST /credential/issue, POST /credential/revoke
│   │   └── health.py               # GET /health, GET /metrics
│   └── middleware/
│       ├── auth.py                 # API key + JWT auth (GENIUS Act BSA entity auth)
│       └── rate_limit.py
│
├── tests/
│   ├── unit/
│   │   ├── test_circuits.py        # Unit tests for each Circom circuit
│   │   ├── test_prover.py          # SnarkJS prover wrapper tests
│   │   └── test_ivms101.py         # IVMS101 schema validation
│   ├── integration/
│   │   ├── test_proof_roundtrip.py # Full generate → verify roundtrip
│   │   ├── test_trisa_bridge.py    # TRISA protocol compatibility
│   │   ├── test_trp_bridge.py      # TRP protocol compatibility
│   │   └── test_hybrid_payload.py  # Hybrid payload encode/decode roundtrip
│   └── compliance/
│       ├── test_sanctions_match.py # Proof MUST fail for sanctioned addresses
│       ├── test_threshold_tiers.py # Proof must encode correct tier per jurisdiction
│       └── test_revocation.py      # Revoked credential MUST fail proof generation
│
├── scripts/
│   ├── build_sanctions_tree.py     # Fetch OFAC SDN, UN, EU lists → Merkle tree
│   ├── compile_circuits.sh         # Compile all Circom circuits + trusted setup
│   └── benchmark_proof_latency.py  # Measure proof gen time per jurisdiction tier
│
└── docker/
    ├── Dockerfile.api
    ├── Dockerfile.prover            # Node.js + SnarkJS + compiled circuits
    └── docker-compose.yml
```

***

## Part III: Data Models

### 3.1 zkKYC Credential

```python
# registry/credential_registry.py
from pydantic import BaseModel, Field
from typing import Literal, Optional
import hashlib

class zkKYCCredential(BaseModel):
    """
    Off-chain credential issued by a trusted KYC provider.
    Only the `commitment` is ever stored on-chain.
    The full record is held by the user's wallet.
    """
    credential_id: str                        # UUID, internal reference
    issuer_did: str                           # DID of issuing KYC provider
    subject_wallet: str                       # wallet address (NOT stored in proof)
    jurisdiction: str                         # ISO 3166-1 alpha-2
    kyc_tier: Literal["retail", "professional", "institutional"]
    sanctions_clear: bool                     # issuer attests sanctions check passed
    issued_at: int                            # Unix timestamp
    expires_at: int                           # Unix timestamp
    revoked: bool = False

    # Derived: Poseidon hash of all fields (circuit-compatible)
    # Never expose raw fields in ZK circuit — only commitment
    def commitment(self) -> str:
        raw = f"{self.issuer_did}|{self.jurisdiction}|{self.kyc_tier}|{self.issued_at}|{self.expires_at}"
        return hashlib.sha256(raw.encode()).hexdigest()  # replace with Poseidon in circuit
```

### 3.2 ComplianceProof (External API Output)

This is what the external VASP API returns — the ZK attestation component of the hybrid payload that accompanies encrypted PII in Travel Rule messages:[^17]

```python
# protocol/compliance_proof.py
from pydantic import BaseModel
from typing import Optional

class ComplianceProof(BaseModel):
    """
    The ZK attestation component of the hybrid Travel Rule payload.
    This object provides machine-verifiable proof of compliance.
    Encrypted PII travels alongside it (see HybridPayload).
    """
    proof_id: str                            # UUID for audit trail
    transfer_id: str                         # Links proof to specific transfer

    # ZK proof artifact
    groth16_proof: str                       # base64 Groth16 proof bytes
    public_signals: list[str]               # Circuit public outputs
    verification_key: str                    # vk for on-chain/off-chain verification

    # Proof metadata (public, non-sensitive)
    originator_vasp_did: str                 # DID of originating VASP
    beneficiary_vasp_did: Optional[str]      # DID of beneficiary VASP (if known)
    jurisdiction: str                        # Jurisdiction proof was generated for
    amount_tier: int                         # Tier (1-4); NOT exact amount
    proof_generated_at: int                  # Unix timestamp
    proof_expires_at: int                    # Proof validity window (default: 300s)

    # Compliance attestations encoded in public signals
    # Public signal[0]: 1 if originator credential valid, 0 if not
    # Public signal[1]: 1 if originator sanctions-clear, 0 if not
    # Public signal[2]: amount_tier (1-4)
    # Public signal[3]: credential jurisdiction matches transfer jurisdiction
    # Public signal[4]: Merkle root of sanctions list used
    # Public signal[5]: Merkle root of issuer list used

    # SAR review flag (signals for human review, NOT automatic filing)
    sar_review_flag: bool = False            # True if activity warrants human SAR review

    # Encrypted audit payload (AES-256-GCM; key managed by HSM)
    encrypted_audit_payload: Optional[str]   # Decryptable under legal process
```

### 3.3 Hybrid Payload

The hybrid payload combines the ZK proof (machine-verifiable compliance attestation) with encrypted PII (satisfying the regulatory "transmit" requirement):

```python
# protocol/hybrid_payload.py
from pydantic import BaseModel
from typing import Optional
from protocol.compliance_proof import ComplianceProof

class HybridPayload(BaseModel):
    """
    Hybrid Travel Rule payload: ZK proof + encrypted PII.

    The ZK proof provides a machine-verifiable attestation that compliance
    was performed correctly. The encrypted PII satisfies the regulatory
    requirement to transmit originator/beneficiary information.

    Both components travel together in every Travel Rule message.
    """
    # ZK attestation component
    compliance_proof: ComplianceProof

    # Encrypted PII component (satisfies "transmit" requirement)
    # Encrypted via AES-256-GCM; key exchanged via TRISA mTLS or DH
    encrypted_pii: str                       # AES-256-GCM ciphertext (base64)
    pii_encryption_method: str = "AES-256-GCM"  # or "TRISA_MTLS"
    pii_key_id: Optional[str] = None         # Key identifier for decryption

    # Metadata
    payload_version: str = "1.0"
    created_at: int                          # Unix timestamp
```

### 3.4 IVMS101 Proof Wrapper

For counterparties that require IVMS101-structured messages, the hybrid payload is wrapped in an IVMS101-compatible envelope:[^18][^17]

```python
# protocol/ivms101.py
from pydantic import BaseModel
from typing import Optional

class ZKIvms101Originator(BaseModel):
    """
    Drop-in replacement for IVMS101 Originator object.
    PII fields are encrypted; ZK proof provides compliance attestation.
    Counterparties running zk-capable Travel Rule software
    verify the proof; all counterparties can decrypt PII via mTLS.
    """
    # Standard IVMS101 structural fields (non-PII)
    account_number: str                      # wallet address — required by IVMS101

    # ZK proof reference
    zk_proof_ref: str                        # proof_id linking to ComplianceProof
    zk_verification_endpoint: str           # URL where beneficiary can fetch and verify

    # Encrypted PII (always present in hybrid model)
    encrypted_natural_person: str            # AES-256-GCM encrypted IVMS101 NaturalPerson
    pii_encryption_method: str = "AES-256-GCM"

class ZKIvms101Message(BaseModel):
    """Full IVMS101 message with ZK originator + encrypted PII."""
    originator: ZKIvms101Originator
    beneficiary_account_number: str          # Beneficiary wallet address
    originating_vasp_did: str
    beneficiary_vasp_did: Optional[str]
    transfer_amount: str                     # Amount as string (not revealed in proof)
    asset_type: str                          # e.g., "USDC", "USDT"

    # Hybrid payload: proof + encrypted PII
    compliance_proof: Optional[ComplianceProof] = None
    compliance_proof_id: Optional[str] = None  # if fetched by reference
    encrypted_pii: Optional[str] = None      # AES-256-GCM encrypted full PII bundle
```

***

## Part IV: ZK Circuit Specifications

### 4.1 Circuit Architecture Decision

Use **Circom** with **circomlib** as the circuit language and **SnarkJS** with **Groth16** as the proof backend. Compliance logic is boolean and arithmetic — sanctions non-membership, credential validity, tier encoding — which maps directly to Circom's constraint system without the overhead of ONNX neural network wrapping.[^22][^23]

Use circomlib for:
- **Poseidon hash**: `circomlib/circuits/poseidon.circom` — circuit-efficient hash for credential commitments and Merkle trees
- **Merkle tree verification**: `circomlib/circuits/mux1.circom` + custom Merkle proof template — membership and non-membership proofs
- **Comparators**: `circomlib/circuits/comparators.circom` — LessThan, GreaterThan for tier boundaries and expiry checks

**Proof system selection rationale**: Groth16 is preferred because compliance circuits stabilize quickly (the trusted setup overhead is bounded), verification is constant-size (192 bytes), and on-chain verification is the cheapest available. PLONK is available as fallback for circuits requiring frequent modification.[^22][^23]

**Why not EZKL/ONNX**: Compliance logic is deterministic boolean/arithmetic. Expressing it as a neural network adds unnecessary complexity (training, calibration, accuracy thresholds) when the same logic can be expressed as exact Circom constraints with zero ambiguity.

### 4.2 Compliance Circuit Definition (Circom)

```circom
// circuits/compliance.circom
pragma circom 2.1.6;

include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";
include "./lib/merkle_tree.circom";
include "./sanctions_nonmembership.circom";
include "./credential_validity.circom";
include "./amount_tier.circom";

/*
 * Main compliance circuit. Proves the following statements simultaneously
 * without revealing any private inputs:
 *
 * PUBLIC INPUTS (known to verifier):
 *   - sanctions_tree_root: Merkle root of current OFAC/UN/EU sanctions list
 *   - issuer_tree_root: Merkle root of trusted credential issuers
 *   - amount_tier: 1, 2, 3, or 4 (not exact amount)
 *   - transfer_timestamp: Unix timestamp
 *   - jurisdiction: encoded as uint (ISO 3166 country code → integer)
 *
 * PRIVATE INPUTS (known only to prover):
 *   - credential fields: issuer_did, kyc_tier, sanctions_clear, issued_at, expires_at
 *   - wallet_address_hash: Poseidon hash of wallet address
 *   - sanctions_merkle_proof: path proving wallet NOT in sanctions tree
 *   - issuer_merkle_proof: path proving issuer IS in trusted issuer tree
 *
 * PROVEN STATEMENTS (circuit constraints):
 *   1. Poseidon(credential_fields) == credential_commitment
 *   2. credential.expires_at > transfer_timestamp (not expired)
 *   3. credential.sanctions_clear == 1 (issuer attests clean)
 *   4. MerkleNonMembership(wallet, sanctions_tree_root) (wallet not sanctioned)
 *   5. MerkleMembership(issuer_did, issuer_tree_root) (issuer is trusted)
 *   6. credential.jurisdiction == jurisdiction (credential matches transfer)
 *   7. amount_tier in {1, 2, 3, 4} (valid tier)
 *   8. IF amount_tier >= 3: sar_review_flag = 1 (flag for human review)
 */

template ComplianceProof(sanctions_tree_depth, issuer_tree_depth) {
    // === PUBLIC INPUTS ===
    signal input sanctions_tree_root;
    signal input issuer_tree_root;
    signal input amount_tier;
    signal input transfer_timestamp;
    signal input jurisdiction;
    signal input credential_commitment;  // expected Poseidon hash

    // === PRIVATE INPUTS ===
    signal input issuer_did;
    signal input kyc_tier;               // 1=retail, 2=professional, 3=institutional
    signal input sanctions_clear;        // 1 or 0
    signal input issued_at;
    signal input expires_at;
    signal input wallet_address_hash;

    // Merkle proof paths
    signal input sanctions_proof_siblings[sanctions_tree_depth];
    signal input sanctions_proof_indices[sanctions_tree_depth];
    signal input sanctions_left_neighbor;
    signal input sanctions_right_neighbor;
    signal input sanctions_left_path[sanctions_tree_depth];
    signal input sanctions_left_indices[sanctions_tree_depth];
    signal input sanctions_right_path[sanctions_tree_depth];
    signal input sanctions_right_indices[sanctions_tree_depth];

    signal input issuer_proof_siblings[issuer_tree_depth];
    signal input issuer_proof_indices[issuer_tree_depth];

    // === PUBLIC OUTPUTS ===
    signal output credential_valid;      // 1 if all checks pass
    signal output sanctions_clear_out;   // 1 if sanctions check passes
    signal output tier_out;              // amount_tier echoed
    signal output jurisdiction_match;    // 1 if jurisdiction matches
    signal output sanctions_root_used;   // echo sanctions_tree_root
    signal output issuer_root_used;      // echo issuer_tree_root
    signal output sar_review_flag;       // 1 if tier >= 3 (human review)

    // === CONSTRAINT 1: Credential commitment check ===
    component hasher = Poseidon(5);
    hasher.inputs[0] <== issuer_did;
    hasher.inputs[1] <== kyc_tier;
    hasher.inputs[2] <== sanctions_clear;
    hasher.inputs[3] <== issued_at;
    hasher.inputs[4] <== expires_at;
    hasher.out === credential_commitment;

    // === CONSTRAINT 2: Not expired ===
    component not_expired = GreaterThan(64);
    not_expired.in[0] <== expires_at;
    not_expired.in[1] <== transfer_timestamp;
    not_expired.out === 1;

    // === CONSTRAINT 3: Issuer attests sanctions clear ===
    sanctions_clear === 1;

    // === CONSTRAINT 4: Wallet not in sanctions list (non-membership) ===
    component sanctions_check = SanctionsNonMembership(sanctions_tree_depth);
    sanctions_check.root <== sanctions_tree_root;
    sanctions_check.wallet_hash <== wallet_address_hash;
    sanctions_check.left_neighbor <== sanctions_left_neighbor;
    sanctions_check.right_neighbor <== sanctions_right_neighbor;
    for (var i = 0; i < sanctions_tree_depth; i++) {
        sanctions_check.left_path[i] <== sanctions_left_path[i];
        sanctions_check.left_indices[i] <== sanctions_left_indices[i];
        sanctions_check.right_path[i] <== sanctions_right_path[i];
        sanctions_check.right_indices[i] <== sanctions_right_indices[i];
    }
    sanctions_check.valid === 1;

    // === CONSTRAINT 5: Issuer in trusted set (membership) ===
    component issuer_check = MerkleProof(issuer_tree_depth);
    issuer_check.leaf <== issuer_did;
    issuer_check.root <== issuer_tree_root;
    for (var i = 0; i < issuer_tree_depth; i++) {
        issuer_check.siblings[i] <== issuer_proof_siblings[i];
        issuer_check.indices[i] <== issuer_proof_indices[i];
    }
    issuer_check.valid === 1;

    // === CONSTRAINT 6: Jurisdiction match ===
    // (credential jurisdiction encoded in issuer_did field for circuit efficiency)
    component jurisdiction_eq = IsEqual();
    jurisdiction_eq.in[0] <== jurisdiction;
    jurisdiction_eq.in[1] <== jurisdiction;  // placeholder; real impl encodes in credential
    jurisdiction_match <== jurisdiction_eq.out;

    // === CONSTRAINT 7: Valid tier ===
    component tier_gte1 = GreaterEqThan(8);
    tier_gte1.in[0] <== amount_tier;
    tier_gte1.in[1] <== 1;
    tier_gte1.out === 1;

    component tier_lte4 = LessEqThan(8);
    tier_lte4.in[0] <== amount_tier;
    tier_lte4.in[1] <== 4;
    tier_lte4.out === 1;

    // === CONSTRAINT 8: SAR review flag (tier >= 3 flags for human review) ===
    component sar_check = GreaterEqThan(8);
    sar_check.in[0] <== amount_tier;
    sar_check.in[1] <== 3;
    sar_review_flag <== sar_check.out;

    // === OUTPUTS ===
    credential_valid <== 1;  // if we reach here, all constraints passed
    sanctions_clear_out <== 1;
    tier_out <== amount_tier;
    sanctions_root_used <== sanctions_tree_root;
    issuer_root_used <== issuer_tree_root;
}

// Default instantiation: 20-level sanctions tree, 10-level issuer tree
component main {public [
    sanctions_tree_root,
    issuer_tree_root,
    amount_tier,
    transfer_timestamp,
    jurisdiction,
    credential_commitment
]} = ComplianceProof(20, 10);
```

### 4.3 Sanctions Non-Membership Circuit

```circom
// circuits/sanctions_nonmembership.circom
pragma circom 2.1.6;

include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";
include "./lib/merkle_tree.circom";

/*
 * Proves that a given wallet address hash is NOT a member of the sanctions
 * Merkle tree, without revealing the wallet address.
 *
 * Uses a "gap proof": show two adjacent leaves whose values bound the
 * target value, proving it cannot be a member.
 *
 * The sorted Merkle tree is rebuilt daily from OFAC SDN, UN consolidated,
 * and EU asset freeze lists.
 */

template SanctionsNonMembership(tree_depth) {
    signal input root;
    signal input wallet_hash;
    signal input left_neighbor;       // largest leaf < wallet_hash
    signal input right_neighbor;      // smallest leaf > wallet_hash

    signal input left_path[tree_depth];
    signal input left_indices[tree_depth];
    signal input right_path[tree_depth];
    signal input right_indices[tree_depth];

    signal output valid;

    // 1. Verify left_neighbor < wallet_hash
    component lt = LessThan(252);
    lt.in[0] <== left_neighbor;
    lt.in[1] <== wallet_hash;
    lt.out === 1;

    // 2. Verify wallet_hash < right_neighbor
    component gt = LessThan(252);
    gt.in[0] <== wallet_hash;
    gt.in[1] <== right_neighbor;
    gt.out === 1;

    // 3. Verify left_neighbor is in the tree
    component left_proof = MerkleProof(tree_depth);
    left_proof.leaf <== left_neighbor;
    left_proof.root <== root;
    for (var i = 0; i < tree_depth; i++) {
        left_proof.siblings[i] <== left_path[i];
        left_proof.indices[i] <== left_indices[i];
    }
    left_proof.valid === 1;

    // 4. Verify right_neighbor is in the tree
    component right_proof = MerkleProof(tree_depth);
    right_proof.leaf <== right_neighbor;
    right_proof.root <== root;
    for (var i = 0; i < tree_depth; i++) {
        right_proof.siblings[i] <== right_path[i];
        right_proof.indices[i] <== right_indices[i];
    }
    right_proof.valid === 1;

    valid <== 1;
}
```

### 4.4 Credential Validity Circuit

```circom
// circuits/credential_validity.circom
pragma circom 2.1.6;

include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";

/*
 * Proves credential is valid: not expired, issuer attests sanctions clear,
 * and commitment matches the Poseidon hash of credential fields.
 */

template CredentialValidity() {
    signal input issuer_did;
    signal input kyc_tier;
    signal input sanctions_clear;
    signal input issued_at;
    signal input expires_at;
    signal input transfer_timestamp;
    signal input expected_commitment;

    signal output valid;
    signal output computed_commitment;

    // Hash credential fields
    component hasher = Poseidon(5);
    hasher.inputs[0] <== issuer_did;
    hasher.inputs[1] <== kyc_tier;
    hasher.inputs[2] <== sanctions_clear;
    hasher.inputs[3] <== issued_at;
    hasher.inputs[4] <== expires_at;

    computed_commitment <== hasher.out;

    // Verify commitment matches
    component eq = IsEqual();
    eq.in[0] <== computed_commitment;
    eq.in[1] <== expected_commitment;
    eq.out === 1;

    // Verify not expired
    component not_expired = GreaterThan(64);
    not_expired.in[0] <== expires_at;
    not_expired.in[1] <== transfer_timestamp;
    not_expired.out === 1;

    // Verify sanctions clear
    sanctions_clear === 1;

    valid <== 1;
}
```

### 4.5 Amount Tier Circuit

```circom
// circuits/amount_tier.circom
pragma circom 2.1.6;

include "circomlib/comparators.circom";

/*
 * Verifies amount_tier is correctly computed for the given jurisdiction
 * without revealing the exact transfer amount.
 *
 * Jurisdiction-specific tier mapping:
 *   Tier 1 (small):  amount < $250 → full privacy
 *   Tier 2 (medium): $250 ≤ amount < $3,000 → compliance proof required
 *   Tier 3 (large):  $3,000 ≤ amount < $10,000 → Travel Rule mandatory (US)
 *   Tier 4 (high):   amount ≥ $10,000 → SAR review flag
 *
 * Per-jurisdiction overrides:
 *   US: Tier 3 = $3,000 (FinCEN)
 *   EU MiCA: Tier 2 = €1,000
 *   FATF Feb 2025: Tier 2 = $250 in 75+ jurisdictions
 */

template AmountTier() {
    signal input amount_tier;
    signal output valid;
    signal output sar_review_flag;

    // Tier must be 1, 2, 3, or 4
    component gte1 = GreaterEqThan(8);
    gte1.in[0] <== amount_tier;
    gte1.in[1] <== 1;
    gte1.out === 1;

    component lte4 = LessEqThan(8);
    lte4.in[0] <== amount_tier;
    lte4.in[1] <== 4;
    lte4.out === 1;

    // SAR review flag for tier >= 3
    component sar = GreaterEqThan(8);
    sar.in[0] <== amount_tier;
    sar.in[1] <== 3;
    sar_review_flag <== sar.out;

    valid <== 1;
}
```

### 4.6 Jurisdiction Tier Mapping (Off-Chain)

```python
# prover/tier_mapping.py
"""
Jurisdiction-specific tier mapping.
Tier is computed off-chain; the circuit verifies tier is in valid range.
The VASP is responsible for computing the correct tier.
"""

JURISDICTION_TIERS = {
    "US": {"tier2": 250, "tier3": 3000, "tier4": 10000},
    "EU": {"tier2": 250, "tier3": 1000, "tier4": 10000},
    "SG": {"tier2": 250, "tier3": 1500, "tier4": 10000},
    "AE": {"tier2": 250, "tier3": 1000, "tier4": 10000},  # UAE (VARA)
    "DEFAULT": {"tier2": 250, "tier3": 3000, "tier4": 10000},
}

def compute_tier(amount_usd: float, jurisdiction: str) -> int:
    thresholds = JURISDICTION_TIERS.get(jurisdiction, JURISDICTION_TIERS["DEFAULT"])
    if amount_usd < thresholds["tier2"]:
        return 1
    elif amount_usd < thresholds["tier3"]:
        return 2
    elif amount_usd < thresholds["tier4"]:
        return 3
    else:
        return 4
```

### 4.7 Merkle Tree Library (Circom)

```circom
// circuits/lib/merkle_tree.circom
pragma circom 2.1.6;

include "circomlib/poseidon.circom";
include "circomlib/mux1.circom";

/*
 * Generic Merkle proof verification using Poseidon hash.
 * Used for both sanctions non-membership and issuer membership proofs.
 */

template MerkleProof(depth) {
    signal input leaf;
    signal input root;
    signal input siblings[depth];
    signal input indices[depth];   // 0 = leaf is left child, 1 = leaf is right child

    signal output valid;

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    component hashers[depth];
    component mux[depth];

    for (var i = 0; i < depth; i++) {
        // Select ordering based on index bit
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== siblings[i];
        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== indices[i];

        // Hash the pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== hashers[i].out;
    }

    // Final hash must equal root
    component eq = IsEqual();
    eq.in[0] <== hashes[depth];
    eq.in[1] <== root;
    valid <== eq.out;
}
```

### 4.8 Sanctions Merkle Tree Builder (Python)

```python
# registry/sanctions_list.py
"""
Sorted Merkle tree of sanctioned wallet addresses.
Supports non-membership proofs via gap proofs.
Rebuilt daily from OFAC SDN list, UN consolidated list, EU asset freeze list.
"""
import json
import subprocess
from typing import Optional

class SanctionsMerkleTree:
    def __init__(self):
        self.leaves: list[int] = []  # Poseidon hashes of sanctioned addresses
        self.root: Optional[str] = None

    def build_from_sources(self, ofac_url: str, un_url: str, eu_url: str) -> str:
        """
        Fetch sanction lists, normalize wallet addresses,
        build sorted Merkle tree, return root hash.
        Uses Poseidon hash (circuit-compatible) via SnarkJS.
        """
        raise NotImplementedError("Implement: fetch lists, hash addresses, build tree")

    def generate_nonmembership_proof(self, wallet_address_hash: int) -> dict:
        """
        Returns gap proof for non-membership:
          - left_neighbor: largest leaf value < wallet_address_hash
          - right_neighbor: smallest leaf value > wallet_address_hash
          - left_path/right_path: Merkle paths for both neighbors
        Circuit verifies both paths and checks wallet_address_hash is between them.
        """
        sorted_leaves = sorted(self.leaves)

        # Find gap
        left_idx = -1
        for i, leaf in enumerate(sorted_leaves):
            if leaf < wallet_address_hash:
                left_idx = i
            else:
                break

        if left_idx == -1 or left_idx >= len(sorted_leaves) - 1:
            raise ValueError("Cannot generate gap proof: address at boundary")

        return {
            "left_neighbor": sorted_leaves[left_idx],
            "right_neighbor": sorted_leaves[left_idx + 1],
            "left_path": self._get_merkle_path(left_idx),
            "right_path": self._get_merkle_path(left_idx + 1),
        }

    def _get_merkle_path(self, index: int) -> dict:
        """Return Merkle path (siblings + indices) for leaf at given index."""
        raise NotImplementedError("Implement Poseidon-based Merkle path extraction")
```

***

## Part V: Local Proving Infrastructure

### 5.1 SnarkJS Prover Wrapper

```python
# prover/snarkjs_prover.py
"""
Python wrapper around SnarkJS for VASP-local proof generation.
No external network required — proofs generated entirely on VASP infrastructure.

SnarkJS is invoked via subprocess (Node.js) or via WASM bindings.
Circuit artifacts (wasm, zkey) are compiled once and reused.
"""
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

class SnarkJSProver:
    """
    Local Groth16 prover using SnarkJS.

    Requires pre-compiled circuit artifacts:
      - compliance.wasm: compiled Circom circuit (WASM)
      - compliance_final.zkey: proving key (from trusted setup)
      - verification_key.json: verification key
    """

    def __init__(self, artifacts_dir: str = "./artifacts"):
        self.artifacts_dir = Path(artifacts_dir)
        self.wasm_path = self.artifacts_dir / "compliance_js" / "compliance.wasm"
        self.zkey_path = self.artifacts_dir / "compliance_final.zkey"
        self.vk_path = self.artifacts_dir / "verification_key.json"

        # Validate artifacts exist
        for path in [self.wasm_path, self.zkey_path, self.vk_path]:
            if not path.exists():
                raise FileNotFoundError(f"Circuit artifact not found: {path}")

    async def generate_proof(self, input_signals: dict) -> dict:
        """
        Generate a Groth16 proof from input signals.

        Args:
            input_signals: dict mapping signal names to values
                (both public and private inputs)

        Returns:
            {
                "proof": <Groth16 proof JSON>,
                "public_signals": [<public output values>],
                "proving_time_ms": <int>
            }
        """
        start = time.time()

        # Write input signals to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(input_signals, f)
            input_path = f.name

        proof_path = tempfile.mktemp(suffix='_proof.json')
        public_path = tempfile.mktemp(suffix='_public.json')

        try:
            # Generate witness
            witness_path = tempfile.mktemp(suffix='.wtns')
            result = subprocess.run(
                [
                    "node",
                    str(self.artifacts_dir / "compliance_js" / "generate_witness.js"),
                    str(self.wasm_path),
                    input_path,
                    witness_path,
                ],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                raise RuntimeError(f"Witness generation failed: {result.stderr}")

            # Generate Groth16 proof
            result = subprocess.run(
                [
                    "npx", "snarkjs", "groth16", "prove",
                    str(self.zkey_path),
                    witness_path,
                    proof_path,
                    public_path,
                ],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                raise RuntimeError(f"Proof generation failed: {result.stderr}")

            # Read results
            with open(proof_path) as f:
                proof = json.load(f)
            with open(public_path) as f:
                public_signals = json.load(f)

            elapsed_ms = int((time.time() - start) * 1000)

            return {
                "proof": proof,
                "public_signals": public_signals,
                "proving_time_ms": elapsed_ms,
            }

        finally:
            # Cleanup temp files
            for p in [input_path, proof_path, public_path]:
                Path(p).unlink(missing_ok=True)
            if 'witness_path' in locals():
                Path(witness_path).unlink(missing_ok=True)

    async def verify_proof(self, proof: dict, public_signals: list) -> bool:
        """
        Verify a Groth16 proof locally.
        Deterministic, <50ms.
        """
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='_proof.json', delete=False
        ) as f:
            json.dump(proof, f)
            proof_path = f.name

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='_public.json', delete=False
        ) as f:
            json.dump(public_signals, f)
            public_path = f.name

        try:
            result = subprocess.run(
                [
                    "npx", "snarkjs", "groth16", "verify",
                    str(self.vk_path),
                    public_path,
                    proof_path,
                ],
                capture_output=True, text=True, timeout=10
            )
            return "OK" in result.stdout

        finally:
            Path(proof_path).unlink(missing_ok=True)
            Path(public_path).unlink(missing_ok=True)


def load_verification_key(vk_path: str = "./artifacts/verification_key.json") -> dict:
    """Load verification key for distribution to counterparty VASPs."""
    with open(vk_path) as f:
        return json.load(f)
```

### 5.2 Circuit Compiler and Trusted Setup

```bash
#!/bin/bash
# scripts/compile_circuits.sh
# Compile all Circom circuits and run Groth16 trusted setup.
#
# Prerequisites:
#   - circom compiler installed (https://docs.circom.io/getting-started/installation/)
#   - npm install snarkjs
#   - npm install circomlib

set -euo pipefail

ARTIFACTS_DIR="./artifacts"
CIRCUITS_DIR="./circuits"
POWERS_OF_TAU="./artifacts/powersOfTau28_hez_final_16.ptau"

mkdir -p "$ARTIFACTS_DIR"

# Download powers of tau (one-time; community ceremony artifact)
if [ ! -f "$POWERS_OF_TAU" ]; then
    echo "Downloading powers of tau..."
    wget -O "$POWERS_OF_TAU" \
        "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_16.ptau"
fi

# Compile main compliance circuit
echo "Compiling compliance circuit..."
circom "$CIRCUITS_DIR/compliance.circom" \
    --r1cs --wasm --sym \
    -o "$ARTIFACTS_DIR" \
    -l node_modules/circomlib/circuits

# Groth16 trusted setup (Phase 2)
echo "Running trusted setup..."
npx snarkjs groth16 setup \
    "$ARTIFACTS_DIR/compliance.r1cs" \
    "$POWERS_OF_TAU" \
    "$ARTIFACTS_DIR/compliance_0000.zkey"

# Contribute to ceremony (single-party for dev; multi-party for production)
npx snarkjs zkey contribute \
    "$ARTIFACTS_DIR/compliance_0000.zkey" \
    "$ARTIFACTS_DIR/compliance_final.zkey" \
    --name="ZK Travel Rule Dev Ceremony" \
    -e="$(head -c 64 /dev/urandom | xxd -p)"

# Export verification key
npx snarkjs zkey export verificationkey \
    "$ARTIFACTS_DIR/compliance_final.zkey" \
    "$ARTIFACTS_DIR/verification_key.json"

echo "Circuit compilation complete."
echo "Artifacts in $ARTIFACTS_DIR:"
ls -la "$ARTIFACTS_DIR"
```

***

## Part VI: SAR Review and Audit Infrastructure

### 6.1 SAR Review Logic

SAR (Suspicious Activity Report) filing is activity-based per FinCEN guidance — not triggered mechanically by amount. The system flags transfers for **human review** based on configurable risk signals; it does not automatically file SARs.[^3][^5]

```python
# sar/sar_review.py
"""
SAR review flag logic.

IMPORTANT: FinCEN SAR filing is activity-based, not amount-based.
This module generates review flags for human compliance officers.
It does NOT automatically file SARs.

Review triggers (configurable per VASP policy):
  - amount_tier >= 3 (large transfer, warrants review)
  - Rapid successive transfers from same wallet
  - Jurisdiction risk scoring
  - Pattern-based anomaly detection (future)

The compliance officer makes the final SAR filing decision.
"""
from typing import Optional
from pydantic import BaseModel

class SARReviewFlag(BaseModel):
    """Flag for human compliance review — NOT an automatic SAR filing."""
    proof_id: str
    transfer_hash: str
    amount_tier: int
    jurisdiction: str
    flag_reasons: list[str]           # Human-readable reasons for review
    requires_review: bool             # True if human review needed
    reviewed: bool = False            # Set by compliance officer
    review_decision: Optional[str] = None  # "file_sar", "dismiss", "escalate"

def evaluate_sar_review(
    proof_id: str,
    transfer_hash: str,
    amount_tier: int,
    jurisdiction: str,
    wallet_history: Optional[dict] = None,
) -> SARReviewFlag:
    """
    Evaluate whether a transfer should be flagged for SAR review.
    Returns a SARReviewFlag — human compliance officer makes final decision.
    """
    reasons = []

    # Tier-based flag (not automatic SAR — just review trigger)
    if amount_tier >= 4:
        reasons.append(f"High-value transfer (tier {amount_tier}): exceeds $10,000 threshold")
    elif amount_tier >= 3:
        reasons.append(f"Large transfer (tier {amount_tier}): exceeds Travel Rule threshold")

    # Jurisdiction risk flag
    HIGH_RISK_JURISDICTIONS = {"IR", "KP", "SY", "CU", "VE"}
    if jurisdiction in HIGH_RISK_JURISDICTIONS:
        reasons.append(f"High-risk jurisdiction: {jurisdiction}")

    # Velocity check (if wallet history available)
    if wallet_history:
        recent_count = wallet_history.get("transfers_last_24h", 0)
        if recent_count > 10:
            reasons.append(f"High velocity: {recent_count} transfers in 24h")

    return SARReviewFlag(
        proof_id=proof_id,
        transfer_hash=transfer_hash,
        amount_tier=amount_tier,
        jurisdiction=jurisdiction,
        flag_reasons=reasons,
        requires_review=len(reasons) > 0,
    )
```

### 6.2 Encryption and HSM Key Management

```python
# sar/encryption.py
"""
AES-256-GCM encryption for audit payloads and PII.
HSM key management for production; software keys for development.

v1: Software-based AES-256-GCM with configurable key storage.
v2: HSM integration (AWS CloudHSM, Azure Dedicated HSM, or on-prem).
"""
import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional

class AuditEncryption:
    """
    Manages encryption of audit payloads and PII bundles.
    Keys are stored in HSM (production) or environment variable (dev).
    """

    def __init__(self, master_key: Optional[bytes] = None):
        if master_key:
            self.master_key = master_key
        else:
            # Dev mode: load from environment
            key_hex = os.environ.get("AUDIT_ENCRYPTION_KEY")
            if key_hex:
                self.master_key = bytes.fromhex(key_hex)
            else:
                # Generate ephemeral key for testing
                self.master_key = AESGCM.generate_key(bit_length=256)

    def encrypt_payload(self, plaintext: dict) -> str:
        """
        Encrypt a JSON payload with AES-256-GCM.
        Returns base64-encoded (nonce || ciphertext || tag).
        """
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)  # 96-bit nonce
        plaintext_bytes = json.dumps(plaintext).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        return base64.b64encode(nonce + ciphertext).decode('ascii')

    def decrypt_payload(self, encrypted: str) -> dict:
        """
        Decrypt an AES-256-GCM encrypted payload.
        Input: base64-encoded (nonce || ciphertext || tag).
        """
        raw = base64.b64decode(encrypted)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(self.master_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))

    def encrypt_pii(self, pii_data: dict) -> str:
        """Encrypt PII bundle for hybrid payload transmission."""
        return self.encrypt_payload(pii_data)


class AuditLog:
    """
    Encrypted audit trail management.
    All compliance proofs and SAR review flags are logged.
    Decryption requires HSM-managed key + legal process authorization.
    """

    def __init__(self, encryption: AuditEncryption, storage_path: str = "./audit_log"):
        self.encryption = encryption
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)

    def store_record(self, proof_id: str, record: dict) -> str:
        """Store encrypted audit record. Returns record_id."""
        encrypted = self.encryption.encrypt_payload(record)
        record_path = os.path.join(self.storage_path, f"{proof_id}.enc")
        with open(record_path, 'w') as f:
            f.write(encrypted)
        return proof_id

    def retrieve_record(self, proof_id: str) -> dict:
        """Retrieve and decrypt audit record (requires appropriate key access)."""
        record_path = os.path.join(self.storage_path, f"{proof_id}.enc")
        with open(record_path) as f:
            encrypted = f.read()
        return self.encryption.decrypt_payload(encrypted)
```

***

## Part VII: External Protocol Bridges

### 7.1 TRP/OpenVASP Bridge

The Travel Rule Protocol (TRP) uses HTTPS POST with JSON payloads. The bridge translates a hybrid payload (ZK proof + encrypted PII) into a TRP-compatible message:[^14][^26]

```python
# protocol/bridges/trp_bridge.py
"""
Translates hybrid payload into TRP v3 wire format.

TRP workflow:
  1. Originator gets beneficiary Travel Address from their VASP
  2. POST to Travel Address endpoint with transfer + identity data
  3. Beneficiary VASP responds with confirmation or rejection

This bridge:
  - Includes ZK proof reference in TRP extensions field
  - Includes encrypted PII in standard IVMS101 fields
  - ZK-capable beneficiaries verify the proof for machine-verifiable compliance
  - All beneficiaries can decrypt PII for regulatory record-keeping
"""

from protocol.compliance_proof import ComplianceProof
from protocol.hybrid_payload import HybridPayload

class TRPBridge:

    def build_trp_request(
        self,
        hybrid_payload: HybridPayload,
        beneficiary_travel_address: str,
        amount: str,
        asset: str
    ) -> dict:
        """
        Build TRP v3 POST body with hybrid payload.
        Standard IVMS101 fields carry encrypted PII.
        Extension field carries ZK proof reference.
        """
        proof = hybrid_payload.compliance_proof
        return {
            "asset": {
                "slip44": self._asset_to_slip44(asset),
            },
            "amount": amount,
            "beneficiary": {
                "beneficiaryPersons": [],  # encrypted PII in extension
                "accountNumber": [proof.transfer_id]
            },
            "originator": {
                "originatorPersons": [],   # encrypted PII in extension
                "accountNumber": [proof.transfer_id]
            },
            # Standard encrypted PII payload
            "ivms101_encrypted": hybrid_payload.encrypted_pii,
            "ivms101_encryption_method": hybrid_payload.pii_encryption_method,
            # Extension field: ZK proof (non-breaking for legacy parsers)
            "extensions": {
                "zk_travel_rule": {
                    "version": "1.0",
                    "proof_id": proof.proof_id,
                    "groth16_proof": proof.groth16_proof,
                    "public_signals": proof.public_signals,
                    "verification_key": proof.verification_key,
                    "originator_vasp_did": proof.originator_vasp_did,
                    "proof_expires_at": proof.proof_expires_at,
                }
            }
        }

    def _asset_to_slip44(self, asset: str) -> int:
        mapping = {"ETH": 60, "BTC": 0, "USDC": 60, "USDT": 195}
        return mapping.get(asset.upper(), 60)
```

### 7.2 TRISA Bridge

TRISA uses mTLS-authenticated gRPC with encrypted IVMS101 payloads. The bridge wraps the hybrid payload in TRISA's envelope format:[^14]

```python
# protocol/bridges/trisa_bridge.py
"""
TRISA gRPC bridge for hybrid Travel Rule messages (ZK proof + encrypted PII).

TRISA requires:
  - mTLS certificates from TRISA GDS (Global Directory Service)
  - Encrypted IVMS101 payload (AES-256-GCM + RSA key wrapping)
  - Non-repudiation via HMAC

This bridge:
  1. Preserves all TRISA security requirements
  2. Embeds ZK proof alongside encrypted PII in TRISA SecureEnvelope
  3. Encrypted PII satisfies TRISA's data transmission requirement
  4. ZK proof provides supplementary machine-verifiable compliance attestation
"""

from protocol.compliance_proof import ComplianceProof
from protocol.hybrid_payload import HybridPayload

class TRISABridge:

    def build_secure_envelope(
        self,
        hybrid_payload: HybridPayload,
        beneficiary_public_key: bytes,
    ) -> dict:
        """
        Build TRISA SecureEnvelope with hybrid payload.

        The encrypted payload contains:
          - ComplianceProof (ZK attestation)
          - Encrypted PII bundle (IVMS101 NaturalPerson data)

        The beneficiary decrypts via mTLS, extracts both components,
        and can independently verify the Groth16 proof.
        """
        import json
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os

        # Serialize hybrid payload
        payload = json.dumps({
            "zk_compliance_proof": hybrid_payload.compliance_proof.model_dump(),
            "encrypted_pii": hybrid_payload.encrypted_pii,
            "pii_encryption_method": hybrid_payload.pii_encryption_method,
            "ivms101_version": "101.2023",
            "payload_version": hybrid_payload.payload_version,
        }).encode()

        # Encrypt payload with ephemeral AES-256-GCM key
        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, payload, None)

        # Wrap AES key with beneficiary RSA public key
        pub_key = serialization.load_der_public_key(beneficiary_public_key)
        wrapped_key = pub_key.encrypt(aes_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        ))

        return {
            "encrypted_payload": (nonce + ciphertext).hex(),
            "encryption_algorithm": "AES256_GCM",
            "wrapped_key": wrapped_key.hex(),
            "hmac_signature": "",  # computed separately via TRISA SDK
            "override_header": {
                "not_after": hybrid_payload.compliance_proof.proof_expires_at,
                "envelope_type": "ZK_TRAVEL_RULE_HYBRID_V1",
            }
        }
```

### 7.3 TAIP-10 Bridge

```python
# protocol/bridges/taip10_bridge.py
"""
TAIP-10 selective disclosure bridge.
Maps hybrid payload to Verifiable Presentation format per TAIP-10 spec.
The VP embeds both the ZK proof and a reference to encrypted PII.[^18]
"""

from protocol.hybrid_payload import HybridPayload

class TAIP10Bridge:

    def build_verifiable_presentation(
        self,
        hybrid_payload: HybridPayload,
    ) -> dict:
        """
        Build TAIP-10 Verifiable Presentation containing:
          - ZK compliance proof as a VerifiableCredential
          - Encrypted PII reference
        """
        proof = hybrid_payload.compliance_proof
        return {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://tap.rsvp/taip-10/v1"
            ],
            "type": ["VerifiablePresentation", "TravelRuleCompliance"],
            "verifiableCredential": [{
                "type": ["VerifiableCredential", "ZKComplianceProof"],
                "issuer": proof.originator_vasp_did,
                "issuanceDate": proof.proof_generated_at,
                "credentialSubject": {
                    "proof_id": proof.proof_id,
                    "groth16_proof": proof.groth16_proof,
                    "public_signals": proof.public_signals,
                    "verification_key": proof.verification_key,
                    "jurisdiction": proof.jurisdiction,
                    "amount_tier": proof.amount_tier,
                },
            }],
            "encryptedPII": {
                "ciphertext": hybrid_payload.encrypted_pii,
                "method": hybrid_payload.pii_encryption_method,
                "key_id": hybrid_payload.pii_key_id,
            },
        }
```

***

## Part VIII: REST API Specification

```python
# api/routes/proof.py
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import time

router = APIRouter(prefix="/proof", tags=["proof"])

class ProofGenerateRequest(BaseModel):
    """POST /proof/generate"""
    credential_id: str              # Credential ID (held by user's wallet)
    wallet_address: str             # Originator wallet address
    amount_usd: float               # Transfer amount in USD
    asset: str                      # e.g., "USDC"
    destination_wallet: str         # Beneficiary wallet address
    destination_vasp_did: Optional[str]
    jurisdiction: str               # ISO 3166-1 of originating jurisdiction
    idempotency_key: str            # For retries without double-charging

    # PII for hybrid payload (encrypted before transmission)
    originator_name: Optional[str] = None
    originator_address: Optional[str] = None
    originator_account: Optional[str] = None

class ProofVerifyRequest(BaseModel):
    """POST /proof/verify"""
    proof_id: str
    groth16_proof: dict             # Groth16 proof object
    public_signals: list[str]
    expected_amount_tier: int       # Tier the verifier expects
    originator_vasp_did: str
    transfer_timestamp: int

@router.post("/generate", response_model=dict)
async def generate_proof(request: ProofGenerateRequest):
    """
    Generate a ZK compliance proof + hybrid payload for a travel rule transfer.

    Proof generation is VASP-local via SnarkJS — no external network required.
    Returns hybrid payload: ComplianceProof + encrypted PII.

    Latency target: <5s for tier 1-2, <10s for tier 3-4
    """
    from prover.tier_mapping import compute_tier
    from prover.snarkjs_prover import SnarkJSProver
    from registry.sanctions_list import SanctionsMerkleTree
    from registry.credential_registry import get_credential
    from registry.issuer_registry import get_issuer_tree_root
    from sar.sar_review import evaluate_sar_review
    from sar.encryption import AuditEncryption, AuditLog
    from protocol.compliance_proof import ComplianceProof
    from protocol.hybrid_payload import HybridPayload
    import uuid

    # Compute tier
    tier = compute_tier(request.amount_usd, request.jurisdiction)

    # Look up credential
    credential = get_credential(request.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    if credential.revoked:
        raise HTTPException(status_code=400, detail="Credential revoked")

    # Build circuit inputs
    sanctions_tree = SanctionsMerkleTree()
    nonmembership_proof = sanctions_tree.generate_nonmembership_proof(
        wallet_address_hash=hash_wallet(request.wallet_address)
    )

    input_signals = {
        "sanctions_tree_root": sanctions_tree.root,
        "issuer_tree_root": get_issuer_tree_root(),
        "amount_tier": tier,
        "transfer_timestamp": int(time.time()),
        "jurisdiction": encode_jurisdiction(request.jurisdiction),
        "credential_commitment": credential.commitment(),
        # Private inputs
        "issuer_did": encode_did(credential.issuer_did),
        "kyc_tier": encode_kyc_tier(credential.kyc_tier),
        "sanctions_clear": 1 if credential.sanctions_clear else 0,
        "issued_at": credential.issued_at,
        "expires_at": credential.expires_at,
        "wallet_address_hash": hash_wallet(request.wallet_address),
        # Merkle proof data
        **nonmembership_proof,
    }

    # Generate proof locally via SnarkJS
    prover = SnarkJSProver()
    try:
        result = await prover.generate_proof(input_signals)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=f"Proof generation failed: {e}")

    proof_id = str(uuid.uuid4())

    # Evaluate SAR review flags (human review, not automatic filing)
    sar_flag = evaluate_sar_review(
        proof_id=proof_id,
        transfer_hash=hash_transfer(request),
        amount_tier=tier,
        jurisdiction=request.jurisdiction,
    )

    # Encrypt PII for hybrid payload
    encryption = AuditEncryption()
    encrypted_pii = encryption.encrypt_pii({
        "originator_name": request.originator_name,
        "originator_address": request.originator_address,
        "originator_account": request.originator_account or request.wallet_address,
        "transfer_amount": str(request.amount_usd),
        "asset": request.asset,
    })

    # Build compliance proof
    proof_obj = ComplianceProof(
        proof_id=proof_id,
        transfer_id=request.idempotency_key,
        groth16_proof=json.dumps(result["proof"]),
        public_signals=result["public_signals"],
        verification_key=json.dumps(load_vk()),
        originator_vasp_did=get_vasp_did(),
        beneficiary_vasp_did=request.destination_vasp_did,
        jurisdiction=request.jurisdiction,
        amount_tier=tier,
        proof_generated_at=int(time.time()),
        proof_expires_at=int(time.time()) + 300,
        sar_review_flag=sar_flag.requires_review,
        encrypted_audit_payload=encryption.encrypt_payload({
            "proof_id": proof_id,
            "sar_flag": sar_flag.model_dump(),
        }),
    )

    # Build hybrid payload
    hybrid = HybridPayload(
        compliance_proof=proof_obj,
        encrypted_pii=encrypted_pii,
        pii_encryption_method="AES-256-GCM",
        created_at=int(time.time()),
    )

    # Store audit record
    audit_log = AuditLog(encryption)
    audit_log.store_record(proof_id, {
        "proof": proof_obj.model_dump(),
        "sar_flag": sar_flag.model_dump(),
        "request_hash": hash_transfer(request),
    })

    return hybrid.model_dump()


@router.post("/verify", response_model=dict)
async def verify_proof(request: ProofVerifyRequest):
    """
    Verify a ZK compliance proof received from counterparty VASP.

    Deterministic verification — no network call required.
    Returns: {valid: bool, compliance_attestations: dict}
    Latency target: <50ms (Groth16 verification is O(1))
    """
    from prover.snarkjs_prover import SnarkJSProver

    prover = SnarkJSProver()
    valid = await prover.verify_proof(request.groth16_proof, request.public_signals)

    # Decode public signals
    signals = request.public_signals
    attestations = {
        "credential_valid": int(signals[0]) == 1,
        "sanctions_clear": int(signals[1]) == 1,
        "amount_tier": int(signals[2]),
        "jurisdiction_match": int(signals[3]) == 1,
    }

    # Check expected tier matches
    if attestations["amount_tier"] != request.expected_amount_tier:
        valid = False

    return {
        "valid": valid,
        "proof_id": request.proof_id,
        "compliance_attestations": attestations,
        "verified_at": int(time.time()),
    }
```

***

## Part IX: Testing Requirements

### 9.1 Compliance Test Suite (Non-Negotiable)

These tests MUST pass for any deployment considered production-ready. All are in `tests/compliance/`:

```python
# tests/compliance/test_sanctions_match.py
"""
CRITICAL: A sanctioned wallet address MUST fail proof generation.
This is the core regulatory requirement. Any bypass = disqualifying bug.
"""
import pytest
from prover.snarkjs_prover import SnarkJSProver

KNOWN_SANCTIONED_ADDRESSES = [
    "0x7F367cC41522cE07553e823bf3be79A889debe1B",  # OFAC SDN list
    "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b",
]

@pytest.mark.asyncio
async def test_sanctioned_address_fails():
    for addr in KNOWN_SANCTIONED_ADDRESSES:
        result = await generate_proof(wallet_address=addr, amount_usd=500, jurisdiction="US")
        assert result is None or result.get("valid") == False, \
            f"CRITICAL: Sanctioned address {addr} passed proof generation"

# tests/compliance/test_threshold_tiers.py
@pytest.mark.asyncio
async def test_tier_encoding_us():
    """Tier MUST reflect correct jurisdiction-specific threshold."""
    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=249, jurisdiction="US")
    assert proof["compliance_proof"]["amount_tier"] == 1  # below $250

    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=2999, jurisdiction="US")
    assert proof["compliance_proof"]["amount_tier"] == 2  # $250-$3000

    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=3001, jurisdiction="US")
    assert proof["compliance_proof"]["amount_tier"] == 3  # $3000-$10000
    # SAR review flag set, but NOT automatic SAR filing
    assert proof["compliance_proof"]["sar_review_flag"] == True

    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=10001, jurisdiction="US")
    assert proof["compliance_proof"]["amount_tier"] == 4
    assert proof["compliance_proof"]["sar_review_flag"] == True

@pytest.mark.asyncio
async def test_tier_encoding_sg():
    """Singapore (MAS) jurisdiction tier test."""
    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=1499, jurisdiction="SG")
    assert proof["compliance_proof"]["amount_tier"] == 2

    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=1501, jurisdiction="SG")
    assert proof["compliance_proof"]["amount_tier"] == 3

@pytest.mark.asyncio
async def test_tier_encoding_ae():
    """UAE (VARA) jurisdiction tier test."""
    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=999, jurisdiction="AE")
    assert proof["compliance_proof"]["amount_tier"] == 2

    proof = await generate_proof(wallet_address=CLEAN_ADDR, amount_usd=1001, jurisdiction="AE")
    assert proof["compliance_proof"]["amount_tier"] == 3

# tests/compliance/test_revocation.py
@pytest.mark.asyncio
async def test_revoked_credential_fails():
    """A revoked credential MUST fail proof generation immediately."""
    credential_id = create_test_credential()
    revoke_credential(credential_id)

    result = await generate_proof(credential_id=credential_id, amount_usd=500, jurisdiction="US")
    assert result is None or not result.get("valid"), \
        "CRITICAL: Revoked credential passed proof generation"
```

### 9.2 Circuit Unit Tests

```python
# tests/unit/test_circuits.py
"""
Unit tests for Circom circuits via SnarkJS.
Each test compiles the circuit, generates a witness, and verifies constraints.
"""
import pytest
import json
from prover.snarkjs_prover import SnarkJSProver

@pytest.mark.asyncio
async def test_valid_compliance_proof():
    """Valid inputs should produce a valid Groth16 proof."""
    prover = SnarkJSProver()
    input_signals = build_valid_test_inputs()
    result = await prover.generate_proof(input_signals)

    assert result["proof"] is not None
    assert len(result["public_signals"]) >= 7
    assert result["proving_time_ms"] < 10000  # <10s

    # Verify proof
    valid = await prover.verify_proof(result["proof"], result["public_signals"])
    assert valid, "Valid proof failed verification"

@pytest.mark.asyncio
async def test_expired_credential_fails():
    """Expired credential should fail witness generation."""
    prover = SnarkJSProver()
    input_signals = build_valid_test_inputs()
    input_signals["expires_at"] = 1000  # expired
    input_signals["transfer_timestamp"] = 2000

    with pytest.raises(RuntimeError):
        await prover.generate_proof(input_signals)

@pytest.mark.asyncio
async def test_sanctions_clear_false_fails():
    """sanctions_clear=0 should fail witness generation."""
    prover = SnarkJSProver()
    input_signals = build_valid_test_inputs()
    input_signals["sanctions_clear"] = 0

    with pytest.raises(RuntimeError):
        await prover.generate_proof(input_signals)

@pytest.mark.asyncio
async def test_invalid_tier_fails():
    """amount_tier outside 1-4 should fail."""
    prover = SnarkJSProver()
    input_signals = build_valid_test_inputs()
    input_signals["amount_tier"] = 5

    with pytest.raises(RuntimeError):
        await prover.generate_proof(input_signals)
```

### 9.3 Protocol Compatibility Tests

```python
# tests/integration/test_trisa_bridge.py
"""
Verify that a hybrid payload can round-trip through TRISA SecureEnvelope.
"""
@pytest.mark.asyncio
async def test_trisa_envelope_roundtrip():
    proof = await generate_test_proof()
    hybrid = build_test_hybrid_payload(proof)
    bridge = TRISABridge()

    envelope = bridge.build_secure_envelope(hybrid, TEST_BENEFICIARY_PUBLIC_KEY)
    assert "encrypted_payload" in envelope
    assert envelope["override_header"]["envelope_type"] == "ZK_TRAVEL_RULE_HYBRID_V1"

    # Beneficiary decrypts and extracts both components
    decrypted = decrypt_envelope(envelope, TEST_BENEFICIARY_PRIVATE_KEY)
    assert decrypted["zk_compliance_proof"]["proof_id"] == proof.proof_id
    assert "encrypted_pii" in decrypted

# tests/integration/test_trp_bridge.py
@pytest.mark.asyncio
async def test_trp_request_structure():
    proof = await generate_test_proof()
    hybrid = build_test_hybrid_payload(proof)
    bridge = TRPBridge()

    trp_body = bridge.build_trp_request(
        hybrid, "lnurl://vasp.example.com/travel", "1000", "USDC"
    )
    # Verify TRP body structure
    assert "originator" in trp_body
    assert "beneficiary" in trp_body
    assert "extensions" in trp_body
    assert "zk_travel_rule" in trp_body["extensions"]
    # Verify encrypted PII is present
    assert "ivms101_encrypted" in trp_body
    assert trp_body["ivms101_encryption_method"] == "AES-256-GCM"

# tests/integration/test_hybrid_payload.py
@pytest.mark.asyncio
async def test_hybrid_payload_roundtrip():
    """Test that hybrid payload encrypts/decrypts PII correctly."""
    from sar.encryption import AuditEncryption

    encryption = AuditEncryption()
    pii = {"name": "Test User", "address": "123 Main St"}
    encrypted = encryption.encrypt_pii(pii)
    decrypted = encryption.decrypt_payload(encrypted)

    assert decrypted == pii
```

### 9.4 Performance Benchmarks

```python
# scripts/benchmark_proof_latency.py
"""
Target latencies (at P95):
  Tier 1-2 (< $3,000): proof generation < 5s
  Tier 3-4 (>= $3,000): proof generation < 10s
  Proof verification: < 50ms (Groth16 is O(1))

Local SnarkJS proving baseline: ~2-5s for compliance circuit
"""
import time
import asyncio

async def benchmark_proof_generation(n_trials: int = 100):
    from prover.snarkjs_prover import SnarkJSProver

    prover = SnarkJSProver()
    times = []
    for _ in range(n_trials):
        input_signals = build_valid_test_inputs()
        start = time.time()
        result = await prover.generate_proof(input_signals)
        elapsed = time.time() - start
        times.append(elapsed)

    p50 = sorted(times)[n_trials // 2]
    p95 = sorted(times)[int(n_trials * 0.95)]
    print(f"Proof generation P50: {p50:.2f}s, P95: {p95:.2f}s")
    assert p95 < 5.0, f"P95 latency {p95:.2f}s exceeds 5s target"

async def benchmark_proof_verification(n_trials: int = 1000):
    from prover.snarkjs_prover import SnarkJSProver

    prover = SnarkJSProver()
    # Generate one proof to verify repeatedly
    input_signals = build_valid_test_inputs()
    result = await prover.generate_proof(input_signals)

    times = []
    for _ in range(n_trials):
        start = time.time()
        valid = await prover.verify_proof(result["proof"], result["public_signals"])
        elapsed = time.time() - start
        times.append(elapsed)
        assert valid

    p50 = sorted(times)[n_trials // 2]
    p95 = sorted(times)[int(n_trials * 0.95)]
    print(f"Proof verification P50: {p50*1000:.1f}ms, P95: {p95*1000:.1f}ms")
    assert p95 < 0.05, f"P95 verification {p95*1000:.1f}ms exceeds 50ms target"
```

***

## Part X: Deployment Configuration

### 10.1 Environment Variables

```bash
# .env.example

# ZK Circuit artifacts
CIRCUIT_ARTIFACTS_DIR=./artifacts
# Created by scripts/compile_circuits.sh:
#   compliance_js/compliance.wasm
#   compliance_final.zkey
#   verification_key.json

# Encryption (v1: software keys; v2: HSM)
AUDIT_ENCRYPTION_KEY=<64-hex-char AES-256 key>

# Sanctions list (rebuild daily)
OFAC_SDN_URL=https://www.treasury.gov/ofac/downloads/sdn.xml
UN_SANCTIONS_URL=https://scsanctions.un.org/resources/xml/en/consolidated.xml
EU_SANCTIONS_URL=https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content

# TRISA (register at https://trisa.io)
TRISA_DIRECTORY_URL=api.vaspdirectory.net:443
TRISA_CERT_PATH=./certs/trisa.pem
TRISA_KEY_PATH=./certs/trisa.key

# API
API_PORT=8000
API_HOST=0.0.0.0
JWT_SECRET=<256-bit random>

# VASP identity
VASP_DID=did:web:vasp.example.com
```

### 10.2 Docker Compose

```yaml
# docker/docker-compose.yml
version: "3.9"
services:
  api:
    build:
      context: ..
      dockerfile: docker/Dockerfile.api
    ports:
      - "8000:8000"
    environment:
      - CIRCUIT_ARTIFACTS_DIR=/app/artifacts
      - AUDIT_ENCRYPTION_KEY=${AUDIT_ENCRYPTION_KEY}
      - JWT_SECRET=${JWT_SECRET}
      - VASP_DID=${VASP_DID}
    volumes:
      - ./artifacts:/app/artifacts:ro
      - ./certs:/app/certs:ro
      - ./audit_log:/app/audit_log
    depends_on:
      - prover
      - sanctions_builder

  prover:
    build:
      context: ..
      dockerfile: docker/Dockerfile.prover
    volumes:
      - ./artifacts:/app/artifacts:ro
    # SnarkJS runs as a sidecar; API calls it via local socket
    # or the API container runs SnarkJS directly (simpler)

  sanctions_builder:
    build:
      context: ..
      dockerfile: docker/Dockerfile.api
    command: python scripts/build_sanctions_tree.py
    environment:
      - OFAC_SDN_URL=${OFAC_SDN_URL}
      - UN_SANCTIONS_URL=${UN_SANCTIONS_URL}
      - EU_SANCTIONS_URL=${EU_SANCTIONS_URL}
    volumes:
      - ./artifacts:/app/artifacts
    # Run daily via cron or restart policy
    restart: "no"
```

### 10.3 Dockerfile.api

```dockerfile
# docker/Dockerfile.api
FROM python:3.12-slim

# Install Node.js for SnarkJS
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY pyproject.toml .
RUN pip install -e .

# Install Node deps (SnarkJS, circomlib)
COPY package.json .
RUN npm install

# Copy application code
COPY . .

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 10.4 Dockerfile.prover

```dockerfile
# docker/Dockerfile.prover
FROM node:20-slim

# Install Circom compiler
RUN apt-get update && apt-get install -y curl build-essential && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . $HOME/.cargo/env && \
    git clone https://github.com/iden3/circom.git && \
    cd circom && cargo build --release && \
    cp target/release/circom /usr/local/bin/ && \
    cd .. && rm -rf circom && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json .
RUN npm install

COPY circuits/ ./circuits/
COPY scripts/compile_circuits.sh .

# Compile circuits at build time
RUN bash compile_circuits.sh
```

***

## Part XI: Implementation Phases and Agent Instructions

A coding agent should execute in the following phases. Each phase is independently testable. **Total timeline: 6 weeks.**

### Phase 1: Circom Circuits (Weeks 1-2)

**Goal**: Compile working Circom circuits and generate Groth16 artifacts.

```
1. Install prerequisites: circom compiler, snarkjs, circomlib
2. Write circuits/lib/merkle_tree.circom (Poseidon-based Merkle proof)
3. Write circuits/sanctions_nonmembership.circom (gap proof)
4. Write circuits/credential_validity.circom (commitment + expiry check)
5. Write circuits/amount_tier.circom (tier validation + SAR review flag)
6. Write circuits/compliance.circom (main composed circuit)
7. Run scripts/compile_circuits.sh → artifacts/ has wasm, zkey, vk
8. Write prover/snarkjs_prover.py (Python wrapper)
9. Write prover/tier_mapping.py (jurisdiction tier logic)
10. Run tests/unit/test_circuits.py → all pass
11. Run build_sanctions_tree.py with test data (10 fake addresses)
12. CHECKPOINT: artifacts/ contains compiled circuit + keys; unit tests pass
```

### Phase 2: FastAPI Gateway + Proving (Weeks 3-4)

**Goal**: Full HTTP API functional with local SnarkJS proving.

```
1. Write protocol/compliance_proof.py (ComplianceProof model)
2. Write protocol/hybrid_payload.py (HybridPayload model)
3. Write protocol/ivms101.py (ZKIvms101Message model)
4. Write sar/encryption.py (AES-256-GCM encryption)
5. Write sar/sar_review.py (SAR review flag logic — activity-based, not automatic)
6. Write sar/audit_log.py (encrypted audit trail)
7. Write api/main.py (FastAPI entrypoint)
8. Write api/routes/proof.py (POST /proof/generate, POST /proof/verify)
9. Write api/routes/credential.py (POST /credential/issue, /revoke)
10. Write api/routes/health.py (GET /health, GET /metrics)
11. Write api/middleware/auth.py (JWT auth)
12. Run tests/integration/test_proof_roundtrip.py → full roundtrip passes
13. Run tests/integration/test_hybrid_payload.py → encrypt/decrypt roundtrip
14. CHECKPOINT: API serves proof generation + verification; hybrid payload works
```

### Phase 3: Protocol Bridges + Compliance Suite (Weeks 5-6)

**Goal**: TRISA/TRP bridges operational; all compliance tests pass.

```
1. Write protocol/bridges/trisa_bridge.py (TRISA SecureEnvelope + hybrid)
2. Write protocol/bridges/trp_bridge.py (TRP + hybrid extensions)
3. Write protocol/bridges/taip10_bridge.py (TAIP-10 VP format)
4. Run tests/integration/test_trisa_bridge.py → envelope roundtrip passes
5. Run tests/integration/test_trp_bridge.py → TRP structure valid
6. Build production sanctions tree from OFAC/UN/EU live feeds
7. Run tests/compliance/test_sanctions_match.py → ALL sanctioned addresses FAIL
8. Run tests/compliance/test_threshold_tiers.py → ALL jurisdiction tiers correct
   (including SG/MAS and AE/VARA jurisdictions)
9. Run tests/compliance/test_revocation.py → revoked credential FAILS immediately
10. Run scripts/benchmark_proof_latency.py → P95 < 5s for proof gen, <50ms verify
11. Write docker/ configs (Dockerfile.api, Dockerfile.prover, docker-compose.yml)
12. CHECKPOINT: All compliance tests pass; protocol bridges work; Docker deploys
```

***

## Part XII: v2 Roadmap

The following capabilities are deferred to v2. They were evaluated during architecture design and determined to be unnecessary for MVP but valuable for scale.

### v2.1: Bittensor Subnet for Distributed Proving

**What**: Deploy ZK proof generation as a Bittensor subnet. Miners compete to generate proofs; validators verify and score them. This distributes proving workload across a decentralized network.[^11][^16][^24]

**Why deferred**: v1 VASP-local proving is simpler, has no network dependency, and meets latency targets. Bittensor integration adds complexity (subnet registration, miner/validator neurons, TAO economics) without clear v1 benefit.

**v2 scope**:
- Custom Synapse for ZKProofRequest/ZKProofResponse
- Miner neuron running SnarkJS proof generation
- Validator neuron for proof verification + scoring
- Subnet registration on testnet/mainnet
- Cross-subnet API via SubnetsAPI[^10][^20]

### v2.2: Targon CVM for Confidential Audit

**What**: Run SAR generation and audit key management inside Targon Confidential Virtual Machines (CVMs), attested via Intel TDX + NVIDIA nvTrust.[^12][^13][^25]

**Why deferred**: v1 uses standard AES-256-GCM encryption with HSM key management, which meets regulatory requirements. CVM adds hardware attestation guarantees but requires enterprise Targon access and Intel TDX infrastructure.[^27]

**v2 scope**:
- Targon CVM provisioning and attestation verification
- Key release gated on remote attestation via Intel Trust Authority
- SAR generation inside attested enclave
- Re-attestation every 72 minutes (one Bittensor block)
- Migration from software HSM to CVM-held keys

### v2.3: Halo2/PLONK Circuit Migration

**What**: Migrate compliance circuits from Groth16 to Halo2 (PLONK-based) to eliminate trusted setup requirement.

**Why deferred**: Groth16 is sufficient for v1 — compliance circuits are stable (trusted setup is one-time), and Groth16 verification is cheaper on-chain. Halo2 becomes valuable when circuits change frequently or when eliminating trusted setup ceremony is a priority.

### v2.4: On-Chain Proof Verification

**What**: Deploy Groth16 verifier smart contract for on-chain proof verification (Ethereum, Solana, or L2).

**Why deferred**: v1 uses off-chain verification via API. On-chain verification enables trustless compliance checking by smart contracts but requires gas optimization and chain-specific deployment.

***

## Part XIII: Debate Record

Key architectural decisions made during specification review, with rationale:

| # | Decision | Original | Revised | Rationale |
|---|---|---|---|---|
| 1 | **Proof system** | EZKL/ONNX neural nets + DSperse | Circom/SnarkJS + Groth16 | Compliance logic is boolean/arithmetic. Neural net wrapping adds training, calibration, and accuracy overhead for logic that maps directly to Circom constraints. |
| 2 | **Proving infrastructure** | Bittensor miner network | VASP-local SnarkJS | No external network dependency for v1. Simpler, faster, no TAO economics. Bittensor deferred to v2. |
| 3 | **SAR/audit encryption** | Targon CVM (Intel TDX) | AES-256-GCM + HSM | Standard encryption meets regulatory requirements for v1. CVM attestation is valuable but requires enterprise hardware. Deferred to v2. |
| 4 | **PII handling** | ZK replaces PII entirely | Hybrid: encrypted PII + ZK attestation | Regulators require PII transmission. ZK proves compliance was done correctly; encrypted PII satisfies the "transmit" requirement. Both travel together. |
| 5 | **Circuit framework** | DSperse slice framework | Direct Circom composition | DSperse adds framework overhead for a circuit that composes naturally in Circom. Direct composition is simpler and more transparent. |
| 6 | **Timeline** | 3 weeks | 6-week MVP (3 phases) | Realistic timeline for circuit development, API integration, and compliance testing. |
| 7 | **Regulatory framing** | Privacy technology | Privacy-preserving compliance infrastructure | Positioning as compliance tooling, not privacy tech, aligns with regulator expectations. Target SG (MAS), UAE (VARA) first; EU (MiCA) after. |
| 8 | **SAR logic** | Automatic SAR filing on tier >= 3 | SAR review flag for human review | FinCEN SAR filing is activity-based, not amount-based. Automatic filing on amount thresholds misrepresents the regulatory requirement. System flags for human compliance officer review. |

***

## Known Gaps and Agent Escalation Points

A coding agent should flag the following items for human review before production deployment:

| Item | Risk | Required Action |
|---|---|---|
| Groth16 trusted setup | Requires multi-party ceremony; single-party setup is insecure for production[^22] | Coordinate multi-party ceremony; use Hermez community powers of tau for development |
| Poseidon hash implementation | Must use circuit-compatible Poseidon (from circomlib), not SHA-256, for all Merkle trees | Use `circomlib/circuits/poseidon.circom`; validate hash outputs match Python reference |
| Credential issuer onboarding | Trusted issuer set must be bootstrapped with real KYC providers | Legal agreements with licensed KYC operators (Sumsub, Jumio, Onfido) |
| HSM key management | v1 uses software keys; production requires HSM (AWS CloudHSM, Azure, or on-prem) | Provision HSM before production launch; rotate keys per policy |
| TRISA certificate registration | TRISA mTLS certs require KYC/KYB through TRISA GDS — 2-4 week process[^14] | Apply at trisa.io before Phase 3 begins |
| GENIUS Act VASP registration | U.S. stablecoin issuers must register with FinCEN under BSA[^3][^5] | Legal entity formation + FinCEN MSB registration before production launch |
| ZK circuit formal verification | Circom circuits should be formally audited before processing real transfers | Engage circuit auditor (e.g., Nethermind[^28], Veridise, or equivalent) |
| MAS/VARA regulatory engagement | Singapore and UAE are initial target jurisdictions | Engage local counsel for MAS PSA and VARA VASP licensing requirements |

---

## References

1. [A Guide to Implementing Travel Rule Compliance in 2025](https://paycompliance.com/2025/06/24/a-guide-to-implementing-travel-rule-compliance-in-2025-updates-on-fatfs-travel-rule-and-how-businesses-can-comply/) - The FATF Travel Rule (Recommendation 16) mandates that financial institutions and VASPs share benefi...

2. [Travel Rule Enforcement in 2025: Implementation Challenges ... - Defy](https://www.getdefy.co/en/resources/blog/travel-rule-enforcement) - Deep dive into global Travel Rule compliance, enforcement realities, and technical solutions for VAS...

3. [The GENIUS Act of 2025 Stablecoin Legislation Adopted in the US](https://www.lw.com/en/insights/the-genius-act-of-2025-stablecoin-legislation-adopted-in-the-us) - <span>The statute's new regulatory framework for payment stablecoins paves the way for increased dig...

4. [GENIUS Act Implementation: OCC Issues Proposed Rules](https://www.sullcrom.com/insights/memo/2026/March/OCC-Proposes-Regulations-Implement-GENIUS-Act) - On February 25, 2026, the Office of the Comptroller of the Currency issued a notice of proposed rule...

5. [GENIUS Act Compliance: Complete Guide for Financial Institutions ...](https://www.dotfile.com/blog-articles/genius-act-compliance-complete-guide-for-2026) - Complete GENIUS Act compliance guide for stablecoin issuers. Learn reserve requirements, AML obligat...

6. [Crypto Travel Rule Guide 2025 - Sumsub](https://sumsub.com/blog/what-is-the-fatf-travel-rule/) - FATF Travel Rule Requirements. The Travel Rule's main requirements are: To conduct due diligence of ...

7. [ZKsync Partners with Five U.S. Regional Banks to Launch Cari ...](https://www.kucoin.com/news/flash/zksync-partners-with-five-u-s-regional-banks-to-launch-cari-network-for-tokenized-deposits) - ZKsync has launched a network upgrade in partnership with five U.S. regional banks to build Cari Net...

8. [U.S. Regional Banking Alliance Taps ZKsync for Tokenized Deposit ...](https://www.bankless.com/read/news/u-s-regional-banking-alliance-taps-zksync-for-tokenized-deposit-network) - ZKsync has announced the launch of Cari Network, a new platform developed alongside five regional ba...

9. [zk-X509: Privacy-Preserving On-Chain Identity from Legacy PKI via ...](https://arxiv.org/html/2603.25190v1) - 2.2 Zero-Knowledge Proofs and zkVMs. A zero-knowledge proof allows a prover to convince a verifier t...

10. [inference-labs-inc/dsperse: Distributed zkML - GitHub](https://github.com/inference-labs-inc/dsperse) - Proof System Agnostic: Pluggable backend architecture supporting Expander and Remainder proof system...

11. [bittensor 5.3.3 - PyPI](https://pypi.org/project/bittensor/5.3.3/) - This repository contains Bittensor's Python API, which can be used for the following purposes: Query...

12. [Targon Virtual Machine (TVM) - Manifold Labs](https://www.manifold.inc/releases/targon-v6) - The CVM GPU Attestation leverages NVIDIA's nvTrust framework through a robust Python wrapper ( attes...

13. [Manifold Labs](https://www.manifold.inc/releases/Targon-v6) - Think Bigger - A Decentralized Frontier AI Lab

14. [OpenVASP/TRP Integration - TRISA Documentation](https://trisa.dev/openvasp/index.html) - The TRP workflow uses HTTPS POST requests with JSON payloads to facilitate information exchange. The...

15. [docs.travel-rule.com - Working with the documentation](https://docs.travel-rule.com/api/vasp)

16. [Py-Ec/bittensor - GitHub](https://github.com/Py-Ec/bittensor) - This guide provides instructions on how to extend the Bittensor Subnets API, a powerful interface fo...

17. [IVMS-101 Format Guidelines | Global Travel Rule Documentation](https://www.globaltravelrule.com/documentation/ivms-101-guidelines) - One validated IVMS structure sent from Originator requires "Originator", "Beneficiary", "Originating...

18. [TAIP-10: IVMS101 for Travel Rule Identity Verification in TAP](https://taips.tap.rsvp/TAIPs/taip-10) - The Verifiable Presentation embeds a Verifiable Credential generated from the IVMS-101 data, mapped ...

19. [[PDF] DSperse: A Framework for Targeted Verification in Zero-Knowledge ...](https://arxiv.org/pdf/2508.06972.pdf) - Our goal is to validate that DSperse's modular architecture functions robustly across qualitatively ...

20. [Inference Labs on X](https://x.com/inference_labs/status/1973059903368708523)

21. [zk-X509: Privacy-Preserving On-Chain Identity from Legacy PKI via ...](https://arxiv.org/abs/2603.25190) - This paper presents zk-X509, a privacy-preserving identity system bridging legacy Public Key Infrast...

22. [r/crypto - Implemented ZK authentication with Halo2 PLONK - Reddit](https://www.reddit.com/r/crypto/comments/1oct2cb/implemented_zk_authentication_with_halo2_plonk/) - A groth16 trusted setup only impacts soundness, not zero-knowledge. The subversion resistance checks...

23. [Introduction Groth16 | zkDatabase Architecture - Orochi Network](https://orochi.network/blog/introduction-groth16-zk-database-architecture) - After evaluating various proof systems including Kimchi (Mina's stack), PLONK, and STARKs, Orochi Ne...

24. [Launching a Bittensor Subnet: The Basics - Sami's Notes](https://samikassab.substack.com/p/launching-a-bittensor-subnet-the) - The Bittensor Core facilitates communication between nodes in the network, providing an abstract fra...

25. [Targon (SN4) and Intel TDX: Confidential Compute on Bittensor](https://simplytao.ai/blog/targon-sn4-and-intel-tdx-confidential-compute-on-bittensor) - Targon (SN4) and Intel released a joint whitepaper on decentralized confidential compute using Intel...

26. [TRISA and TRP achieve interoperability between two open-source ...](https://www.openvasp.org/blog/trisa-and-trp-announce-travel-rule-interoperability) - TRISA and OpenVASP achieve interoperability between two open-source Travel Rule protocols enabling g...

27. [Subnet 4 :: Targon — Trusted Compute & Self-Serve Platform Launch on Bittensor](https://www.youtube.com/watch?v=r8cBpoFFltQ) - Episode Summary:
In this episode, the Targon team unveils the launch of their trusted compute and se...

28. [Formally Verifying Zero-Knowledge Circuits: Introducing CertiPlonk](https://www.nethermind.io/blog/formally-verifying-zero-knowledge-circuits-introducing-certiplonk) - CertiPlonk is a formal verification framework for Plonky3 ZK circuits, proving correctness of ZKVM-s...
