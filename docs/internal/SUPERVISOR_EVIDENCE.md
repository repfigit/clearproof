# Supervisor Evidence Checklist

**Purpose:** Engineering evidence map mapping FATF Travel Rule Supervision best-practice evidence requests to concrete clearproof artifacts. This is not legal advice; it is an internal engineering reference for examination preparedness.

**Last updated:** 2026-07-27
**References:**
- FATF 7th Targeted Update (2025): 93% of jurisdictions have Travel Rule laws; gap shifted to supervision/enforcement
- FATF Best Practices on Travel Rule Supervision (2025)
- FATF R.16 2025 revisions ("payments or value transfers and related messages")

---

## Checklist: Supervisor Evidence Requests vs. clearproof Artifacts

### 1. Proof of Originator/Beneficiary Information Transmission

| Supervisor Request | clearproof Artifact | Status |
|---|---|---|
| Evidence that originator name, account number, and address were transmitted | `proofs` table: `originator_vasp_did`, `beneficiary_vasp_did`, `transfer_id` columns; `audit_entries` table: `entry_type='transfer_initiated'` records with `transaction_ref` linking to transfer | COVERED |
| Evidence that beneficiary institution was identified | `proofs` table: `beneficiary_vasp_did` column; TRP bridge: `beneficiary.beneficiaryPersons` (empty, PII in encrypted envelope); TRISA bridge: `encrypted_payload.zk_compliance_proof.beneficiary_vasp_did` | COVERED |
| Proof that required identity data accompanied the transfer | `HybridPayload.encrypted_pii` (AES-256-GCM ciphertext of IVMS101 payload); `pii_nonce` and `pii_associated_data` for envelope binding; TRP `ivms101_encrypted` field | COVERED |
| Timestamp of transmission | `proofs.proof_generated_at` (Unix timestamp); `audit_entries.timestamp`; on-chain `ProofRecord.timestamp` (block.timestamp) | COVERED |

### 2. Sanctions Screening Evidence

| Supervisor Request | clearproof Artifact | Status |
|---|---|---|
| Evidence that sanctions screening was performed | `ComplianceRegistry.verifyAndRecord()`: requires `bytes32(_pubSignals[2]) == sanctionsOracle.currentRoot()` (sanctions Merkle root match); `SanctionsOracle.currentRoot()` on-chain state | COVERED |
| Sanctions list version used at time of screening | `SanctionsOracle` contract stores `currentRoot` (Merkle root of sanctions tree); `scripts/build_sanctions_tree.py` produces versioned tree with source manifest and SHA-256 hashes; `audit_entries` with `entry_type='sanctions_root_updated'` | COVERED |
| Freshness of sanctions data | `ComplianceRegistry`: `require(!sanctionsOracle.isStale(), "Sanctions oracle stale")` enforces staleness check; `SanctionsOracle.isStale()` compares last-update timestamp against configurable threshold | COVERED |
| Non-membership proof (originator/beneficiary not on sanctions list) | Groth16 circuit public signal `_pubSignals[2]` = sanctions Merkle root; circuit internally proves non-membership of address in sanctions set; on-chain verification confirms root match | COVERED |

### 3. Record-Retrieval Latency and Availability

| Supervisor Request | clearproof Artifact | Status |
|---|---|---|
| Ability to retrieve transaction records within required timeframe | `audit_entries` table indexed by `sequence_number`, `entry_type`, `transaction_ref`; `ProofStore.get_by_id()` and `get_by_transfer_id()` for proof retrieval; Postgres asyncpg connection pool | COVERED |
| Record retention for required period (typically 5 years) | `proofs.proof_expires_at` field (circuit-enforced); `audit_entries` are append-only with hash chain (no TTL in current schema); `idempotency_keys` have `expires_at` but are separate from audit records | COVERED (audit_entries); PARTIAL (proof expiry is for validity, not retention) |
| Audit trail integrity (tamper evidence) | `PersistentAuditLog.verify_chain()`: validates hash chain from `start_seq`; each `entry_hash = SHA256(data_hash, prev_entry_hash, sequence_number)`; tamper-evident linked list | COVERED |
| Record completeness (no gaps in sequence) | `audit_entries.sequence_number` is monotonically increasing; `_next_sequence()` = `MAX(sequence_number) + 1`; `verify_chain()` detects missing entries via hash chain break | COVERED |

### 4. Revocation Handling

| Supervisor Request | clearproof Artifact | Status |
|---|---|---|
| Evidence that revoked credentials are rejected | `ComplianceRegistry.revokeCredential(commitment)`: sets `revokedCredentials[commitment] = true`; `verifyAndRecord()`: `require(!revokedCredentials[bytes32(_pubSignals[7])], "Credential revoked")`; `CredentialRevoked(commitment, revoker)` event emitted | COVERED |
| Timestamp of revocation | On-chain: `CredentialRevoked` event includes block.timestamp (implicit); off-chain: `audit_entries` with `entry_type='credential_revoked'` | COVERED |
| Authority/actor performing revocation | On-chain: `CredentialRevoked` event includes `revoker` (msg.sender address); `REVOKER_ROLE` (AccessControl) restricts who can revoke; off-chain: `audit_entries.actor` field | COVERED |
| Prevention of post-revocation use | On-chain: `require(!revokedCredentials[...])` in `verifyAndRecord()` reverts if credential revoked; nullifier mechanism (`usedNullifiers`) prevents replay of same proof | COVERED |

### 5. Transaction Monitoring and SAR Evidence

| Supervisor Request | clearproof Artifact | Status |
|---|---|---|
| Evidence of transaction monitoring decisions | `ComplianceProof` includes `sar_review_flag` (public signal `_pubSignals[1]`); on-chain `ProofVerified` event emits `sarFlag` boolean; internal advisory only (not transmitted externally per BSA anti-tipping-off) | COVERED |
| Audit trail of monitoring decisions | `audit_entries` with `entry_type='sar_review'` (if implemented); `proofs` table stores `sar_review_flag` per proof | PARTIAL (flag exists in proof model; dedicated audit entry type not yet in schema) |
| Non-tipping-off compliance | `TAIP10Bridge`: `sar_review_flag` intentionally excluded from external VC credentialSubject; TRP bridge: comment notes "sar_review_flag excluded — internal advisory only (BSA anti-tipping-off)"; SAR flag never appears in transmitted messages | COVERED |

### 6. Cross-Border Message Completeness

| Supervisor Request | clearproof Artifact | Status |
|---|---|---|
| All required fields present in transmitted message | TRP bridge: `asset`, `amount`, `originator`, `beneficiary`, `ivms101_encrypted`, `extensions.zk_travel_rule` (full proof + encrypted PII); TRISA bridge: `encrypted_payload` (zk_compliance_proof + encrypted_pii + metadata), `wrapped_key`, `override_header`; TAIP-10 bridge: VerifiablePresentation with credentialSubject (proof fields) + encryptedPII | COVERED |
| Message format compliance (IVMS101) | `HybridPayload.encrypted_pii` contains IVMS101 JSON; TRISA bridge: `ivms101_version: "101.2023"` in encrypted payload; TRP bridge: `ivms101_encrypted` field | COVERED |
| Cryptographic proof of compliance accompanies message | TRP: `extensions.zk_travel_rule.groth16_proof` + `public_signals` + `verification_key`; TRISA: `encrypted_payload.zk_compliance_proof` (full ComplianceProof model dump); TAIP-10: `verifiableCredential[0].credentialSubject` (proof fields) | COVERED |

### 7. VASP Identity and Registration

| Supervisor Request | clearproof Artifact | Status |
|---|---|---|
| Originating VASP is registered and authorized | `VASPRegistry` contract: `vasps(vaspDidHash)` returns VASP record including wallet address; `verifyAndRecord()`: `require(vaspRegistry.isActive(vaspDidHash), "VASP not active")` and `require(msg.sender == vaspWallet, "Not registered VASP wallet")` | COVERED |
| VASP identity bound to transaction | On-chain: `_pubSignals[11] == block.chainid` (domain binding), `_pubSignals[12]` = contract address hash (state binding), `_pubSignals[13]` = transfer ID hash (transfer binding); `ComplianceProof.originator_vasp_did` and `beneficiary_vasp_did` | COVERED |
| VASP key rotation and lifecycle | `VASPRegistry` manages VASP records; key rotation not yet fully implemented (see ROADMAP Phase 1) | GAP |

---

## Gap List: Supervisor Requests with No Corresponding Artifact

| Gap | Supervisor Request | Current State | Remediation (one line) |
|---|---|---|---|
| G-1 | Evidence of VASP key rotation events and timeline | `VASPRegistry` stores current VASP keys but does not emit rotation events or maintain key history | Add `KeyRotated(vaspDidHash, oldKey, newKey, timestamp)` event to `VASPRegistry` and corresponding `audit_entries` records |
| G-2 | Dedicated audit entry type for SAR review decisions | `sar_review_flag` exists in proof model but no dedicated `entry_type='sar_review'` in audit log schema | Add `sar_review` entry type to `PersistentAuditLog.append()` calls at proof generation time, recording the flag and decision rationale |
| G-3 | Proof of data minimization (what PII was NOT transmitted) | Encrypted PII is transmitted; no explicit record of what fields were excluded or minimized | Add `data_minimization_manifest` to `HybridPayload` listing excluded fields per jurisdiction rule profile |
| G-4 | Counterparty decryption success/failure evidence | Encrypted PII is transmitted but no audit trail of successful decryption by beneficiary | Add `decrypt_audit` table: `transfer_id`, `decrypt_timestamp`, `decrypt_success`, `decrypt_actor` (beneficiary VASP DID) |
| G-5 | Multi-jurisdiction rule version applied to transfer | `ComplianceProof.jurisdiction` is a string but no rule version or effective date | Add `rule_version` and `rule_effective_date` fields to `ComplianceProof` and `proofs` table |
| G-6 | Evidence of sanctions list source and provenance | `SanctionsOracle` stores Merkle root but not source manifest details on-chain | Add `SanctionsRootUpdated(root, sourceManifestHash, timestamp, operator)` event to `SanctionsOracle` |
| G-7 | Record of failed compliance checks (rejected transfers) | `verifyAndRecord()` reverts on failure but does not record failed attempts | Add `ProofRejected(transferId, reason, timestamp)` event and corresponding `audit_entries` for failed verification attempts |

---

## FATF R.16 2025 Revisions: Field-Level Delta Assessment

**Revision scope:** FATF R.16 2025 expanded from "virtual asset transfers" to "payments or value transfers and related messages," broadening the scope to include messaging around transfers, not just the transfers themselves.

### Current Bridge Field Coverage vs. R.16 2025 Requirements

| R.16 2025 Requirement | Current Bridge Fields | Delta |
|---|---|---|
| Originator information (name, account number, address) | TRP: `originator.originatorPersons` (empty, PII in encrypted envelope); TRISA: `encrypted_payload.zk_compliance_proof.originator_vasp_did`; TAIP-10: `credentialSubject` (no PII) | NO DELTA for identity data (encrypted PII contains IVMS101 originator fields) |
| Beneficiary information (name, account number) | TRP: `beneficiary.beneficiaryPersons` (empty); TRISA: `encrypted_payload.zk_compliance_proof.beneficiary_vasp_did`; TAIP-10: `credentialSubject` (no PII) | NO DELTA for identity data (encrypted PII contains IVMS101 beneficiary fields) |
| Transfer amount and asset | TRP: `amount`, `asset.slip44`; TRISA: `encrypted_payload.zk_compliance_proof` (amount in public signals); TAIP-10: `credentialSubject.amount_tier` | MINOR DELTA: TAIP-10 uses `amount_tier` (bucketed) not exact amount; TRP/TRISA have exact amount |
| Timestamp of transfer | TRP: `extensions.zk_travel_rule.proof_generated_at`; TRISA: `encrypted_payload.zk_compliance_proof.proof_generated_at`; TAIP-10: `credentialSubject.issuanceDate` | NO DELTA |
| "Related messages" (new scope) | TRP: single POST request; TRISA: SecureEnvelope (single message); TAIP-10: single VerifiablePresentation | GAP: No explicit support for multi-message workflows (e.g., pre-notification, confirmation, amendment messages) that R.16 2025 may require |
| Message sequencing and correlation | TRP: `transfer_id` in `accountNumber`; TRISA: `encrypted_payload.zk_compliance_proof.transfer_id`; TAIP-10: `credentialSubject.transfer_id` | PARTIAL: `transfer_id` exists but no explicit message sequence number or correlation ID for multi-message flows |
| Purpose of transfer (new emphasis) | Not present in any bridge | GAP: No `transfer_purpose` or `payment_purpose` field in current bridge schemas |
| Counterparty VASP identity | TRP: implicit (Travel Address endpoint); TRISA: `encrypted_payload.zk_compliance_proof.originator_vasp_did` / `beneficiary_vasp_did`; TAIP-10: `credentialSubject.originator_vasp_did` / `beneficiary_vasp_did` | NO DELTA |

### Summary of R.16 2025 Deltas

1. **Multi-message workflows:** R.16 2025's "related messages" scope implies support for message sequences (pre-notification, amendment, confirmation). Current bridges support single-message flows only. Remediation: add `message_sequence_number` and `message_type` fields to bridge schemas.

2. **Transfer purpose:** R.16 2025 emphasizes purpose of payment. Current bridges lack `transfer_purpose` field. Remediation: add optional `transfer_purpose` field to `ComplianceProof` and bridge schemas.

3. **Exact amount in TAIP-10:** TAIP-10 uses `amount_tier` (privacy-preserving bucket) while R.16 may require exact amount disclosure to supervisors. Remediation: add `exact_amount` field to TAIP-10 credentialSubject (supervisor-only disclosure, not public).

4. **Message correlation:** Multi-message flows require explicit correlation. Current `transfer_id` provides transfer-level correlation but not message-level. Remediation: add `message_id` (unique per message) and `thread_id` (groups related messages) to bridge schemas.

---

## Follow-Up Candidate Issues (Not Filed in Linear)

The following gaps should be filed as Linear issues after human triage:

1. **AIF-XX: VASP key rotation audit trail** — Add `KeyRotated` event to `VASPRegistry` and corresponding audit entries (addresses G-1)
2. **AIF-XX: SAR review audit entry type** — Add dedicated `sar_review` entry type to `PersistentAuditLog` (addresses G-2)
3. **AIF-XX: Data minimization manifest** — Add `data_minimization_manifest` to `HybridPayload` (addresses G-3)
4. **AIF-XX: Counterparty decryption audit** — Add `decrypt_audit` table for beneficiary decrypt events (addresses G-4)
5. **AIF-XX: Multi-jurisdiction rule versioning** — Add `rule_version` and `rule_effective_date` to `ComplianceProof` (addresses G-5)
6. **AIF-XX: Sanctions source provenance on-chain** — Add `SanctionsRootUpdated` event with source manifest hash (addresses G-6)
7. **AIF-XX: Failed compliance check recording** — Add `ProofRejected` event and audit entries (addresses G-7)
8. **AIF-XX: R.16 2025 multi-message support** — Add `message_sequence_number` and `message_type` to bridge schemas (addresses R.16 2025 "related messages" scope)
9. **AIF-XX: Transfer purpose field** — Add `transfer_purpose` to `ComplianceProof` and bridge schemas (addresses R.16 2025 purpose emphasis)
10. **AIF-XX: Message correlation identifiers** — Add `message_id` and `thread_id` to bridge schemas (addresses R.16 2025 multi-message correlation)

---

## Verification

To verify this checklist:

1. Open this document — checklist covers: proof of originator/beneficiary info transmission, sanctions screening evidence, record-retrieval latency, revocation handling, transaction monitoring, cross-border message completeness, VASP identity
2. Each checklist item names a concrete artifact path/table/event or appears in the gap list
3. ROADMAP.md cites the 2025 R.16 revisions (see Regulatory And Ecosystem Anchors section)
