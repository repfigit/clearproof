# Post-Quantum Exposure Assessment

**Status:** Living document — update when cryptographic assumptions change.
**Last reviewed:** 2026-07-27
**Scope:** clearproof's cryptographic dependencies and their exposure under a quantum threat model.

## Executive Summary

clearproof relies on three cryptographic primitives with different post-quantum (PQ) exposure profiles:

1. **Proof system** (Groth16 over BN254/BLS12-381 pairing curves) — forward-looking forgery risk
2. **PII envelope** (X25519 HPKE + AES-256-GCM) — retrospective decryption risk
3. **Trust store** (MPC ceremony artifacts) — forward-looking trust risk

This document classifies each exposure, distinguishes forward-looking from retrospective risk, and records the migration triggers that will drive PQ adoption.

---

## 1. Proof-System Exposure (Groth16 over Pairing Curves)

**Primitive:** Groth16 zk-SNARK proofs over BN254 and BLS12-381 elliptic curves.

**Quantum threat:** Shor's algorithm breaks the discrete logarithm problem underlying pairing-based cryptography. A sufficiently large fault-tolerant quantum computer (FTQC) can compute discrete logs in polynomial time, enabling proof forgery.

**Exposure classification:** **Forward-looking risk**

- **What breaks:** The soundness property of Groth16 proofs. An adversary with an FTQC can forge valid proofs for false statements.
- **What is affected:** All *future* proofs generated after the FTQC becomes operational. Proofs generated today and verified today remain sound (assuming the verifier is honest and the proving key is uncompromised).
- **What is NOT affected:** Proofs already verified and archived. Once a proof is verified on-chain or by a regulator, its validity at the time of verification is historical fact, not a cryptographic claim. The archive does not need to remain sound against future forgery — it needs to remain *authentic* (untampered), which is a hash-based integrity check (SHA-256), not a pairing-based one.

**Assets at risk:**
- `artifacts/*.zkey` (proving keys) — forgery capability if exposed to FTQC
- `artifacts/*.vkey` (verification keys) — same
- `circuits/compliance.circom` — the circuit definition itself is PQ-neutral, but its compiled artifacts are not
- On-chain `Groth16Verifier.sol` — accepts forged proofs if the verifier key is compromised

**Mitigation path:** Migrate to a PQ-safe proof system (e.g., Noir/UltraHonk with universal setup, or lattice-based SNARKs) before FTQC operationalizes. See §4 Migration Triggers.

---

## 2. PII Envelope Exposure (X25519 HPKE + AES-256-GCM)

**Primitive:** Hybrid Public Key Encryption (HPKE) using X25519 for key agreement and AES-256-GCM for symmetric encryption. The envelope format is documented in `src/sar/hpke_envelope.py` (HPKE v2, RFC 9180).

**Quantum threat:**
- **X25519 (key agreement):** Broken by Shor's algorithm. An adversary who captures the encrypted envelope *today* and later obtains an FTQC can recover the shared secret and decrypt the envelope.
- **AES-256-GCM (symmetric encryption):** Resists quantum attack up to Grover's algorithm, which provides a quadratic speedup. AES-256 becomes AES-128-equivalent under Grover — still computationally infeasible for bulk decryption, but the security margin halves.

**Exposure classification:** **Retrospective risk (store-now-decrypt-later)**

- **What breaks:** The confidentiality of PII envelopes captured today. An adversary who exfiltrates encrypted payloads from the API, database, or network traffic can hold them until an FTQC is available, then decrypt them.
- **What is affected:** All `HybridPayload` objects in transit or at rest. This includes:
  - PII encrypted for regulatory transmission (Travel Rule payloads)
  - Credential envelopes (verifiable credentials, DID documents)
  - SAR (Suspicious Activity Report) metadata encrypted for internal review
- **What is NOT affected:** The integrity of the envelope (AES-GCM authentication tag remains valid if the key is uncompromised). The *confidentiality* is the at-risk property.

**Assets at risk:**
- `PII_MASTER_KEY` (environment variable) — if compromised, all envelopes decryptable regardless of PQ
- Per-recipient public keys (X25519) — captured envelopes decryptable with corresponding private key + FTQC
- Encrypted payloads in `storage/` (database) and in transit (API responses, bridge messages)

**Mitigation path:** Migrate to PQ-safe key agreement (e.g., X-Wing, ML-KEM) in HPKE v3. See §4 Migration Triggers.

---

## 3. Symmetric Exposure (AES-256-GCM)

**Primitive:** AES-256 in Galois/Counter Mode (GCM) for authenticated encryption.

**Quantum threat:** Grover's algorithm provides a quadratic speedup for brute-force search. AES-256's 256-bit key space becomes effectively 128-bit under Grover — still computationally infeasible for realistic adversaries, but the security margin is halved.

**Exposure classification:** **Forward-looking risk (reduced margin)**

- **What breaks:** Nothing immediately. AES-256-GCM remains computationally secure under Grover, but the effective security level drops from 256 bits to 128 bits.
- **What is affected:** All symmetric encryption operations. In clearproof, this is the AES-256-GCM layer of the HPKE envelope (see §2).
- **What is NOT affected:** The structural security of GCM (authentication, nonce misuse resistance) — these are information-theoretic or based on the PRF security of AES, not key length.

**Assets at risk:**
- Same as §2: `HybridPayload` envelopes, `PII_MASTER_KEY`-derived keys

**Mitigation path:** No immediate action required. AES-256 remains NIST-approved through 2035+ for TOP SECRET data. If the threat model evolves (e.g., quantum advantage beyond Grover), migrate to AES-512 (not standardized) or a lattice-based symmetric alternative. For now, the X25519 key agreement layer is the binding constraint, not AES.

---

## 4. Trust-Store Exposure (MPC Ceremony Artifacts)

**Primitive:** Multi-party computation (MPC) trusted setup ceremony for Groth16 proving/verification keys. The ceremony is documented in `docs/internal/CEREMONY_RUNBOOK.md` and `docs/internal/CIRCUIT_TRUSTED_SETUP.md`.

**Quantum threat:** The MPC ceremony produces a *toxic waste* file (the Lagrange coefficients and evaluation points). If any participant in the ceremony retains their share of the toxic waste and later obtains an FTQC, they can forge proofs.

**Exposure classification:** **Forward-looking risk (trust erosion)**

- **What breaks:** The soundness guarantee of the trusted setup. If the toxic waste is not destroyed (or if a participant is compromised), an FTQC-holder can forge proofs.
- **What is affected:** The integrity of the entire proving system. All proofs generated with compromised ceremony artifacts are untrustworthy.
- **What is NOT affected:** The ceremony transcript itself (if published and auditable). The transparency of the ceremony allows post-hoc verification that participants followed the protocol, but does not prevent a dishonest participant from retaining toxic waste.

**Assets at risk:**
- `artifacts/*.ptau` (Powers of Tau) — if toxic waste retained
- `artifacts/*.zkey` (proving keys) — derived from compromised ptau
- The reputation of the ceremony participants — if a participant is later found to have retained toxic waste, all proofs generated with those keys are suspect

**Mitigation path:**
1. Ensure the ceremony runbook includes a public, verifiable toxic-waste destruction ceremony (e.g., live-streamed deletion with multi-sig witness).
2. Migrate to a universal-setup proof system (Noir/UltraHonk) that eliminates the need for per-circuit trusted setup. This is the long-term solution.
3. In the interim, document the ceremony participants and their attestation of toxic-waste destruction in `docs/internal/CEREMONY_RUNBOOK.md`.

---

## 5. Forward-Looking vs. Retrospective Risk

| Risk type | Definition | Assets affected | clearproof exposure |
|-----------|------------|-----------------|---------------------|
| **Forward-looking** | A future capability (FTQC) breaks a cryptographic assumption, affecting *future* operations | Proving keys, verification keys, ceremony artifacts | Groth16 forgery (§1), trust-store erosion (§4) |
| **Retrospective** | A future capability (FTQC) breaks a cryptographic assumption, allowing *past* data to be decrypted or forged | Encrypted envelopes, captured network traffic | X25519 HPKE store-now-decrypt-later (§2) |

**Key distinction:**
- **Forward-looking risks** affect the *validity* of future proofs. Once an FTQC is operational, new proofs can be forged, but old proofs (already verified) remain historically valid.
- **Retrospective risks** affect the *confidentiality* of past data. Once an FTQC is operational, captured envelopes can be decrypted, violating the privacy of data encrypted today.

**clearproof's exposure profile:**
- **High retrospective risk:** PII envelopes (Travel Rule payloads, credentials) are long-lived and high-value. An adversary who captures them today can decrypt them in 10-15 years if an FTQC materializes.
- **Moderate forward-looking risk:** Proof forgery affects future compliance checks, but regulators and VASPs can re-verify with a PQ-safe system once the migration is complete.
- **Low symmetric risk:** AES-256-GCM remains secure under Grover; the binding constraint is X25519, not AES.

---

## 6. Migration Triggers

clearproof will migrate to PQ-safe primitives when **any** of the following triggers is reached:

### 6.1 PQ Precompile Availability

- **Trigger:** EVM-compatible chains (Ethereum, Arbitrum, Base) ship a precompile for a PQ-safe proof system (e.g., STARK verification, Nova/IVC, or lattice-based SNARKs).
- **Rationale:** On-chain verification is the hot path. If a PQ-safe proof system is natively supported, the gas cost and latency are acceptable for production.
- **Status (2026-07-27):** No PQ precompiles deployed on mainnet. Starknet uses STARKs (PQ-safe) but is not EVM-compatible. Ethereum's EIP-4844 (proto-danksharding) does not include PQ precompiles.

### 6.2 HPKE-PQ RFC Finalization

- **Trigger:** IETF finalizes `draft-ietf-hpke-pq` (or a successor) specifying PQ-safe key agreement for HPKE. The X-Wing hybrid KEM (ML-KEM + X25519) is the leading candidate.
- **Rationale:** HPKE v2 (RFC 9180) does not include PQ-safe KEMs. HPKE v3 is expected to standardize X-Wing or a similar hybrid KEM.
- **Status (2026-07-27):** `draft-ietf-hpke-pq` is in active development. X-Wing is implemented in BoringSSL, liboqs, and other libraries, but not yet standardized in an RFC.
- **Decision:** clearproof defers X-Wing adoption until HPKE v3 is finalized. Rationale:
  - X-Wing is a *hybrid* KEM (ML-KEM + X25519), providing PQ security *plus* classical security. This is a safe interim step, but not a final migration.
  - HPKE v3 may specify a different KEM (e.g., pure ML-KEM, or a different hybrid). Migrating to X-Wing now and then to HPKE v3 later would require two envelope-format changes.
  - The retrospective risk (§2) is real but not urgent: FTQC timelines are 10-15 years, and clearproof's PII retention horizon is 10 years (regulatory requirement). The window is tight but not closed.

### 6.3 NIST Timeline Milestones

- **Trigger:** NIST publishes a final standard for a PQ-safe signature scheme (FIPS 204/205/206) and a PQ-safe KEM (FIPS 203) with clear guidance on deployment timelines.
- **Rationale:** NIST standards are the de facto requirement for regulated industries (finance, healthcare). Clearproof's customers (VASPs, banks) will demand NIST-compliant cryptography.
- **Status (2026-07-27):** NIST published FIPS 203 (ML-KEM) in August 2024 and FIPS 204 (ML-DSA) in August 2024. FIPS 205 (SLH-DSA) is in final review. Deployment guidance is pending.
- **Action:** Monitor NIST's PQ deployment guidance. When VASP customers begin requiring NIST-compliant envelopes, prioritize HPKE v3 migration.

---

## 7. Summary and Recommendations

| Exposure | Risk type | Urgency | Mitigation | Timeline |
|----------|-----------|---------|------------|----------|
| Groth16 forgery | Forward-looking | Medium | Migrate to Noir/UltraHonk or lattice-based SNARK | 2-3 years (depends on precompile availability) |
| X25519 HPKE | Retrospective | High | Migrate to HPKE v3 with X-Wing or pure ML-KEM | 1-2 years (depends on RFC finalization) |
| AES-256-GCM | Forward-looking (reduced margin) | Low | No action required; monitor Grover advances | N/A (secure through 2035+) |
| MPC ceremony artifacts | Forward-looking (trust erosion) | Medium | Publish toxic-waste destruction transcript; migrate to universal setup | 2-3 years (depends on Noir adoption) |

**Priority order:**
1. **X25519 HPKE migration** — retrospective risk is highest because PII envelopes are long-lived and high-value. Monitor `draft-ietf-hpke-pq` and prepare for HPKE v3 adoption.
2. **Groth16 migration** — forward-looking risk is moderate because proof forgery affects future compliance checks, but old proofs remain historically valid. Monitor EVM PQ precompile development.
3. **Ceremony transparency** — publish the toxic-waste destruction transcript to maintain trust in the current proving system.
4. **AES-256-GCM** — no action required; the security margin is halved under Grover but remains computationally infeasible.

---

## 8. References

- NIST PQC standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- IETF HPKE: RFC 9180 (HPKE v2), `draft-ietf-hpke-pq` (HPKE-PQ)
- X-Wing hybrid KEM: `draft-connolly-cfrg-xwing-kem`
- Groth16 soundness under quantum attack: [Boneh et al., 2020]
- Grover's algorithm and AES: [NIST SP 800-131A Rev. 2]
- clearproof ceremony documentation: `docs/internal/CEREMONY_RUNBOOK.md`, `docs/internal/CIRCUIT_TRUSTED_SETUP.md`
- clearproof envelope format: `src/sar/hpke_envelope.py`

---

## 9. Document Maintenance

This document should be reviewed and updated:
- When NIST publishes new PQ deployment guidance
- When IETF finalizes `draft-ietf-hpke-pq` or HPKE v3
- When an EVM-compatible chain ships a PQ precompile
- When clearproof's cryptographic dependencies change (e.g., new proof system, new envelope format)
- Annually, as part of the security review process

**Owner:** clearproof security team (security@clearproof.dev)
