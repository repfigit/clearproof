---
title: Architecture
category: concepts
order: 2
cli-topic: architecture
---

# Architecture

## Overview

clearproof is a monorepo spanning four languages:

- **Circom** -- ZK circuit definitions
- **TypeScript** -- Proof SDK, CLI, contract bindings
- **Python** -- FastAPI server, registries, chain interaction
- **Solidity** -- On-chain verifier, registries, compliance recording

## Component map

### VASP server

The API server collects witnesses from the credential, sanctions, and issuer registries, passes all inputs to the Groth16 prover, evaluates SAR flags, encrypts PII, and assembles the hybrid payload. This is a sequential pipeline, not parallel.

### On-chain contracts

ComplianceRegistry is the main entry point. It calls Groth16Verifier for cryptographic verification, checks VASPRegistry for VASP identity and issuer roots, and validates the sanctions root against SanctionsOracle. SanctionsRootRelay receives root updates from a relayer or cross-chain bridge and forwards them to the oracle.

### How they connect

The VASP server generates a hybrid payload and sends it to the counterparty via TRISA / TRP / TAIP-10. Either VASP can optionally record the proof on-chain via ComplianceRegistry.

## Data flow: compliant transfer

1. Look up zkKYC credential
2. Build sanctions + issuer witnesses
3. Generate Groth16 proof
4. Evaluate SAR review flags
5. Encrypt PII (AES-256-GCM)
6. Assemble hybrid payload
7. Send via TRISA / TRP / TAIP-10
8. Beneficiary verifies proof (<1ms)
9. Beneficiary decrypts PII for records
10. (Optional) On-chain recording via verifyAndRecord()

Steps 1-6 happen sequentially inside the originating VASP. The SAR review (step 4) evaluates whether the transfer warrants human compliance review -- this is advisory only, not an automatic SAR filing. On-chain recording (step 10) can be submitted by either the originating or beneficiary VASP.

## Hybrid payload

The proof is publicly verifiable. The PII is only readable by the intended counterparty. The envelope binding uses the transfer_id as AES-256-GCM associated data, preventing the encrypted PII from being replayed in a different transfer context.

Components:
- **ZK Proof** (192 bytes) -- Groth16 proof with 16 public signals
- **Encrypted PII** -- AES-256-GCM ciphertext with IVMS101 originator data
- **Envelope binding** -- transfer_id as AAD

## Security properties

The circuit proves all six properties simultaneously in a single Groth16 proof. They are independent -- not sequential.

1. **Valid credential from trusted issuer** -- credential commitment + issuer Merkle membership
2. **Wallet NOT on sanctions list** -- sorted-tree gap proof
3. **Amount in claimed tier** -- range check without revealing exact amount
4. **Bound to specific chain + contract** -- domain_chain_id + domain_contract_hash
5. **Credential not reused** -- credential nullifier (one-time use)
6. **Proof expires in 5 minutes** -- proof_expires_at timestamp
