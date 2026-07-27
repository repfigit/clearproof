---
title: GDPR Data-Minimization
category: concepts
order: 8
cli-topic: gdpr
---

# GDPR Data-Minimization by Design

## The tension

The EU Transfer of Funds Regulation (TFR) requires VASPs to transmit originator and beneficiary information with every transfer. GDPR simultaneously requires data minimization: personal data must be limited to what is necessary.

These obligations pull in opposite directions. Transmit everything and you violate minimization. Transmit nothing and you violate the TFR.

## The resolution

clearproof splits "prove compliance" from "transmit raw data" into separate operations, as recommended by [INATBA's 2025 ZKP-for-GDPR working paper](https://inatba.org/workstreams/data-protection/) and [a16z's privacy-preserving regulatory frameworks analysis](https://a16zcrypto.com/posts/article/privacy-preserving-regulatory-frameworks/).

**The ZK proof attests.** A Groth16 proof (192 bytes) provides machine-verifiable evidence that sanctions screening, credential validation, and amount checks all passed. The proof exposes 16 public signals: compliance status, amount tier (not the exact amount), jurisdiction code, credential commitment, sanctions tree root, and domain binding parameters. No personal data appears in any public signal.

**Minimal encrypted data travels.** PII is encrypted with AES-256-GCM using HKDF-derived keys and envelope-bound associated data. The ciphertext cannot be replayed across transfers. The counterparty decrypts only when legally required for record-keeping or suspicious activity reporting.

**The counterparty verifies first, decrypts only if needed.** The proof is publicly verifiable (under 1ms) without any key material. Decryption of PII is a separate step triggered by legal obligation, not automatic processing.

## What the proof reveals (and what it doesn't)

The 16 public signals contain: compliance status, amount tier (1-4), jurisdiction (ISO country code), credential commitment (Poseidon hash), credential nullifier (one-time use), sanctions/issuer tree roots, domain binding (chain ID + contract hash), transfer binding (transfer ID hash), timestamp, and expiration. No field contains name, address, account number, or any personal identifier.

## What the counterparty receives

The hybrid payload: ZK proof (192 bytes, publicly verifiable) + AES-256-GCM encrypted PII (IVMS101 originator data). The counterparty can verify the proof independently, then decrypt PII only when legally required. Envelope binding prevents cross-transfer replay. Domain binding prevents cross-chain replay.

## Data-flow accuracy

Every claim traces to code:
- Encryption: `src/sar/encryption.py` (AES-256-GCM, 12-byte nonce, HKDF-SHA256, envelope_id as AAD)
- Hybrid payload: `src/protocol/hybrid_payload.py` (encrypted_pii, pii_nonce, pii_associated_data)
- Public signals: `circuits/compliance.circom` (16 signals, no PII)
- SAR flag exclusion: `src/protocol/hybrid_payload.py` (excluded from bridge payloads per BSA anti-tipping-off)

## Positioning, not certification

This describes how the architecture aligns with GDPR data-minimization principles. It does not constitute legal advice or compliance certification. VASPs should consult their own data protection counsel regarding specific obligations.
